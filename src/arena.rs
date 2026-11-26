//! General-Purpose Shared Memory Arena (`NexusSharedArena`) & Lock-Free SPSC Ring Buffers
//!
//! Serves the entire Nexus-IO universal host runtime:
//! - Native hardware streams (camera, audio, sensors, GPU/NPU)
//! - Wasm application cells (currently `PortableCopy` direct linear-memory transfer;
//!   `SharedMemory` is explicitly gated as `UnsupportedTransport` until real imported
//!   Wasm shared-memory mapping is implemented)
//! - Native UI binary operation batches (`UiOp` stream)
//! - Database / `BlobBridge` payloads and inter-node transfer staging
//!
//! Concurrency, Ownership & Safety Invariants:
//! 1. **Globally Unique Execution Owner Identity (`ArenaOwnerId`):** Every cell execution mints a
//!    unique `(app, cell_id, monotonic_exec_seq)` identity via `mint_owner_id()`, so two concurrent
//!    invocations of the same cell can NEVER collide or revoke each other's handles.
//! 2. **Explicitly Bounded Generation-Validated Handles:** Slot IDs are bounded `u32` (never
//!    silently truncating a `u64` in the compact `(generation << 32) | id` C-ABI) paired with a
//!    monotonic `u32` generation incremented on revocation.
//! 3. **Enforced SPSC Exclusivity:** `SpscRingBuffer` enforces single-producer and single-consumer
//!    exclusivity at runtime via atomic `producer_active` / `consumer_active` RAII guards
//!    (`Err(ArenaError::Busy)` on concurrent same-side access), making `Sync` sound without
//!    relying on caller discipline. Typed `RingProducer` / `RingConsumer` endpoints are also
//!    available via `split_ring()`.
//! 4. **Linearized Race-Free Revocation (`LifecycleGate`):** Both `ArenaRegion` and `SpscRingBuffer`
//!    embed a 64-bit atomic lifecycle state (`bit 63 = REVOKED_BIT`, `bits 0..63 = active_ops`).
//!    Every read/write atomically enters the gate before touching memory and exits afterward.
//!    `revoke_and_drain()` sets `REVOKED_BIT` (`AcqRel`) and waits until `active_ops == 0`,
//!    guaranteeing zero in-flight operations remain and zero post-revocation cursor publications
//!    can ever occur.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

const REVOKED_BIT: u64 = 1u64 << 63;
const ACTIVE_MASK: u64 = !REVOKED_BIT;

/// Linearized lock-free lifecycle gate (`bit 63 = revoked`, `bits 0..63 = active_ops`).
struct LifecycleGate {
    state: AtomicU64,
}

struct OpGuard<'a> {
    gate: &'a LifecycleGate,
}

impl Drop for OpGuard<'_> {
    fn drop(&mut self) {
        self.gate.state.fetch_sub(1, Ordering::Release);
    }
}

impl LifecycleGate {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    #[inline]
    fn is_revoked(&self) -> bool {
        (self.state.load(Ordering::Acquire) & REVOKED_BIT) != 0
    }

    /// Atomically acquire an active-operation permit, failing immediately if `REVOKED_BIT` is set.
    #[inline]
    fn try_enter(&self) -> Result<OpGuard<'_>, ArenaError> {
        let mut cur = self.state.load(Ordering::Relaxed);
        loop {
            if (cur & REVOKED_BIT) != 0 {
                return Err(ArenaError::Revoked);
            }
            if (cur & ACTIVE_MASK) == ACTIVE_MASK {
                return Err(ArenaError::Busy);
            }
            match self.state.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(OpGuard { gate: self }),
                Err(next) => cur = next,
            }
        }
    }

    /// Linearization point for revocation: sets `REVOKED_BIT` atomically and drains all in-flight
    /// operations (`active_ops == 0`) before returning.
    fn revoke_and_drain(&self) {
        self.state.fetch_or(REVOKED_BIT, Ordering::AcqRel);
        while (self.state.load(Ordering::Acquire) & ACTIVE_MASK) != 0 {
            std::thread::yield_now();
        }
    }
}

/// Lock-free RAII guard enforcing single-producer or single-consumer exclusivity on `SpscRingBuffer`.
struct SideGuard<'a> {
    flag: &'a AtomicBool,
}

impl<'a> SideGuard<'a> {
    #[inline]
    fn try_acquire(flag: &'a AtomicBool) -> Result<Self, ArenaError> {
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self { flag })
            .map_err(|_| ArenaError::Busy)
    }
}

impl Drop for SideGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

/// Explicit data-plane transport mode behind the same logical arena interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Reserved for genuine imported shared linear memory / OS mmap across host & guest.
    /// Currently returns `ArenaError::UnsupportedTransport` until real shared-memory mapping is wired.
    SharedMemory,
    /// Portable direct-copy baseline (direct host <-> guest linear memory transfer, zero serialization).
    PortableCopy,
}

/// Globally unique owner identity incorporating `(app, cell_id, monotonic_exec_seq)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArenaOwnerId {
    pub app: String,
    pub cell_id: String,
    pub exec_seq: u64,
}

impl ArenaOwnerId {
    pub fn as_canonical(&self) -> String {
        format!("cell:{}/{}#{}", self.app, self.cell_id, self.exec_seq)
    }
}

/// Generation-validated handle to a flat `ArenaRegion` (explicitly bounded `u32` ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SharedBufferHandle {
    pub id: u32,
    pub generation: u32,
}

/// Generation-validated handle to a lock-free `SpscRingBuffer` (explicitly bounded `u32` ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RingBufferHandle {
    pub id: u32,
    pub generation: u32,
}

impl RingBufferHandle {
    /// Lossless pack into 64-bit C-ABI handle: `(generation: u32 << 32) | (id: u32)`.
    #[inline]
    pub fn pack_i64(self) -> i64 {
        (((self.generation as u64) << 32) | (self.id as u64)) as i64
    }

    /// Lossless unpack from 64-bit C-ABI handle.
    #[inline]
    pub fn unpack_i64(raw: i64) -> Self {
        let u = raw as u64;
        Self {
            id: (u & 0xFFFF_FFFF) as u32,
            generation: ((u >> 32) & 0xFFFF_FFFF) as u32,
        }
    }
}

/// Metadata describing an allocated buffer region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferDescriptor {
    pub handle: SharedBufferHandle,
    pub owner_id: String,
    pub label: String,
    pub capacity: usize,
    pub transport: TransportMode,
}

/// Metadata describing a streaming SPSC ring buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDescriptor {
    pub handle: RingBufferHandle,
    pub owner_id: String,
    pub label: String,
    pub capacity: usize,
    pub transport: TransportMode,
}

/// RAII-style lease referencing an active buffer region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferLease {
    pub handle: SharedBufferHandle,
    pub owner_id: String,
    pub capacity: usize,
}

/// Typed arena errors (never panics on guest bounds, concurrency conflicts, or stale handles).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArenaError {
    NotFound,
    Revoked,
    PermissionDenied,
    OutOfBounds,
    InvalidCapacity,
    BufferFull,
    Busy,
    UnsupportedTransport,
    HandleExhausted,
}

impl std::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Arena handle not found"),
            Self::Revoked => write!(f, "Arena handle revoked or generation mismatch"),
            Self::PermissionDenied => write!(f, "Caller does not own this arena handle"),
            Self::OutOfBounds => write!(f, "Offset/length out of arena region bounds"),
            Self::InvalidCapacity => write!(f, "Invalid arena capacity"),
            Self::BufferFull => write!(f, "Ring buffer full"),
            Self::Busy => write!(f, "Concurrent same-side SPSC access rejected"),
            Self::UnsupportedTransport => {
                write!(f, "TransportMode::SharedMemory is not yet implemented; use PortableCopy")
            }
            Self::HandleExhausted => write!(f, "Arena u32 handle space exhausted"),
        }
    }
}

impl std::error::Error for ArenaError {}

/// Backing storage for a flat buffer region with linearized revocation gate.
pub struct ArenaRegion {
    pub descriptor: BufferDescriptor,
    gate: LifecycleGate,
    data: RwLock<Vec<u8>>,
}

impl ArenaRegion {
    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.gate.is_revoked()
    }

    pub(crate) fn revoke_and_drain(&self) {
        self.gate.revoke_and_drain();
    }

    pub fn write_at(&self, offset: usize, src: &[u8]) -> Result<usize, ArenaError> {
        let _guard = self.gate.try_enter()?;
        let mut buf = self.data.write().map_err(|_| ArenaError::Revoked)?;
        let end = offset.checked_add(src.len()).ok_or(ArenaError::OutOfBounds)?;
        if end > buf.len() {
            return Err(ArenaError::OutOfBounds);
        }
        buf[offset..end].copy_from_slice(src);
        Ok(src.len())
    }

    pub fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<usize, ArenaError> {
        let _guard = self.gate.try_enter()?;
        let buf = self.data.read().map_err(|_| ArenaError::Revoked)?;
        let end = offset.checked_add(dst.len()).ok_or(ArenaError::OutOfBounds)?;
        if end > buf.len() {
            return Err(ArenaError::OutOfBounds);
        }
        dst.copy_from_slice(&buf[offset..end]);
        Ok(dst.len())
    }
}

/// Lock-free Single-Producer Single-Consumer (SPSC) byte ring buffer with:
/// - Runtime-enforced single-producer / single-consumer exclusivity (`producer_active`, `consumer_active`)
/// - Linearized revocation gate (`LifecycleGate`) preventing post-revocation cursor publication
/// - Explicit `Ordering::Acquire` / `Ordering::Release` cursor synchronization
/// - Power-of-two capacity for fast bitmask indexing (`cursor & mask`).
pub struct SpscRingBuffer {
    pub descriptor: StreamDescriptor,
    mask: usize,
    gate: LifecycleGate,
    producer_active: AtomicBool,
    consumer_active: AtomicBool,
    storage: Box<[std::cell::UnsafeCell<u8>]>,
    write_pos: AtomicU64,
    read_pos: AtomicU64,
}

// SAFETY:
// 1. `producer_active` (Acquire/Release CAS) guarantees at most ONE thread executes `write()` at any time.
// 2. `consumer_active` (Acquire/Release CAS) guarantees at most ONE thread executes `read()` at any time.
// 3. The sole active producer only writes indices in `[write_pos, read_pos + cap)` before releasing `write_pos`.
// 4. The sole active consumer only reads indices in `[read_pos, write_pos)` after acquiring `write_pos`
//    and before releasing `read_pos`.
// Therefore, no two threads can ever access the same `UnsafeCell<u8>` slot concurrently.
unsafe impl Send for SpscRingBuffer {}
unsafe impl Sync for SpscRingBuffer {}

/// Exclusive typed producer endpoint for compile-time SPSC ownership.
pub struct RingProducer {
    ring: Arc<SpscRingBuffer>,
}

/// Exclusive typed consumer endpoint for compile-time SPSC ownership.
pub struct RingConsumer {
    ring: Arc<SpscRingBuffer>,
}

impl RingProducer {
    #[inline]
    pub fn write(&mut self, src: &[u8]) -> Result<usize, ArenaError> {
        self.ring.write(src)
    }

    #[inline]
    pub fn handle(&self) -> RingBufferHandle {
        self.ring.descriptor.handle
    }
}

impl RingConsumer {
    #[inline]
    pub fn read(&mut self, dst: &mut [u8]) -> Result<usize, ArenaError> {
        self.ring.read(dst)
    }

    #[inline]
    pub fn handle(&self) -> RingBufferHandle {
        self.ring.descriptor.handle
    }
}

impl SpscRingBuffer {
    pub fn new(descriptor: StreamDescriptor) -> Result<Self, ArenaError> {
        if descriptor.capacity == 0 || descriptor.capacity > (64 * 1024 * 1024) {
            return Err(ArenaError::InvalidCapacity);
        }
        let cap = descriptor.capacity.next_power_of_two();
        let mut storage = Vec::with_capacity(cap);
        for _ in 0..cap {
            storage.push(std::cell::UnsafeCell::new(0u8));
        }
        let mut desc = descriptor;
        desc.capacity = cap;
        Ok(Self {
            descriptor: desc,
            mask: cap - 1,
            gate: LifecycleGate::new(),
            producer_active: AtomicBool::new(false),
            consumer_active: AtomicBool::new(false),
            storage: storage.into_boxed_slice(),
            write_pos: AtomicU64::new(0),
            read_pos: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.gate.is_revoked()
    }

    pub(crate) fn revoke_and_drain(&self) {
        self.gate.revoke_and_drain();
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.mask + 1
    }

    #[inline]
    pub fn available_read(&self) -> usize {
        if self.is_revoked() {
            return 0;
        }
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Relaxed);
        w.saturating_sub(r) as usize
    }

    #[inline]
    pub fn available_write(&self) -> usize {
        if self.is_revoked() {
            return 0;
        }
        let w = self.write_pos.load(Ordering::Relaxed);
        let r = self.read_pos.load(Ordering::Acquire);
        self.capacity().saturating_sub(w.saturating_sub(r) as usize)
    }

    /// Producer write: acquires both the linearized `LifecycleGate` and the exclusive `producer_active`
    /// guard, writes up to `src.len()` bytes, and publishes `write_pos` (`Release`) before releasing the gate.
    pub fn write(&self, src: &[u8]) -> Result<usize, ArenaError> {
        let _op_guard = self.gate.try_enter()?;
        let _side_guard = SideGuard::try_acquire(&self.producer_active)?;

        let w = self.write_pos.load(Ordering::Relaxed);
        let r = self.read_pos.load(Ordering::Acquire);
        let cap = self.capacity() as u64;
        let free = cap.saturating_sub(w.saturating_sub(r)) as usize;
        let n = src.len().min(free);
        if n == 0 {
            return Ok(0);
        }
        for (i, &byte) in src[..n].iter().enumerate() {
            let idx = ((w as usize).wrapping_add(i)) & self.mask;
            // SAFETY: Enforced by `SideGuard` (sole producer) and `[w, r + cap)` bounds.
            unsafe {
                *self.storage[idx].get() = byte;
            }
        }
        self.write_pos.store(w.wrapping_add(n as u64), Ordering::Release);
        Ok(n)
    }

    /// Consumer read: acquires both the linearized `LifecycleGate` and the exclusive `consumer_active`
    /// guard, reads up to `dst.len()` bytes after `Acquire` on `write_pos`, and publishes `read_pos` (`Release`).
    pub fn read(&self, dst: &mut [u8]) -> Result<usize, ArenaError> {
        let _op_guard = self.gate.try_enter()?;
        let _side_guard = SideGuard::try_acquire(&self.consumer_active)?;

        let r = self.read_pos.load(Ordering::Relaxed);
        let w = self.write_pos.load(Ordering::Acquire);
        let avail = w.saturating_sub(r) as usize;
        let n = dst.len().min(avail);
        if n == 0 {
            return Ok(0);
        }
        for (i, out) in dst[..n].iter_mut().enumerate() {
            let idx = ((r as usize).wrapping_add(i)) & self.mask;
            // SAFETY: Enforced by `SideGuard` (sole consumer) and `[r, w)` bounds.
            unsafe {
                *out = *self.storage[idx].get();
            }
        }
        self.read_pos.store(r.wrapping_add(n as u64), Ordering::Release);
        Ok(n)
    }
}

struct BufferSlot {
    generation: u32,
    region: Option<Arc<ArenaRegion>>,
}

struct RingSlot {
    generation: u32,
    ring: Option<Arc<SpscRingBuffer>>,
    endpoints_split: bool,
}

/// Process-wide general-purpose arena & SPSC ring buffer registry.
pub struct NexusSharedArena {
    next_id: AtomicU32,
    next_exec_seq: AtomicU64,
    buffers: RwLock<HashMap<u32, BufferSlot>>,
    rings: RwLock<HashMap<u32, RingSlot>>,
}

static GLOBAL_ARENA: OnceLock<Arc<NexusSharedArena>> = OnceLock::new();

impl Default for NexusSharedArena {
    fn default() -> Self {
        Self::new()
    }
}

impl NexusSharedArena {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU32::new(1),
            next_exec_seq: AtomicU64::new(1),
            buffers: RwLock::new(HashMap::new()),
            rings: RwLock::new(HashMap::new()),
        }
    }

    pub fn global() -> Arc<Self> {
        GLOBAL_ARENA
            .get_or_init(|| Arc::new(Self::new()))
            .clone()
    }

    fn alloc_slot_id(&self) -> Result<u32, ArenaError> {
        let mut cur = self.next_id.load(Ordering::Relaxed);
        loop {
            if cur == 0 || cur == u32::MAX {
                return Err(ArenaError::HandleExhausted);
            }
            match self.next_id.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(cur),
                Err(next) => cur = next,
            }
        }
    }

    /// Mint a globally unique execution owner identity (`app`, `cell_id`, monotonic `exec_seq`).
    pub fn mint_owner_id(&self, app: impl Into<String>, cell_id: impl Into<String>) -> ArenaOwnerId {
        ArenaOwnerId {
            app: app.into(),
            cell_id: cell_id.into(),
            exec_seq: self.next_exec_seq.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Allocate a flat `ArenaRegion` owned by `owner_id`.
    /// Rejects `TransportMode::SharedMemory` explicitly until genuine imported shared-memory mapping is implemented.
    pub fn alloc_buffer(
        &self,
        owner_id: impl Into<String>,
        label: impl Into<String>,
        capacity: usize,
        transport: TransportMode,
    ) -> Result<BufferLease, ArenaError> {
        if transport == TransportMode::SharedMemory {
            return Err(ArenaError::UnsupportedTransport);
        }
        if capacity == 0 || capacity > (64 * 1024 * 1024) {
            return Err(ArenaError::InvalidCapacity);
        }
        let id = self.alloc_slot_id()?;
        let generation = 1u32;
        let handle = SharedBufferHandle { id, generation };
        let owner = owner_id.into();
        let region = Arc::new(ArenaRegion {
            descriptor: BufferDescriptor {
                handle,
                owner_id: owner.clone(),
                label: label.into(),
                capacity,
                transport,
            },
            gate: LifecycleGate::new(),
            data: RwLock::new(vec![0u8; capacity]),
        });
        let mut map = self.buffers.write().map_err(|_| ArenaError::Revoked)?;
        map.insert(
            id,
            BufferSlot {
                generation,
                region: Some(region),
            },
        );
        Ok(BufferLease {
            handle,
            owner_id: owner,
            capacity,
        })
    }

    /// Allocate a lock-free `SpscRingBuffer` owned by `owner_id`.
    /// Rejects `TransportMode::SharedMemory` explicitly until genuine imported shared-memory mapping is implemented.
    pub fn alloc_ring(
        &self,
        owner_id: impl Into<String>,
        label: impl Into<String>,
        capacity: usize,
        transport: TransportMode,
    ) -> Result<StreamDescriptor, ArenaError> {
        if transport == TransportMode::SharedMemory {
            return Err(ArenaError::UnsupportedTransport);
        }
        let id = self.alloc_slot_id()?;
        let generation = 1u32;
        let handle = RingBufferHandle { id, generation };
        let desc = StreamDescriptor {
            handle,
            owner_id: owner_id.into(),
            label: label.into(),
            capacity,
            transport,
        };
        let ring = Arc::new(SpscRingBuffer::new(desc)?);
        let actual_desc = ring.descriptor.clone();
        let mut map = self.rings.write().map_err(|_| ArenaError::Revoked)?;
        map.insert(
            id,
            RingSlot {
                generation,
                ring: Some(ring),
                endpoints_split: false,
            },
        );
        Ok(actual_desc)
    }

    /// Split a ring handle into one exclusive `(RingProducer, RingConsumer)` pair (can only be called once).
    pub fn split_ring(
        &self,
        handle: RingBufferHandle,
        caller_owner: Option<&str>,
    ) -> Result<(RingProducer, RingConsumer), ArenaError> {
        let mut map = self.rings.write().map_err(|_| ArenaError::Revoked)?;
        let slot = map.get_mut(&handle.id).ok_or(ArenaError::NotFound)?;
        if slot.generation != handle.generation {
            return Err(ArenaError::Revoked);
        }
        if slot.endpoints_split {
            return Err(ArenaError::Busy);
        }
        let ring = slot.ring.as_ref().ok_or(ArenaError::Revoked)?;
        if ring.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        if let Some(caller) = caller_owner {
            if ring.descriptor.owner_id != caller {
                return Err(ArenaError::PermissionDenied);
            }
        }
        slot.endpoints_split = true;
        Ok((
            RingProducer { ring: ring.clone() },
            RingConsumer { ring: ring.clone() },
        ))
    }

    /// Resolve a generation-validated flat buffer region.
    pub fn get_buffer(
        &self,
        handle: SharedBufferHandle,
        caller_owner: Option<&str>,
    ) -> Result<Arc<ArenaRegion>, ArenaError> {
        let map = self.buffers.read().map_err(|_| ArenaError::Revoked)?;
        let slot = map.get(&handle.id).ok_or(ArenaError::NotFound)?;
        if slot.generation != handle.generation {
            return Err(ArenaError::Revoked);
        }
        let region = slot.region.as_ref().ok_or(ArenaError::Revoked)?;
        if region.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        if let Some(caller) = caller_owner {
            if region.descriptor.owner_id != caller {
                return Err(ArenaError::PermissionDenied);
            }
        }
        Ok(region.clone())
    }

    /// Resolve a generation-validated SPSC ring buffer.
    pub fn get_ring(
        &self,
        handle: RingBufferHandle,
        caller_owner: Option<&str>,
    ) -> Result<Arc<SpscRingBuffer>, ArenaError> {
        let map = self.rings.read().map_err(|_| ArenaError::Revoked)?;
        let slot = map.get(&handle.id).ok_or(ArenaError::NotFound)?;
        if slot.generation != handle.generation {
            return Err(ArenaError::Revoked);
        }
        let ring = slot.ring.as_ref().ok_or(ArenaError::Revoked)?;
        if ring.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        if let Some(caller) = caller_owner {
            if ring.descriptor.owner_id != caller {
                return Err(ArenaError::PermissionDenied);
            }
        }
        Ok(ring.clone())
    }

    /// Revoke a single ring buffer handle, draining all in-flight ops before returning.
    pub fn revoke_ring(&self, handle: RingBufferHandle) -> bool {
        let taken = if let Ok(mut map) = self.rings.write() {
            if let Some(slot) = map.get_mut(&handle.id) {
                if slot.generation == handle.generation {
                    if let Some(ring) = slot.ring.take() {
                        slot.generation = slot.generation.wrapping_add(1);
                        Some(ring)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(ring) = taken {
            ring.revoke_and_drain();
            true
        } else {
            false
        }
    }

    /// Deterministically revoke ALL buffers and SPSC rings owned by `owner_id`, draining all
    /// in-flight operations before returning so zero post-revocation reads/writes can occur.
    pub fn revoke_owner(&self, owner_id: &str) -> usize {
        let mut taken_buffers = Vec::new();
        let mut taken_rings = Vec::new();

        if let Ok(mut map) = self.buffers.write() {
            for slot in map.values_mut() {
                let matches = slot
                    .region
                    .as_ref()
                    .map(|r| r.descriptor.owner_id == owner_id)
                    .unwrap_or(false);
                if matches {
                    if let Some(reg) = slot.region.take() {
                        slot.generation = slot.generation.wrapping_add(1);
                        taken_buffers.push(reg);
                    }
                }
            }
        }
        if let Ok(mut map) = self.rings.write() {
            for slot in map.values_mut() {
                let matches = slot
                    .ring
                    .as_ref()
                    .map(|r| r.descriptor.owner_id == owner_id)
                    .unwrap_or(false);
                if matches {
                    if let Some(r) = slot.ring.take() {
                        slot.generation = slot.generation.wrapping_add(1);
                        taken_rings.push(r);
                    }
                }
            }
        }

        let count = taken_buffers.len() + taken_rings.len();
        for reg in taken_buffers {
            reg.revoke_and_drain();
        }
        for ring in taken_rings {
            ring.revoke_and_drain();
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_ring_wraparound_ordering_and_inflight_revocation() {
        let arena = NexusSharedArena::new();
        let owner_a = arena.mint_owner_id("erp", "sensor").as_canonical();
        let owner_b = arena.mint_owner_id("erp", "sensor").as_canonical();
        assert_ne!(owner_a, owner_b);

        // SharedMemory MUST fail explicitly as UnsupportedTransport until real shared mapping is wired
        assert_eq!(
            arena.alloc_ring(&owner_a, "nope", 16, TransportMode::SharedMemory).err(),
            Some(ArenaError::UnsupportedTransport)
        );
        assert_eq!(
            arena.alloc_buffer(&owner_a, "nope", 16, TransportMode::SharedMemory).err(),
            Some(ArenaError::UnsupportedTransport)
        );

        let stream_a = arena
            .alloc_ring(&owner_a, "imu.stream", 16, TransportMode::PortableCopy)
            .unwrap();
        let stream_b = arena
            .alloc_ring(&owner_b, "imu.stream", 16, TransportMode::PortableCopy)
            .unwrap();

        let (mut prod_a, mut cons_a) = arena.split_ring(stream_a.handle, Some(&owner_a)).unwrap();
        // Second split MUST fail with Busy
        assert_eq!(
            arena.split_ring(stream_a.handle, Some(&owner_a)).err(),
            Some(ArenaError::Busy)
        );
        let ring_b = arena.get_ring(stream_b.handle, Some(&owner_b)).unwrap();

        // Cross-owner access MUST be rejected
        assert_eq!(
            arena.get_ring(stream_a.handle, Some(&owner_b)).err(),
            Some(ArenaError::PermissionDenied)
        );

        // Wraparound test on stream_a via exclusive typed endpoints
        assert_eq!(prod_a.write(b"0123456789").unwrap(), 10);
        let mut out = [0u8; 6];
        assert_eq!(cons_a.read(&mut out).unwrap(), 6);
        assert_eq!(&out, b"012345");
        assert_eq!(prod_a.write(b"ABCDEFGHIJKL").unwrap(), 12);
        let mut out2 = [0u8; 16];
        assert_eq!(cons_a.read(&mut out2).unwrap(), 16);
        assert_eq!(&out2, b"6789ABCDEFGHIJKL");

        // Revoking owner_a drains and invalidates stream_a immediately without affecting owner_b
        assert_eq!(arena.revoke_owner(&owner_a), 1);
        assert_eq!(prod_a.write(b"x").err(), Some(ArenaError::Revoked));
        assert_eq!(cons_a.read(&mut out).err(), Some(ArenaError::Revoked));
        assert_eq!(
            arena.get_ring(stream_a.handle, Some(&owner_a)).err(),
            Some(ArenaError::Revoked)
        );
        assert_eq!(ring_b.write(b"still-live").unwrap(), 10);
    }

    #[test]
    fn concurrent_spsc_producer_consumer_and_race_free_revocation_stress() {
        let arena = Arc::new(NexusSharedArena::new());
        let owner = arena.mint_owner_id("stress", "stream").as_canonical();
        let stream = arena
            .alloc_ring(&owner, "stress.ring", 256, TransportMode::PortableCopy)
            .unwrap();
        let ring = arena.get_ring(stream.handle, Some(&owner)).unwrap();

        // Concurrent producer + consumer + competing producer + concurrent revocation
        let r_prod1 = ring.clone();
        let r_prod2 = ring.clone();
        let r_cons = ring.clone();
        let arena_rev = arena.clone();
        let owner_rev = owner.clone();

        let t_p1 = std::thread::spawn(move || {
            let mut saw_revoked = false;
            for _ in 0..5_000 {
                match r_prod1.write(b"abcd") {
                    Ok(_) | Err(ArenaError::Busy) => {}
                    Err(ArenaError::Revoked) => {
                        saw_revoked = true;
                        break;
                    }
                    Err(e) => panic!("Unexpected producer error: {:?}", e),
                }
            }
            saw_revoked
        });

        let t_p2 = std::thread::spawn(move || {
            for _ in 0..5_000 {
                match r_prod2.write(b"wxyz") {
                    Ok(_) | Err(ArenaError::Busy) => {}
                    Err(ArenaError::Revoked) => break,
                    Err(e) => panic!("Unexpected competing producer error: {:?}", e),
                }
            }
        });

        let t_cons = std::thread::spawn(move || {
            let mut buf = [0u8; 32];
            for _ in 0..5_000 {
                match r_cons.read(&mut buf) {
                    Ok(_) | Err(ArenaError::Busy) => {}
                    Err(ArenaError::Revoked) => break,
                    Err(e) => panic!("Unexpected consumer error: {:?}", e),
                }
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(arena_rev.revoke_owner(&owner_rev), 1);

        // Immediately after `revoke_owner` returns, NO write or read may ever succeed
        assert_eq!(ring.write(b"post-revoke").err(), Some(ArenaError::Revoked));
        let mut post = [0u8; 8];
        assert_eq!(ring.read(&mut post).err(), Some(ArenaError::Revoked));

        let _ = t_p1.join().unwrap();
        t_p2.join().unwrap();
        t_cons.join().unwrap();
    }

    #[test]
    fn flat_buffer_bounds_and_inflight_revocation() {
        let arena = NexusSharedArena::new();
        let owner = arena.mint_owner_id("erp", "ui").as_canonical();
        let lease = arena
            .alloc_buffer(&owner, "ui.ops", 64, TransportMode::PortableCopy)
            .unwrap();
        let reg = arena.get_buffer(lease.handle, Some(&owner)).unwrap();
        assert_eq!(reg.write_at(0, b"nexus-zczs").unwrap(), 10);
        assert_eq!(reg.write_at(60, b"overflow!").err(), Some(ArenaError::OutOfBounds));

        let mut dst = [0u8; 10];
        assert_eq!(reg.read_at(0, &mut dst).unwrap(), 10);
        assert_eq!(&dst, b"nexus-zczs");

        assert_eq!(arena.revoke_owner(&owner), 1);
        assert_eq!(reg.write_at(0, b"nope").err(), Some(ArenaError::Revoked));
        assert_eq!(reg.read_at(0, &mut dst).err(), Some(ArenaError::Revoked));
    }
}
