//! General-Purpose Zero-Copy Shared Memory Arena (`NexusSharedArena`) & SPSC Ring Buffers
//!
//! Serves the entire Nexus-IO universal host runtime:
//! - Native hardware streams (camera, audio, sensors, GPU/NPU)
//! - Wasm application cells (shared-memory ZCZS when supported, portable copy fallback otherwise)
//! - Native UI binary operation batches (`UiOp` stream)
//! - Database / `BlobBridge` payloads and inter-node transfer staging
//!
//! Security & Lifecycle Invariants:
//! 1. **Globally Unique Execution Owner Identity (`ArenaOwnerId`):** Every cell execution mints a
//!    unique `(app, cell_id, monotonic_exec_seq)` identity via `mint_owner_id()`, so two concurrent
//!    invocations of the same cell can NEVER collide or revoke each other's handles.
//! 2. **Generation-Validated Handles:** Every `SharedBufferHandle` and `RingBufferHandle` carries
//!    a `(monotonic_id, generation)` pair so stale/revoked handles can never alias a new slot.
//! 3. **Immediate In-Flight Revocation (`AtomicBool`):** Both `ArenaRegion` and `SpscRingBuffer`
//!    embed an `AtomicBool` (`revoked`) checked with `Ordering::Acquire` on every read/write and
//!    set with `Ordering::Release` inside `revoke_owner()` / `revoke_ring()`. Even an already-cloned
//!    `Arc` fails closed with `ArenaError::Revoked` immediately on revocation.
//! 4. **Explicit Memory Ordering:** `SpscRingBuffer` uses `Ordering::Acquire` on foreign cursor
//!    loads and `Ordering::Release` on local cursor stores.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Explicit data-plane transport mode behind the same logical arena interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Genuine shared-memory access (host + guest share imported linear memory / mmap region).
    SharedMemory,
    /// Portable single-copy baseline (host copies directly to/from guest linear memory, zero serialization).
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

/// Generation-validated handle to a flat `ArenaRegion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SharedBufferHandle {
    pub id: u64,
    pub generation: u32,
}

/// Generation-validated handle to a lock-free `SpscRingBuffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RingBufferHandle {
    pub id: u64,
    pub generation: u32,
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

/// Typed arena errors (never panics on guest bounds or stale handle access).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArenaError {
    NotFound,
    Revoked,
    PermissionDenied,
    OutOfBounds,
    InvalidCapacity,
    BufferFull,
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
        }
    }
}

impl std::error::Error for ArenaError {}

/// Backing storage for a flat shared buffer region with immediate revocation guard.
pub struct ArenaRegion {
    pub descriptor: BufferDescriptor,
    revoked: AtomicBool,
    data: RwLock<Vec<u8>>,
}

impl ArenaRegion {
    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub(crate) fn mark_revoked(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub fn write_at(&self, offset: usize, src: &[u8]) -> Result<usize, ArenaError> {
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        let mut buf = self.data.write().map_err(|_| ArenaError::Revoked)?;
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        let end = offset.checked_add(src.len()).ok_or(ArenaError::OutOfBounds)?;
        if end > buf.len() {
            return Err(ArenaError::OutOfBounds);
        }
        buf[offset..end].copy_from_slice(src);
        Ok(src.len())
    }

    pub fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<usize, ArenaError> {
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        let buf = self.data.read().map_err(|_| ArenaError::Revoked)?;
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        let end = offset.checked_add(dst.len()).ok_or(ArenaError::OutOfBounds)?;
        if end > buf.len() {
            return Err(ArenaError::OutOfBounds);
        }
        dst.copy_from_slice(&buf[offset..end]);
        Ok(dst.len())
    }
}

/// Lock-free Single-Producer Single-Consumer (SPSC) byte ring buffer with explicit
/// `Acquire`/`Release` atomic cursor ordering and immediate revocation guard.
///
/// Capacity is rounded up to a power of two for fast bitmask indexing (`cursor & mask`).
pub struct SpscRingBuffer {
    pub descriptor: StreamDescriptor,
    mask: usize,
    revoked: AtomicBool,
    storage: Box<[std::cell::UnsafeCell<u8>]>,
    /// Next byte index to be written by producer (monotonic).
    write_pos: AtomicU64,
    /// Next byte index to be read by consumer (monotonic).
    read_pos: AtomicU64,
}

// SAFETY: `SpscRingBuffer` enforces disjoint producer/consumer index ownership via
// `Acquire`/`Release` atomic operations on `write_pos` and `read_pos`.
unsafe impl Send for SpscRingBuffer {}
unsafe impl Sync for SpscRingBuffer {}

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
            revoked: AtomicBool::new(false),
            storage: storage.into_boxed_slice(),
            write_pos: AtomicU64::new(0),
            read_pos: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub(crate) fn mark_revoked(&self) {
        self.revoked.store(true, Ordering::Release);
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

    /// Producer write: checks revocation, copies up to `src.len()` bytes, and publishes `write_pos`
    /// with `Ordering::Release`.
    pub fn write(&self, src: &[u8]) -> Result<usize, ArenaError> {
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
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
            // SAFETY: Producer exclusively owns `[w, r + cap)` until `write_pos` is released.
            unsafe {
                *self.storage[idx].get() = byte;
            }
        }
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        self.write_pos.store(w.wrapping_add(n as u64), Ordering::Release);
        Ok(n)
    }

    /// Consumer read: checks revocation, reads up to `dst.len()` bytes after `Ordering::Acquire`
    /// on `write_pos`, then publishes `read_pos` with `Ordering::Release`.
    pub fn read(&self, dst: &mut [u8]) -> Result<usize, ArenaError> {
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
        }
        let r = self.read_pos.load(Ordering::Relaxed);
        let w = self.write_pos.load(Ordering::Acquire);
        let avail = w.saturating_sub(r) as usize;
        let n = dst.len().min(avail);
        if n == 0 {
            return Ok(0);
        }
        for (i, out) in dst[..n].iter_mut().enumerate() {
            let idx = ((r as usize).wrapping_add(i)) & self.mask;
            // SAFETY: Consumer exclusively owns `[r, w)` after acquiring `write_pos`.
            unsafe {
                *out = *self.storage[idx].get();
            }
        }
        if self.is_revoked() {
            return Err(ArenaError::Revoked);
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
}

/// Process-wide general-purpose shared memory & SPSC ring buffer arena.
pub struct NexusSharedArena {
    next_id: AtomicU64,
    next_exec_seq: AtomicU64,
    buffers: RwLock<HashMap<u64, BufferSlot>>,
    rings: RwLock<HashMap<u64, RingSlot>>,
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
            next_id: AtomicU64::new(1),
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

    /// Mint a globally unique execution owner identity (`app`, `cell_id`, monotonic `exec_seq`).
    pub fn mint_owner_id(&self, app: impl Into<String>, cell_id: impl Into<String>) -> ArenaOwnerId {
        ArenaOwnerId {
            app: app.into(),
            cell_id: cell_id.into(),
            exec_seq: self.next_exec_seq.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Allocate a flat `ArenaRegion` owned by `owner_id`.
    pub fn alloc_buffer(
        &self,
        owner_id: impl Into<String>,
        label: impl Into<String>,
        capacity: usize,
        transport: TransportMode,
    ) -> Result<BufferLease, ArenaError> {
        if capacity == 0 || capacity > (64 * 1024 * 1024) {
            return Err(ArenaError::InvalidCapacity);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
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
            revoked: AtomicBool::new(false),
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
    pub fn alloc_ring(
        &self,
        owner_id: impl Into<String>,
        label: impl Into<String>,
        capacity: usize,
        transport: TransportMode,
    ) -> Result<StreamDescriptor, ArenaError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
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
            },
        );
        Ok(actual_desc)
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

    /// Revoke a single ring buffer handle, marking it revoked immediately and incrementing generation.
    pub fn revoke_ring(&self, handle: RingBufferHandle) -> bool {
        if let Ok(mut map) = self.rings.write() {
            if let Some(slot) = map.get_mut(&handle.id) {
                if slot.generation == handle.generation {
                    if let Some(ring) = slot.ring.take() {
                        ring.mark_revoked();
                        slot.generation = slot.generation.wrapping_add(1);
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Deterministically revoke ALL buffers and SPSC rings owned by `owner_id`.
    /// Marks every underlying `ArenaRegion` / `SpscRingBuffer` revoked immediately so even
    /// already-cloned in-flight `Arc` references fail closed with `ArenaError::Revoked`.
    pub fn revoke_owner(&self, owner_id: &str) -> usize {
        let mut revoked = 0usize;
        if let Ok(mut map) = self.buffers.write() {
            for slot in map.values_mut() {
                let matches = slot
                    .region
                    .as_ref()
                    .map(|r| r.descriptor.owner_id == owner_id)
                    .unwrap_or(false);
                if matches {
                    if let Some(reg) = slot.region.take() {
                        reg.mark_revoked();
                        slot.generation = slot.generation.wrapping_add(1);
                        revoked += 1;
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
                        r.mark_revoked();
                        slot.generation = slot.generation.wrapping_add(1);
                        revoked += 1;
                    }
                }
            }
        }
        revoked
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
        assert_ne!(owner_a, owner_b, "Two executions of the same cell MUST have distinct ArenaOwnerIds");

        let stream_a = arena
            .alloc_ring(&owner_a, "imu.stream", 16, TransportMode::PortableCopy)
            .unwrap();
        let stream_b = arena
            .alloc_ring(&owner_b, "imu.stream", 16, TransportMode::PortableCopy)
            .unwrap();

        let ring_a = arena.get_ring(stream_a.handle, Some(&owner_a)).unwrap();
        let ring_b = arena.get_ring(stream_b.handle, Some(&owner_b)).unwrap();

        // Cross-owner access MUST be rejected
        assert_eq!(
            arena.get_ring(stream_a.handle, Some(&owner_b)).err(),
            Some(ArenaError::PermissionDenied)
        );

        // Wraparound test on ring_a
        assert_eq!(ring_a.write(b"0123456789").unwrap(), 10);
        let mut out = [0u8; 6];
        assert_eq!(ring_a.read(&mut out).unwrap(), 6);
        assert_eq!(&out, b"012345");
        assert_eq!(ring_a.write(b"ABCDEFGHIJKL").unwrap(), 12);
        let mut out2 = [0u8; 16];
        assert_eq!(ring_a.read(&mut out2).unwrap(), 16);
        assert_eq!(&out2, b"6789ABCDEFGHIJKL");

        // Revoking owner_a MUST invalidate ring_a immediately (even on an already-held Arc!)
        // and MUST NOT affect owner_b's concurrent stream!
        assert_eq!(arena.revoke_owner(&owner_a), 1);
        assert_eq!(ring_a.write(b"x").err(), Some(ArenaError::Revoked));
        assert_eq!(ring_a.read(&mut out).err(), Some(ArenaError::Revoked));
        assert_eq!(
            arena.get_ring(stream_a.handle, Some(&owner_a)).err(),
            Some(ArenaError::Revoked)
        );

        // Owner B remains completely unaffected
        assert_eq!(ring_b.write(b"still-live").unwrap(), 10);
    }

    #[test]
    fn flat_buffer_bounds_and_inflight_revocation() {
        let arena = NexusSharedArena::new();
        let owner = arena.mint_owner_id("erp", "ui").as_canonical();
        let lease = arena
            .alloc_buffer(&owner, "ui.ops", 64, TransportMode::SharedMemory)
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
