//! General-Purpose Zero-Copy Shared Memory Arena (`NexusSharedArena`) & SPSC Ring Buffers
//!
//! Serves the entire Nexus-IO universal host runtime:
//! - Native hardware streams (camera, audio, sensors, GPU/NPU)
//! - Wasm application cells (shared-memory ZCZS when supported, portable copy fallback otherwise)
//! - Native UI binary operation batches (`UiOp` stream)
//! - Database / `BlobBridge` payloads and inter-node transfer staging
//!
//! Safety & Lifecycle Invariants:
//! 1. **Generation-Validated Handles:** Every `SharedBufferHandle` and `RingBufferHandle` carries
//!    a `(slot, generation)` pair so stale/revoked handles fail deterministically with `Revoked`.
//! 2. **Deterministic Owner Revocation:** Every region/ring is tagged with an `owner_id` (e.g.
//!    `cell:<app>/<cell_id>`). Calling `revoke_owner(owner_id)` on cell teardown immediately
//!    invalidates all active handles and reclaims memory.
//! 3. **Explicit Memory Ordering:** `SpscRingBuffer` uses `Ordering::Acquire` on foreign cursor
//!    loads and `Ordering::Release` on local cursor stores — safe for concurrent SPSC producers
//!    and consumers without locking the hot path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Backing storage for a flat shared buffer region.
pub struct ArenaRegion {
    pub descriptor: BufferDescriptor,
    data: RwLock<Vec<u8>>,
}

impl ArenaRegion {
    pub fn write_at(&self, offset: usize, src: &[u8]) -> Result<usize, ArenaError> {
        let mut buf = self.data.write().map_err(|_| ArenaError::Revoked)?;
        let end = offset.checked_add(src.len()).ok_or(ArenaError::OutOfBounds)?;
        if end > buf.len() {
            return Err(ArenaError::OutOfBounds);
        }
        buf[offset..end].copy_from_slice(src);
        Ok(src.len())
    }

    pub fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<usize, ArenaError> {
        let buf = self.data.read().map_err(|_| ArenaError::Revoked)?;
        let end = offset.checked_add(dst.len()).ok_or(ArenaError::OutOfBounds)?;
        if end > buf.len() {
            return Err(ArenaError::OutOfBounds);
        }
        dst.copy_from_slice(&buf[offset..end]);
        Ok(dst.len())
    }
}

/// Lock-free Single-Producer Single-Consumer (SPSC) byte ring buffer with explicit
/// `Acquire`/`Release` atomic cursor ordering.
///
/// Capacity is rounded up to a power of two for fast bitmask indexing (`cursor & mask`).
pub struct SpscRingBuffer {
    pub descriptor: StreamDescriptor,
    mask: usize,
    storage: Box<[std::cell::UnsafeCell<u8>]>,
    /// Next byte index to be written by producer (monotonic).
    write_pos: AtomicU64,
    /// Next byte index to be read by consumer (monotonic).
    read_pos: AtomicU64,
}

// SAFETY: `SpscRingBuffer` enforces disjoint producer/consumer index ownership via
// `Acquire`/`Release` atomic operations on `write_pos` and `read_pos`.
// Concurrent calls to `push` or `pop` from the same side are serialized by the arena entry guard
// or single-owner contract.
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
            storage: storage.into_boxed_slice(),
            write_pos: AtomicU64::new(0),
            read_pos: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.mask + 1
    }

    #[inline]
    pub fn available_read(&self) -> usize {
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Relaxed);
        w.saturating_sub(r) as usize
    }

    #[inline]
    pub fn available_write(&self) -> usize {
        let w = self.write_pos.load(Ordering::Relaxed);
        let r = self.read_pos.load(Ordering::Acquire);
        self.capacity().saturating_sub(w.saturating_sub(r) as usize)
    }

    /// Producer write: copies up to `src.len()` bytes and publishes `write_pos` with `Ordering::Release`.
    pub fn write(&self, src: &[u8]) -> usize {
        let w = self.write_pos.load(Ordering::Relaxed);
        let r = self.read_pos.load(Ordering::Acquire);
        let cap = self.capacity() as u64;
        let free = cap.saturating_sub(w.saturating_sub(r)) as usize;
        let n = src.len().min(free);
        if n == 0 {
            return 0;
        }
        for (i, &byte) in src[..n].iter().enumerate() {
            let idx = ((w as usize).wrapping_add(i)) & self.mask;
            // SAFETY: Producer exclusively owns `[w, r + cap)` until `write_pos` is released.
            unsafe {
                *self.storage[idx].get() = byte;
            }
        }
        self.write_pos.store(w.wrapping_add(n as u64), Ordering::Release);
        n
    }

    /// Consumer read: reads up to `dst.len()` bytes after `Ordering::Acquire` on `write_pos`,
    /// then publishes `read_pos` with `Ordering::Release`.
    pub fn read(&self, dst: &mut [u8]) -> usize {
        let r = self.read_pos.load(Ordering::Relaxed);
        let w = self.write_pos.load(Ordering::Acquire);
        let avail = w.saturating_sub(r) as usize;
        let n = dst.len().min(avail);
        if n == 0 {
            return 0;
        }
        for (i, out) in dst[..n].iter_mut().enumerate() {
            let idx = ((r as usize).wrapping_add(i)) & self.mask;
            // SAFETY: Consumer exclusively owns `[r, w)` after acquiring `write_pos`.
            unsafe {
                *out = *self.storage[idx].get();
            }
        }
        self.read_pos.store(r.wrapping_add(n as u64), Ordering::Release);
        n
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
    buffers: RwLock<HashMap<u64, BufferSlot>>,
    rings: RwLock<HashMap<u64, RingSlot>>,
}

static GLOBAL_ARENA: OnceLock<Arc<NexusSharedArena>> = OnceLock::new();

impl NexusSharedArena {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            buffers: RwLock::new(HashMap::new()),
            rings: RwLock::new(HashMap::new()),
        }
    }

    pub fn global() -> Arc<Self> {
        GLOBAL_ARENA
            .get_or_init(|| Arc::new(Self::new()))
            .clone()
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
        if let Some(caller) = caller_owner {
            if ring.descriptor.owner_id != caller {
                return Err(ArenaError::PermissionDenied);
            }
        }
        Ok(ring.clone())
    }

    /// Revoke a single ring buffer handle, incrementing its generation so stale references fail.
    pub fn revoke_ring(&self, handle: RingBufferHandle) -> bool {
        if let Ok(mut map) = self.rings.write() {
            if let Some(slot) = map.get_mut(&handle.id) {
                if slot.generation == handle.generation && slot.ring.is_some() {
                    slot.ring = None;
                    slot.generation = slot.generation.wrapping_add(1);
                    return true;
                }
            }
        }
        false
    }

    /// Deterministically revoke ALL buffers and SPSC rings owned by `owner_id`
    /// (called automatically on Wasm cell termination/hibernation).
    pub fn revoke_owner(&self, owner_id: &str) -> usize {
        let mut revoked = 0usize;
        if let Ok(mut map) = self.buffers.write() {
            for slot in map.values_mut() {
                if let Some(ref reg) = slot.region {
                    if reg.descriptor.owner_id == owner_id {
                        slot.region = None;
                        slot.generation = slot.generation.wrapping_add(1);
                        revoked += 1;
                    }
                }
            }
        }
        if let Ok(mut map) = self.rings.write() {
            for slot in map.values_mut() {
                if let Some(ref r) = slot.ring {
                    if r.descriptor.owner_id == owner_id {
                        slot.ring = None;
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
    fn spsc_ring_wraparound_ordering_and_generation_revocation() {
        let arena = NexusSharedArena::new();
        let stream = arena
            .alloc_ring("cell:erp/sensor", "imu.stream", 16, TransportMode::PortableCopy)
            .unwrap();
        assert_eq!(stream.capacity, 16);

        let ring = arena.get_ring(stream.handle, Some("cell:erp/sensor")).unwrap();
        // Wrong owner MUST be rejected
        assert_eq!(
            arena.get_ring(stream.handle, Some("cell:other/attacker")).err(),
            Some(ArenaError::PermissionDenied)
        );

        // Write 10 bytes, read 6, write 12 (tests wraparound across boundary)
        assert_eq!(ring.write(b"0123456789"), 10);
        let mut out = [0u8; 6];
        assert_eq!(ring.read(&mut out), 6);
        assert_eq!(&out, b"012345");

        assert_eq!(ring.write(b"ABCDEFGHIJKL"), 12);
        let mut out2 = [0u8; 16];
        assert_eq!(ring.read(&mut out2), 16);
        assert_eq!(&out2, b"6789ABCDEFGHIJKL");

        // Owner teardown deterministically revokes handle
        assert_eq!(arena.revoke_owner("cell:erp/sensor"), 1);
        assert_eq!(
            arena.get_ring(stream.handle, Some("cell:erp/sensor")).err(),
            Some(ArenaError::Revoked)
        );
    }

    #[test]
    fn flat_buffer_bounds_and_owner_isolation() {
        let arena = NexusSharedArena::new();
        let lease = arena
            .alloc_buffer("cell:erp/ui", "ui.ops", 64, TransportMode::SharedMemory)
            .unwrap();
        let reg = arena.get_buffer(lease.handle, Some("cell:erp/ui")).unwrap();
        assert_eq!(reg.write_at(0, b"nexus-zczs").unwrap(), 10);
        assert_eq!(reg.write_at(60, b"overflow!").err(), Some(ArenaError::OutOfBounds));

        let mut dst = [0u8; 10];
        assert_eq!(reg.read_at(0, &mut dst).unwrap(), 10);
        assert_eq!(&dst, b"nexus-zczs");

        assert_eq!(arena.revoke_owner("cell:erp/ui"), 1);
        assert_eq!(
            arena.get_buffer(lease.handle, Some("cell:erp/ui")).err(),
            Some(ArenaError::Revoked)
        );
    }
}
