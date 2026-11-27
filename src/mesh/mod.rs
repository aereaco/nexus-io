//! Track B: Nexus 6-Layer Resource Mesh & Scoped Hybrid Consensus
//!
//! Separates:
//! 1. **Soft-State Resource Fabric (`resources.rs`):** Signed CRDT (LWW-Element-Set) gossip
//!    advertising CPU, GPU/VRAM, RAM/SharedArena, and CAS storage capabilities + policy-aware placement.
//! 2. **Scoped Hybrid Consensus (`consensus.rs`):** Partitioned coordination groups with
//!    `CftFastPath` (Model A, `2f+1`, 1-RTT) and opt-in `BftSigned` (Model B, `3f+1` + equivocation
//!    detection), Ed25519 signed Quorum Certificates, and monotonic fencing epochs on all leases.

pub mod consensus;
pub mod resources;
