//! Nexus Soft-State Resource Fabric (Canonical Signed CRDT Gossip, Atomic Reservations & CAS Locality)
//!
//! Hardening Invariants (P0.1):
//! 1. **Single Canonical Length-Prefixed Signing Format:** Every security- and scheduling-relevant
//!    field (`node_id`, `identity_id`, `org_id`, `group_id`, `region`, `ed25519_pubkey`, `cpu_arch`,
//!    `cpu_cores`, `available_cpu_cores`, `ram_mb`, `available_ram_mb`, `shared_arena_mb`,
//!    `cas_storage_gb`, `verified_local_cas_cids`, `advertised_cas_cids`, all `GpuCapability` fields
//!    including sorted `apis`, `wasm_slots`, `healthy`, `tombstone`, `expires_at_ms`, `lamport_ts`)
//!    is covered by one canonical encoder (`canonical_bytes()`).
//! 2. **Authorized Mesh Membership Binding:** `merge_advertisement` validates `(node_id, identity_id,
//!    org_id, ed25519_pubkey)` against an authoritative `CoordinationGroup` — untrusted nodes cannot
//!    self-assert organization membership.
//! 3. **Deterministic CRDT Convergence:** Equal `lamport_ts` breaks ties deterministically using
//!    `blake3(canonical_bytes)` (commutative, associative, idempotent), with explicit tombstones
//!    and TTL expiration.
//! 4. **Atomic Capacity Reservations & Verified CAS Locality:** `ReservationLedger` accounts for
//!    active CPU/RAM/GPU/Wasm reservations separately from advertisements, and scheduling
//!    distinguishes verified local CAS availability from merely advertised CIDs.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::mesh::consensus::{
    hash_proposal, CoordinationGroup, FencedLease, SignedVote, VoteRequest, VoterNode,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuCapability {
    pub vendor: String,
    pub model: String,
    pub vram_mb: u64,
    pub free_vram_mb: u64,
    pub apis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAdvertisement {
    pub node_id: String,
    pub identity_id: String,
    pub org_id: String,
    pub group_id: String,
    pub region: String,
    pub ed25519_pubkey: String,
    pub cpu_arch: String,
    pub cpu_cores: u32,
    pub available_cpu_cores: u32,
    pub ram_mb: u64,
    pub available_ram_mb: u64,
    pub shared_arena_mb: u64,
    pub cas_storage_gb: u64,
    /// CAS CIDs whose local presence/integrity has been verified on this node.
    #[serde(default)]
    pub verified_local_cas_cids: Vec<String>,
    /// CAS CIDs merely advertised as reachable/cached.
    #[serde(default)]
    pub advertised_cas_cids: Vec<String>,
    pub gpus: Vec<GpuCapability>,
    pub wasm_slots: u32,
    pub healthy: bool,
    #[serde(default)]
    pub tombstone: bool,
    pub expires_at_ms: u64,
    pub lamport_ts: u64,
    pub signature: String,
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl NodeAdvertisement {
    /// Single canonical length-prefixed encoding covering ALL security- and scheduling-relevant fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"NEXUS-NODE-ADV-v2");
        for s in [
            self.node_id.as_str(),
            self.identity_id.as_str(),
            self.org_id.as_str(),
            self.group_id.as_str(),
            self.region.as_str(),
            self.ed25519_pubkey.as_str(),
            self.cpu_arch.as_str(),
        ] {
            push_len_prefixed(&mut out, s.as_bytes());
        }
        out.extend_from_slice(&self.cpu_cores.to_be_bytes());
        out.extend_from_slice(&self.available_cpu_cores.to_be_bytes());
        out.extend_from_slice(&self.ram_mb.to_be_bytes());
        out.extend_from_slice(&self.available_ram_mb.to_be_bytes());
        out.extend_from_slice(&self.shared_arena_mb.to_be_bytes());
        out.extend_from_slice(&self.cas_storage_gb.to_be_bytes());
        out.extend_from_slice(&self.wasm_slots.to_be_bytes());
        out.push(u8::from(self.healthy));
        out.push(u8::from(self.tombstone));
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.lamport_ts.to_be_bytes());

        let mut verified_cids = self.verified_local_cas_cids.clone();
        verified_cids.sort();
        out.extend_from_slice(&(verified_cids.len() as u32).to_be_bytes());
        for c in &verified_cids {
            push_len_prefixed(&mut out, c.as_bytes());
        }

        let mut adv_cids = self.advertised_cas_cids.clone();
        adv_cids.sort();
        out.extend_from_slice(&(adv_cids.len() as u32).to_be_bytes());
        for c in &adv_cids {
            push_len_prefixed(&mut out, c.as_bytes());
        }

        out.extend_from_slice(&(self.gpus.len() as u32).to_be_bytes());
        for g in &self.gpus {
            push_len_prefixed(&mut out, g.vendor.as_bytes());
            push_len_prefixed(&mut out, g.model.as_bytes());
            out.extend_from_slice(&g.vram_mb.to_be_bytes());
            out.extend_from_slice(&g.free_vram_mb.to_be_bytes());
            let mut apis = g.apis.clone();
            apis.sort();
            out.extend_from_slice(&(apis.len() as u32).to_be_bytes());
            for api in &apis {
                push_len_prefixed(&mut out, api.as_bytes());
            }
        }
        out
    }

    pub fn canonical_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    pub fn sign(&mut self, sk_b64: &str) -> Result<()> {
        let bytes = self.canonical_bytes();
        self.signature = nexus_db::auth::ed25519_sign(sk_b64, &bytes)?;
        Ok(())
    }

    pub fn verify_signature_with_pubkey(&self, authorized_pubkey: &str) -> bool {
        let bytes = self.canonical_bytes();
        nexus_db::auth::ed25519_verify(authorized_pubkey, &bytes, &self.signature)
    }
}

/// Deterministic, membership-authenticated LWW-Element-Set CRDT for mesh resource discovery.
#[derive(Debug, Clone, Default)]
pub struct ResourceMeshCrdt {
    pub nodes: HashMap<String, NodeAdvertisement>,
}

impl ResourceMeshCrdt {
    pub fn new() -> Self {
        Self::default()
    }

    /// Authenticate `adv` against `group` membership (`node_id`, `identity_id`, `org_id`,
    /// `ed25519_pubkey`, `group_id`), reject expired non-tombstone records at ingestion, and merge
    /// deterministically using `(lamport_ts, tombstone, canonical_digest)`.
    pub fn merge_advertisement(
        &mut self,
        adv: NodeAdvertisement,
        group: &CoordinationGroup,
        now_ms: u64,
    ) -> Result<bool> {
        if !adv.tombstone && now_ms >= adv.expires_at_ms {
            anyhow::bail!(
                "Rejected expired NodeAdvertisement from '{}' (expires_at_ms={} <= now={})",
                adv.node_id,
                adv.expires_at_ms,
                now_ms
            );
        }
        if adv.group_id != group.group_id {
            anyhow::bail!(
                "Advertisement group_id '{}' does not match authorized group '{}'",
                adv.group_id,
                group.group_id
            );
        }
        let member = group.members.get(&adv.node_id).ok_or_else(|| {
            anyhow!(
                "Node '{}' is not an authorized member of coordination group '{}'",
                adv.node_id,
                group.group_id
            )
        })?;
        if member.identity_id != adv.identity_id
            || member.org_id != adv.org_id
            || member.ed25519_pubkey != adv.ed25519_pubkey
        {
            anyhow::bail!(
                "Advertisement identity/org/pubkey mismatch for node '{}' against authorized membership",
                adv.node_id
            );
        }
        if !adv.verify_signature_with_pubkey(&member.ed25519_pubkey) {
            anyhow::bail!(
                "Rejected NodeAdvertisement with invalid Ed25519 signature from '{}'",
                adv.node_id
            );
        }

        if let Some(existing) = self.nodes.get(&adv.node_id) {
            let new_key = (adv.lamport_ts, adv.tombstone, adv.canonical_digest());
            let old_key = (existing.lamport_ts, existing.tombstone, existing.canonical_digest());
            if new_key <= old_key {
                return Ok(false);
            }
        }
        self.nodes.insert(adv.node_id.clone(), adv);
        Ok(true)
    }

    /// Gossip anti-entropy merge: commutative, associative, idempotent under equal timestamps!
    pub fn merge_gossip(
        &mut self,
        other: &ResourceMeshCrdt,
        group: &CoordinationGroup,
        now_ms: u64,
    ) -> Result<usize> {
        let mut updated = 0usize;
        for adv in other.nodes.values() {
            if !adv.tombstone && now_ms >= adv.expires_at_ms {
                continue;
            }
            if self.merge_advertisement(adv.clone(), group, now_ms)? {
                updated += 1;
            }
        }
        Ok(updated)
    }

    /// Garbage-collect both expired ordinary advertisements AND tombstones older than `tombstone_retention_ms`.
    /// Active tombstones within `tombstone_retention_ms` are retained to prevent stale resurrection.
    pub fn gc_expired(&mut self, now_ms: u64, tombstone_retention_ms: u64) -> usize {
        let before = self.nodes.len();
        self.nodes.retain(|_, adv| {
            if adv.tombstone {
                now_ms.saturating_sub(adv.expires_at_ms) <= tombstone_retention_ms
            } else {
                now_ms < adv.expires_at_ms
            }
        });
        before.saturating_sub(self.nodes.len())
    }
}

/// Authoritative per-node reservation ledger so advertised capacity is NEVER double-booked.
#[derive(Debug, Clone, Default)]
pub struct NodeReservation {
    pub cpu_cores: u32,
    pub ram_mb: u64,
    pub gpu_vram_mb: u64,
    pub wasm_slots: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ReservationLedger {
    /// Active reservations keyed by `workload_id` -> `(node_id, NodeReservation)`.
    active: HashMap<String, (String, NodeReservation)>,
}

impl ReservationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reserved_for_node(&self, node_id: &str) -> NodeReservation {
        let mut sum = NodeReservation::default();
        for (nid, res) in self.active.values() {
            if nid == node_id {
                sum.cpu_cores = sum.cpu_cores.saturating_add(res.cpu_cores);
                sum.ram_mb = sum.ram_mb.saturating_add(res.ram_mb);
                sum.gpu_vram_mb = sum.gpu_vram_mb.saturating_add(res.gpu_vram_mb);
                sum.wasm_slots = sum.wasm_slots.saturating_add(res.wasm_slots);
            }
        }
        sum
    }

    pub fn reserve(
        &mut self,
        workload_id: &str,
        node: &NodeAdvertisement,
        req: NodeReservation,
    ) -> Result<()> {
        let used = self.reserved_for_node(&node.node_id);
        let free_cpu = node.available_cpu_cores.saturating_sub(used.cpu_cores);
        let free_ram = node.available_ram_mb.saturating_sub(used.ram_mb);
        let free_wasm = node.wasm_slots.saturating_sub(used.wasm_slots);
        let max_gpu_free = node
            .gpus
            .iter()
            .map(|g| g.free_vram_mb)
            .max()
            .unwrap_or(0)
            .saturating_sub(used.gpu_vram_mb);

        if req.cpu_cores > free_cpu
            || req.ram_mb > free_ram
            || req.wasm_slots > free_wasm
            || req.gpu_vram_mb > max_gpu_free
        {
            anyhow::bail!(
                "Insufficient unreserved capacity on node '{}' (free cpu={}, ram={}MB, gpu={}MB, wasm={})",
                node.node_id,
                free_cpu,
                free_ram,
                max_gpu_free,
                free_wasm
            );
        }
        self.active
            .insert(workload_id.to_string(), (node.node_id.clone(), req));
        Ok(())
    }

    pub fn release(&mut self, workload_id: &str) {
        self.active.remove(workload_id);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadSpec {
    pub workload_id: String,
    pub required_org_id: String,
    pub min_cpu_cores: u32,
    pub min_ram_mb: u64,
    pub min_gpu_vram_mb: u64,
    pub required_gpu_api: Option<String>,
    #[serde(default)]
    pub required_wasm_slots: u32,
    pub preferred_region: Option<String>,
    pub input_cas_cid: Option<String>,
    /// If true, only nodes with `input_cas_cid` in `verified_local_cas_cids` are eligible.
    #[serde(default)]
    pub require_verified_cas_locality: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementDecision {
    pub workload_id: String,
    pub selected_node_id: String,
    pub resource_key: String,
    pub verified_cas_local: bool,
    pub lease: FencedLease,
}

/// Select the best healthy, authorized, unexpired node accounting for `ReservationLedger` +
/// verified CAS locality, collect durable votes from `voters`, and commit a quorum-fenced lease.
#[allow(clippy::too_many_arguments)]
pub async fn schedule_and_lease_workload(
    crdt: &ResourceMeshCrdt,
    reservations: &mut ReservationLedger,
    group: &mut CoordinationGroup,
    spec: &WorkloadSpec,
    resource_key: &str,
    ttl_ms: u64,
    now: u64,
    online_voters: &[VoterNode],
) -> Result<PlacementDecision> {
    let mut candidates: Vec<(&NodeAdvertisement, i64, bool)> = crdt
        .nodes
        .values()
        .filter_map(|n| {
            // Must be healthy, non-tombstone, unexpired, and authorized in `group` for `required_org_id`
            if !n.healthy || n.tombstone || now >= n.expires_at_ms || n.org_id != spec.required_org_id {
                return None;
            }
            let member = group.members.get(&n.node_id)?;
            if member.org_id != spec.required_org_id || member.identity_id != n.identity_id {
                return None;
            }

            let used = reservations.reserved_for_node(&n.node_id);
            let free_cpu = n.available_cpu_cores.saturating_sub(used.cpu_cores);
            let free_ram = n.available_ram_mb.saturating_sub(used.ram_mb);
            let free_wasm = n.wasm_slots.saturating_sub(used.wasm_slots);
            if free_cpu < spec.min_cpu_cores
                || free_ram < spec.min_ram_mb
                || free_wasm < spec.required_wasm_slots
            {
                return None;
            }

            if spec.min_gpu_vram_mb > 0 {
                let gpu_ok = n.gpus.iter().any(|g| {
                    g.free_vram_mb.saturating_sub(used.gpu_vram_mb) >= spec.min_gpu_vram_mb
                        && spec
                            .required_gpu_api
                            .as_deref()
                            .map(|api| g.apis.iter().any(|a| a.eq_ignore_ascii_case(api)))
                            .unwrap_or(true)
                });
                if !gpu_ok {
                    return None;
                }
            }

            let verified_local = spec
                .input_cas_cid
                .as_deref()
                .map(|cid| n.verified_local_cas_cids.iter().any(|c| c == cid))
                .unwrap_or(false);
            let advertised_local = spec
                .input_cas_cid
                .as_deref()
                .map(|cid| n.advertised_cas_cids.iter().any(|c| c == cid))
                .unwrap_or(false);
            if spec.require_verified_cas_locality && spec.input_cas_cid.is_some() && !verified_local {
                return None;
            }

            let mut score = (free_cpu as i64) * 10 + (n.shared_arena_mb as i64 / 64);
            if let Some(ref pref) = spec.preferred_region {
                if &n.region == pref {
                    score += 500;
                }
            }
            if verified_local {
                score += 2000; // Strong preference for cryptographically/locally verified CAS data
            } else if advertised_local {
                score += 200;
            }
            if spec.min_gpu_vram_mb > 0 {
                let best_vram = n
                    .gpus
                    .iter()
                    .map(|g| g.free_vram_mb.saturating_sub(used.gpu_vram_mb))
                    .max()
                    .unwrap_or(0) as i64;
                score += best_vram / 128;
            }
            Some((n, score, verified_local))
        })
        .collect();

    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.node_id.cmp(&b.0.node_id)));
    let &(chosen, _, verified_local) = candidates
        .first()
        .ok_or_else(|| anyhow!("No eligible authorized mesh node satisfies workload '{}'", spec.workload_id))?;

    let next_fencing = group.max_fencing_epoch.get(resource_key).copied().unwrap_or(0) + 1;
    let proposal_hash = hash_proposal(resource_key, &chosen.node_id, &spec.workload_id, next_fencing);
    let vote_req = VoteRequest {
        group_id: group.group_id.clone(),
        epoch: group.membership_epoch,
        slot: group.next_slot,
        proposal_hash,
    };

    // Parallel 1-RTT fan-out to all online authorized voters!
    let mut join_set = tokio::task::JoinSet::new();
    for voter in online_voters {
        if group.members.contains_key(&voter.node_id) {
            let v = voter.clone();
            let req = vote_req.clone();
            join_set.spawn(async move { v.cast_vote(&req).await });
        }
    }
    let mut votes: Vec<SignedVote> = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(Ok(v)) = res {
            votes.push(v);
        }
    }

    let lease = group
        .commit_exclusive_lease(
            resource_key,
            &chosen.node_id,
            &spec.workload_id,
            ttl_ms,
            now,
            votes,
        )
        .await?;

    reservations.reserve(
        &spec.workload_id,
        chosen,
        NodeReservation {
            cpu_cores: spec.min_cpu_cores,
            ram_mb: spec.min_ram_mb,
            gpu_vram_mb: spec.min_gpu_vram_mb,
            wasm_slots: spec.required_wasm_slots,
        },
    )?;

    Ok(PlacementDecision {
        workload_id: spec.workload_id.clone(),
        selected_node_id: chosen.node_id.clone(),
        resource_key: resource_key.to_string(),
        verified_cas_local: verified_local,
        lease,
    })
}
