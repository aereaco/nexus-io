//! Nexus Soft-State Resource Fabric (Signed CRDT Gossip + Heterogeneous Compute/GPU/CAS Scheduler)
//!
//! - Nodes advertise CPU cores/arch, GPU vendor/model/VRAM/APIs, RAM/SharedArena capacity, and
//!   CAS storage capacity via Ed25519-signed `NodeAdvertisement`s.
//! - Advertisements replicate via a commutative, associative, idempotent LWW-Element-Set CRDT
//!   (`ResourceMeshCrdt`) — zero consensus latency for telemetry/discovery.
//! - Workload placement matches hardware + org trust constraints against CRDT state, then commits
//!   an exclusive quorum-fenced lease through `CoordinationGroup`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::mesh::consensus::{
    hash_proposal, sign_vote, CoordinationGroup, FencedLease, SignedVote,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub region: String,
    pub ed25519_pubkey: String,
    pub cpu_arch: String,
    pub cpu_cores: u32,
    pub available_cpu_cores: u32,
    pub ram_mb: u64,
    pub shared_arena_mb: u64,
    pub cas_storage_gb: u64,
    pub gpus: Vec<GpuCapability>,
    pub wasm_slots: u32,
    pub healthy: bool,
    pub lamport_ts: u64,
    pub signature: String,
}

impl NodeAdvertisement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let gpu_summary: String = self
            .gpus
            .iter()
            .map(|g| format!("{}:{}:{}:{}", g.vendor, g.model, g.vram_mb, g.free_vram_mb))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "NEXUS-NODE-ADV-v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.node_id,
            self.identity_id,
            self.org_id,
            self.region,
            self.cpu_arch,
            self.cpu_cores,
            self.available_cpu_cores,
            self.ram_mb,
            self.shared_arena_mb,
            self.cas_storage_gb,
            gpu_summary,
            self.healthy,
            self.lamport_ts,
        )
        .into_bytes()
    }

    pub fn sign(&mut self, sk_b64: &str) -> Result<()> {
        let bytes = self.canonical_bytes();
        self.signature = nexus_db::auth::ed25519_sign(sk_b64, &bytes)?;
        Ok(())
    }

    pub fn verify_signature(&self) -> bool {
        let bytes = self.canonical_bytes();
        nexus_db::auth::ed25519_verify(&self.ed25519_pubkey, &bytes, &self.signature)
    }
}

/// Commutative, associative, idempotent LWW-Element-Set CRDT for mesh resource discovery.
#[derive(Debug, Clone, Default)]
pub struct ResourceMeshCrdt {
    pub nodes: HashMap<String, NodeAdvertisement>,
}

impl ResourceMeshCrdt {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify signature and merge a `NodeAdvertisement` using LWW `(lamport_ts, node_id)` ordering.
    pub fn merge_advertisement(&mut self, adv: NodeAdvertisement) -> Result<bool> {
        if !adv.verify_signature() {
            anyhow::bail!("Rejected NodeAdvertisement with invalid Ed25519 signature from '{}'", adv.node_id);
        }
        if let Some(existing) = self.nodes.get(&adv.node_id) {
            if adv.lamport_ts <= existing.lamport_ts {
                return Ok(false);
            }
        }
        self.nodes.insert(adv.node_id.clone(), adv);
        Ok(true)
    }

    /// Gossip anti-entropy merge: commutative, associative, idempotent.
    pub fn merge_gossip(&mut self, other: &ResourceMeshCrdt) -> Result<usize> {
        let mut updated = 0usize;
        for adv in other.nodes.values() {
            if self.merge_advertisement(adv.clone())? {
                updated += 1;
            }
        }
        Ok(updated)
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
    pub preferred_region: Option<String>,
    pub input_cas_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementDecision {
    pub workload_id: String,
    pub selected_node_id: String,
    pub resource_key: String,
    pub lease: FencedLease,
}

/// Select the best healthy, authorized node from CRDT state and acquire an exclusive quorum-fenced
/// lease from the scoped `CoordinationGroup`.
pub fn schedule_and_lease_workload(
    crdt: &ResourceMeshCrdt,
    group: &mut CoordinationGroup,
    spec: &WorkloadSpec,
    resource_key: &str,
    ttl_ms: u64,
    now: u64,
    online_voter_keys: &[(String, String)],
) -> Result<PlacementDecision> {
    let mut candidates: Vec<(&NodeAdvertisement, i64)> = crdt
        .nodes
        .values()
        .filter(|n| {
            n.healthy
                && n.org_id == spec.required_org_id
                && n.available_cpu_cores >= spec.min_cpu_cores
                && n.ram_mb >= spec.min_ram_mb
                && (spec.min_gpu_vram_mb == 0
                    || n.gpus.iter().any(|g| {
                        g.free_vram_mb >= spec.min_gpu_vram_mb
                            && spec
                                .required_gpu_api
                                .as_deref()
                                .map(|api| g.apis.iter().any(|a| a.eq_ignore_ascii_case(api)))
                                .unwrap_or(true)
                    }))
        })
        .map(|n| {
            let mut score = (n.available_cpu_cores as i64) * 10 + (n.shared_arena_mb as i64 / 64);
            if let Some(ref pref) = spec.preferred_region {
                if &n.region == pref {
                    score += 500;
                }
            }
            if spec.min_gpu_vram_mb > 0 {
                let best_vram = n.gpus.iter().map(|g| g.free_vram_mb).max().unwrap_or(0) as i64;
                score += best_vram / 128;
            }
            (n, score)
        })
        .collect();

    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.node_id.cmp(&b.0.node_id)));
    let (chosen, _) = candidates
        .first()
        .ok_or_else(|| anyhow!("No eligible healthy mesh node satisfies workload '{}'", spec.workload_id))?;

    let next_fencing = group.max_fencing_epoch.get(resource_key).copied().unwrap_or(0) + 1;
    let proposal_hash = hash_proposal(resource_key, &chosen.node_id, &spec.workload_id, next_fencing);
    let slot = group.next_slot;
    let epoch = group.membership_epoch;
    let mut votes: Vec<SignedVote> = Vec::new();
    for (voter_id, voter_sk) in online_voter_keys {
        if group.members.contains_key(voter_id) {
            votes.push(sign_vote(&group.group_id, epoch, slot, &proposal_hash, voter_id, voter_sk)?);
        }
    }

    let lease = group.commit_exclusive_lease(
        resource_key,
        &chosen.node_id,
        &spec.workload_id,
        ttl_ms,
        now,
        votes,
    )?;

    Ok(PlacementDecision {
        workload_id: spec.workload_id.clone(),
        selected_node_id: chosen.node_id.clone(),
        resource_key: resource_key.to_string(),
        lease,
    })
}
