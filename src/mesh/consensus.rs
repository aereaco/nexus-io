//! Nexus Scoped Hybrid Consensus Protocol
//!
//! Design Properties:
//! - **Partitioned Coordination Groups:** Independent consensus groups per org, storage namespace,
//!   or compute pool (zero global bottleneck).
//! - **Model A Default (`CftFastPath`, `2f + 1`):** Authenticated crash-fault tolerance with
//!   leaderless 1-RTT fast path when uncontended.
//! - **Model B Opt-In (`BftSigned`, `3f + 1`):** Byzantine fault tolerance per group with
//!   cryptographic `EquivocationProof` detection — zero BFT overhead on private/federated groups.
//! - **Monotonic Fencing Epochs:** Every exclusive resource lease carries a strictly increasing
//!   `fencing_epoch` + Ed25519 `QuorumCertificate`, ensuring a partitioned/reconnected node can
//!   NEVER act on stale authority.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusMode {
    /// Model A: Trusted/Federated Crash-Fault Tolerance (`quorum = n / 2 + 1`).
    CftFastPath,
    /// Model B: Open/Untrusted Byzantine-Fault Tolerance (`quorum = (2 * n) / 3 + 1`).
    BftSigned,
}

impl ConsensusMode {
    pub fn quorum_size(self, total_members: usize) -> usize {
        if total_members == 0 {
            return 1;
        }
        match self {
            Self::CftFastPath => (total_members / 2) + 1,
            Self::BftSigned => ((2 * total_members) / 3) + 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub node_id: String,
    pub identity_id: String,
    pub ed25519_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVote {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
    pub voter_node_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
    pub mode: ConsensusMode,
    pub votes: Vec<SignedVote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub voter_node_id: String,
    pub vote_a: SignedVote,
    pub vote_b: SignedVote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FencedLease {
    pub lease_id: String,
    pub group_id: String,
    pub resource_key: String,
    pub holder_node_id: String,
    pub workload_id: String,
    pub fencing_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub qc: QuorumCertificate,
}

/// Canonical length-prefixed vote payload to eliminate framing ambiguity.
pub fn canonical_vote_payload(
    group_id: &str,
    epoch: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"NEXUS-CONSENSUS-VOTE-v1");
    for field in [group_id.as_bytes(), proposal_hash.as_bytes(), voter_node_id.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&slot.to_be_bytes());
    out
}

pub fn sign_vote(
    group_id: &str,
    epoch: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
    voter_sk_b64: &str,
) -> Result<SignedVote> {
    let payload = canonical_vote_payload(group_id, epoch, slot, proposal_hash, voter_node_id);
    let sig = nexus_db::auth::ed25519_sign(voter_sk_b64, &payload)?;
    Ok(SignedVote {
        group_id: group_id.to_string(),
        epoch,
        slot,
        proposal_hash: proposal_hash.to_string(),
        voter_node_id: voter_node_id.to_string(),
        signature: sig,
    })
}

pub fn hash_proposal(resource_key: &str, holder_node_id: &str, workload_id: &str, fencing_epoch: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NEXUS-LEASE-PROPOSAL-v1|");
    hasher.update(resource_key.as_bytes());
    hasher.update(b"|");
    hasher.update(holder_node_id.as_bytes());
    hasher.update(b"|");
    hasher.update(workload_id.as_bytes());
    hasher.update(&fencing_epoch.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Independent partitioned coordination group (one per org, storage namespace, or compute pool).
#[derive(Debug, Clone)]
pub struct CoordinationGroup {
    pub group_id: String,
    pub mode: ConsensusMode,
    pub membership_epoch: u64,
    pub next_slot: u64,
    pub members: HashMap<String, GroupMember>,
    /// Active exclusive resource leases keyed by `resource_key`.
    pub active_leases: HashMap<String, FencedLease>,
    /// Highest committed fencing epoch per `resource_key` (monotonic even after expiry/release!).
    pub max_fencing_epoch: HashMap<String, u64>,
    /// Observed votes keyed by `(epoch, slot, voter_node_id)` for Byzantine equivocation detection.
    seen_votes: HashMap<(u64, u64, String), SignedVote>,
    pub equivocations: Vec<EquivocationProof>,
}

impl CoordinationGroup {
    pub fn new(group_id: impl Into<String>, mode: ConsensusMode, members: Vec<GroupMember>) -> Self {
        let map = members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        Self {
            group_id: group_id.into(),
            mode,
            membership_epoch: 1,
            next_slot: 1,
            members: map,
            active_leases: HashMap::new(),
            max_fencing_epoch: HashMap::new(),
            seen_votes: HashMap::new(),
            equivocations: Vec::new(),
        }
    }

    pub fn quorum_size(&self) -> usize {
        self.mode.quorum_size(self.members.len())
    }

    /// Reconfigure group membership, advancing `membership_epoch` monotonically.
    pub fn reconfigure_membership(&mut self, new_members: Vec<GroupMember>) {
        self.membership_epoch += 1;
        self.members = new_members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
    }

    /// Verify a `SignedVote` against the group's membership and detect Byzantine equivocation.
    pub fn record_and_verify_vote(&mut self, vote: &SignedVote) -> Result<Option<EquivocationProof>> {
        if vote.group_id != self.group_id || vote.epoch != self.membership_epoch {
            anyhow::bail!(
                "Vote group/epoch mismatch: expected ({}, {}), got ({}, {})",
                self.group_id,
                self.membership_epoch,
                vote.group_id,
                vote.epoch
            );
        }
        let member = self
            .members
            .get(&vote.voter_node_id)
            .ok_or_else(|| anyhow!("Unknown voter node '{}'", vote.voter_node_id))?;
        let payload = canonical_vote_payload(
            &vote.group_id,
            vote.epoch,
            vote.slot,
            &vote.proposal_hash,
            &vote.voter_node_id,
        );
        if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &vote.signature) {
            anyhow::bail!("Invalid Ed25519 vote signature from node '{}'", vote.voter_node_id);
        }

        let key = (vote.epoch, vote.slot, vote.voter_node_id.clone());
        if let Some(prev) = self.seen_votes.get(&key) {
            if prev.proposal_hash != vote.proposal_hash {
                let proof = EquivocationProof {
                    group_id: self.group_id.clone(),
                    epoch: vote.epoch,
                    slot: vote.slot,
                    voter_node_id: vote.voter_node_id.clone(),
                    vote_a: prev.clone(),
                    vote_b: vote.clone(),
                };
                self.equivocations.push(proof.clone());
                return Ok(Some(proof));
            }
        } else {
            self.seen_votes.insert(key, vote.clone());
        }
        Ok(None)
    }

    /// Verify a `QuorumCertificate` independently against the group's member public keys and quorum rule.
    pub fn verify_qc(&self, qc: &QuorumCertificate) -> Result<()> {
        if qc.group_id != self.group_id || qc.mode != self.mode {
            anyhow::bail!("QC group or mode mismatch");
        }
        let mut unique_voters = HashSet::new();
        for v in &qc.votes {
            if v.group_id != qc.group_id || v.epoch != qc.epoch || v.slot != qc.slot || v.proposal_hash != qc.proposal_hash {
                anyhow::bail!("QC contains mismatched vote");
            }
            let member = self
                .members
                .get(&v.voter_node_id)
                .ok_or_else(|| anyhow!("QC voter '{}' not in group", v.voter_node_id))?;
            let payload = canonical_vote_payload(&v.group_id, v.epoch, v.slot, &v.proposal_hash, &v.voter_node_id);
            if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &v.signature) {
                anyhow::bail!("QC contains invalid signature from '{}'", v.voter_node_id);
            }
            unique_voters.insert(v.voter_node_id.clone());
        }
        let required = self.quorum_size();
        if unique_voters.len() < required {
            anyhow::bail!(
                "Insufficient quorum for {:?}: got {} valid votes, need {}",
                self.mode,
                unique_voters.len(),
                required
            );
        }
        Ok(())
    }

    /// Acquire an exclusive, quorum-fenced resource lease at timestamp `now`.
    /// Safety invariant: NEVER grants an overlapping lease while a non-expired lease is held by
    /// another node, and ALWAYS mints a strictly higher monotonic `fencing_epoch`.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_exclusive_lease(
        &mut self,
        resource_key: &str,
        holder_node_id: &str,
        workload_id: &str,
        ttl_ms: u64,
        now: u64,
        votes: Vec<SignedVote>,
    ) -> Result<FencedLease> {
        if let Some(existing) = self.active_leases.get(resource_key) {
            if existing.expires_at_ms > now && existing.holder_node_id != holder_node_id {
                anyhow::bail!(
                    "Resource '{}' is exclusively leased by '{}' (fencing_epoch={}) until {}",
                    resource_key,
                    existing.holder_node_id,
                    existing.fencing_epoch,
                    existing.expires_at_ms
                );
            }
        }

        let next_fencing = self.max_fencing_epoch.get(resource_key).copied().unwrap_or(0) + 1;
        let slot = self.next_slot;
        let expected_hash = hash_proposal(resource_key, holder_node_id, workload_id, next_fencing);

        let mut valid_votes = Vec::new();
        let mut unique_voters = HashSet::new();
        for v in votes {
            if v.slot != slot || v.proposal_hash != expected_hash {
                continue;
            }
            if let Some(equiv) = self.record_and_verify_vote(&v)? {
                anyhow::bail!(
                    "Byzantine equivocation detected from '{}' at slot {}",
                    equiv.voter_node_id,
                    equiv.slot
                );
            }
            if unique_voters.insert(v.voter_node_id.clone()) {
                valid_votes.push(v);
            }
        }

        let required = self.quorum_size();
        if valid_votes.len() < required {
            anyhow::bail!(
                "Quorum not reached for '{}' ({:?}): got {} valid votes, need {}",
                resource_key,
                self.mode,
                valid_votes.len(),
                required
            );
        }

        let qc = QuorumCertificate {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            slot,
            proposal_hash: expected_hash,
            mode: self.mode,
            votes: valid_votes,
        };
        self.verify_qc(&qc)?;

        self.next_slot += 1;
        self.max_fencing_epoch.insert(resource_key.to_string(), next_fencing);
        let lease = FencedLease {
            lease_id: format!("lse_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
            group_id: self.group_id.clone(),
            resource_key: resource_key.to_string(),
            holder_node_id: holder_node_id.to_string(),
            workload_id: workload_id.to_string(),
            fencing_epoch: next_fencing,
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(ttl_ms),
            qc,
        };
        self.active_leases.insert(resource_key.to_string(), lease.clone());
        Ok(lease)
    }

    /// Strict fencing-token guard: rejects any partitioned/stale node attempting to write or
    /// execute with an outdated `fencing_epoch` or expired lease!
    pub fn verify_fencing_token(
        &self,
        resource_key: &str,
        holder_node_id: &str,
        fencing_epoch: u64,
        now: u64,
    ) -> Result<()> {
        let highest = self.max_fencing_epoch.get(resource_key).copied().unwrap_or(0);
        if fencing_epoch < highest || fencing_epoch == 0 {
            anyhow::bail!(
                "Stale fencing token rejected for '{}': presented epoch {}, current highest is {}",
                resource_key,
                fencing_epoch,
                highest
            );
        }
        let Some(active) = self.active_leases.get(resource_key) else {
            anyhow::bail!("No active lease for resource '{}'", resource_key);
        };
        if active.holder_node_id != holder_node_id || active.fencing_epoch != fencing_epoch {
            anyhow::bail!(
                "Lease holder/epoch mismatch for '{}': active is ({}, {}), presented ({}, {})",
                resource_key,
                active.holder_node_id,
                active.fencing_epoch,
                holder_node_id,
                fencing_epoch
            );
        }
        if now >= active.expires_at_ms {
            anyhow::bail!("Lease '{}' for '{}' has expired", active.lease_id, resource_key);
        }
        Ok(())
    }

    pub fn expire_lease_for_fault(&mut self, resource_key: &str, now: u64) {
        if let Some(l) = self.active_leases.get_mut(resource_key) {
            l.expires_at_ms = now.saturating_sub(1);
        }
    }

    /// Convenience helper returning current wall-clock ms.
    pub fn now_ms() -> u64 {
        now_ms()
    }
}
