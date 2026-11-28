//! Nexus Scoped Hybrid Consensus Foundation (Durable Vote-Locks, Recovery & Resource Fencing)
//!
//! Maturity & Scope (Explicit):
//! - **`CftFastPath` (`2f + 1` quorum):** Durable per-voter vote-locks in `nexus-db` prevent honest
//!   voters from signing conflicting proposals for the same `(group_id, epoch, slot)` across
//!   concurrent requests and process restarts. Committed leases, membership epochs, and monotonic
//!   fencing tokens are persisted durably and enforced at the resource boundary (`FencedResourceGuard`).
//! - **`BftSigned` (`3f + 1` quorum):** Adds signed `3f + 1` quorum thresholds and cryptographic
//!   `EquivocationProof` detection. Full multi-round Byzantine view-change (HotStuff/Tendermint)
//!   remains a separate future milestone.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Database;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusMode {
    /// Model A: Crash-Fault Tolerant quorum (`quorum = n / 2 + 1`) backed by durable vote-locks.
    CftFastPath,
    /// Model B: Signed `3f + 1` quorum (`quorum = (2 * n) / 3 + 1`) + equivocation proof detection.
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

/// Authorized coordination group member binding node, identity, public key, and organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub node_id: String,
    pub identity_id: String,
    pub org_id: String,
    pub ed25519_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableVoterLock {
    lock_key: String,
    group_id: String,
    epoch: u64,
    slot: u64,
    proposal_hash: String,
    voter_node_id: String,
    signature: String,
    locked_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableMembershipRecord {
    group_id: String,
    mode: ConsensusMode,
    membership_epoch: u64,
    next_slot: u64,
    members: Vec<GroupMember>,
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

/// Low-level cryptographic vote signer (use `VoterNode::cast_vote` for durable vote-lock safety!).
pub fn sign_vote_raw(
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
    hasher.update(b"NEXUS-LEASE-PROPOSAL-v1");
    for field in [resource_key.as_bytes(), holder_node_id.as_bytes(), workload_id.as_bytes()] {
        hasher.update(&(field.len() as u32).to_be_bytes());
        hasher.update(field);
    }
    hasher.update(&fencing_epoch.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Independent durable voter node backed by its own `nexus-db` instance.
///
/// Safety invariant: `cast_vote` atomically persists a `sys_mesh_voter_lock` record via `CREATE`
/// (insert-if-absent) **before** returning a `SignedVote`. A conflicting `proposal_hash` for the
/// same `(group_id, epoch, slot)` is ALWAYS rejected — across concurrent requests and restarts!
#[derive(Clone)]
pub struct VoterNode {
    pub node_id: String,
    pub ed25519_sk_b64: String,
    db: Arc<Database>,
}

impl VoterNode {
    pub fn new(node_id: impl Into<String>, ed25519_sk_b64: impl Into<String>, db: Arc<Database>) -> Self {
        Self {
            node_id: node_id.into(),
            ed25519_sk_b64: ed25519_sk_b64.into(),
            db,
        }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let _ = self
            .db
            .client
            .query("DEFINE TABLE IF NOT EXISTS sys_mesh_voter_lock SCHEMALESS;")
            .await;
        Ok(())
    }

    /// Atomically acquire durable vote-lock BEFORE returning signature.
    /// - Same `(group_id, epoch, slot, proposal_hash)` -> idempotently returns the locked vote.
    /// - Different `proposal_hash` for same `(group_id, epoch, slot)` -> FAILS CLOSED!
    pub async fn cast_vote(&self, req: &VoteRequest) -> Result<SignedVote> {
        self.ensure_tables().await?;
        let lock_key = format!(
            "{}_{}_{}_{}",
            blake3::hash(req.group_id.as_bytes()).to_hex().as_str()[..12].to_string(),
            req.epoch,
            req.slot,
            self.node_id
        );
        let vote = sign_vote_raw(
            &req.group_id,
            req.epoch,
            req.slot,
            &req.proposal_hash,
            &self.node_id,
            &self.ed25519_sk_b64,
        )?;
        let lock_rec = DurableVoterLock {
            lock_key: lock_key.clone(),
            group_id: req.group_id.clone(),
            epoch: req.epoch,
            slot: req.slot,
            proposal_hash: req.proposal_hash.clone(),
            voter_node_id: self.node_id.clone(),
            signature: vote.signature.clone(),
            locked_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&lock_rec)?;

        // Atomic database CREATE (fails if record already exists — cross-process atomic!)
        let create_res = self
            .db
            .client
            .query("CREATE type::record('sys_mesh_voter_lock', $id) CONTENT $l;")
            .bind(("id", lock_key.clone()))
            .bind(("l", val))
            .await;

        let created_ok = match create_res {
            Ok(resp) => resp.check().is_ok(),
            Err(_) => false,
        };
        if created_ok {
            return Ok(vote);
        }

        // Lock already exists in DB — inspect existing durable lock
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_voter_lock', $id)")
            .bind(("id", lock_key))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let existing: DurableVoterLock = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Failed to acquire or read durable voter lock"))?;

        if existing.proposal_hash == req.proposal_hash {
            return Ok(SignedVote {
                group_id: existing.group_id,
                epoch: existing.epoch,
                slot: existing.slot,
                proposal_hash: existing.proposal_hash,
                voter_node_id: existing.voter_node_id,
                signature: existing.signature,
            });
        }

        anyhow::bail!(
            "Durable vote-lock conflict on node '{}' for ({}, epoch={}, slot={}): already locked on '{}', refusing '{}'",
            self.node_id,
            req.group_id,
            req.epoch,
            req.slot,
            existing.proposal_hash,
            req.proposal_hash
        )
    }
}

/// Resource-boundary fencing guard enforced directly at the protected resource (compute/storage node),
/// independent of coordinator reachability. Persists monotonic `highest_epoch` in `nexus-db`.
#[derive(Clone)]
pub struct FencedResourceGuard {
    db: Arc<Database>,
}

impl FencedResourceGuard {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let _ = self
            .db
            .client
            .query("DEFINE TABLE IF NOT EXISTS sys_mesh_resource_fence SCHEMALESS;")
            .await;
        Ok(())
    }

    /// Enforce monotonic fencing epoch at the actual protected resource boundary.
    /// Rejects any stale/partitioned caller presenting `fencing_epoch < highest_seen_epoch`
    /// or presenting a different holder for the same epoch!
    pub async fn accept_fenced_operation(
        &self,
        resource_key: &str,
        holder_node_id: &str,
        fencing_epoch: u64,
    ) -> Result<u64> {
        if fencing_epoch == 0 {
            anyhow::bail!("Fencing epoch must be >= 1");
        }
        self.ensure_tables().await?;
        let key = blake3::hash(resource_key.as_bytes()).to_hex().to_string();
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_resource_fence', $id)")
            .bind(("id", key.clone()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        if let Some(existing) = rows.first() {
            let cur_epoch = existing["highest_epoch"].as_u64().unwrap_or(0);
            let cur_holder = existing["holder_node_id"].as_str().unwrap_or("");
            if fencing_epoch < cur_epoch {
                anyhow::bail!(
                    "Resource boundary rejected stale fencing_epoch {} for '{}' (highest seen: {})",
                    fencing_epoch,
                    resource_key,
                    cur_epoch
                );
            }
            if fencing_epoch == cur_epoch && cur_holder != holder_node_id {
                anyhow::bail!(
                    "Resource boundary rejected conflicting holder '{}' at epoch {} (owned by '{}')",
                    holder_node_id,
                    fencing_epoch,
                    cur_holder
                );
            }
            if fencing_epoch == cur_epoch {
                return Ok(cur_epoch);
            }
        }
        let rec = serde_json::json!({
            "resource_key": resource_key,
            "holder_node_id": holder_node_id,
            "highest_epoch": fencing_epoch,
            "updated_at_ms": now_ms(),
        });
        self.db
            .client
            .query("UPSERT type::record('sys_mesh_resource_fence', $id) CONTENT $r;")
            .bind(("id", key))
            .bind(("r", rec))
            .await?
            .check()?;
        Ok(fencing_epoch)
    }
}

/// Independent partitioned coordination group with optional `nexus-db` durability & crash recovery.
#[derive(Clone)]
pub struct CoordinationGroup {
    pub group_id: String,
    pub mode: ConsensusMode,
    pub membership_epoch: u64,
    pub next_slot: u64,
    pub members: HashMap<String, GroupMember>,
    pub active_leases: HashMap<String, FencedLease>,
    pub max_fencing_epoch: HashMap<String, u64>,
    seen_votes: HashMap<(u64, u64, String), SignedVote>,
    pub equivocations: Vec<EquivocationProof>,
    db: Option<Arc<Database>>,
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
            db: None,
        }
    }

    /// Open or recover a durable `CoordinationGroup` backed by `nexus-db`.
    /// On restart, recovers committed `membership_epoch`, `next_slot`, `active_leases`, and
    /// monotonic `max_fencing_epoch` (discarding any uncommitted/incomplete proposals).
    pub async fn open_durable(
        db: Arc<Database>,
        group_id: impl Into<String>,
        mode: ConsensusMode,
        initial_members: Vec<GroupMember>,
    ) -> Result<Self> {
        let gid = group_id.into();
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_mesh_membership SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_mesh_decision_log SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_mesh_fencing_epoch SCHEMALESS;";
        let _ = db.client.query(ddl).await;

        let mut group = Self::new(gid.clone(), mode, initial_members);
        group.db = Some(db.clone());

        let gkey = blake3::hash(gid.as_bytes()).to_hex().to_string();
        let mut mresp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_membership', $id)")
            .bind(("id", gkey.clone()))
            .await?;
        let mrows: Vec<serde_json::Value> = mresp.take(0).unwrap_or_default();
        if let Some(rec) = mrows
            .first()
            .and_then(|v| serde_json::from_value::<DurableMembershipRecord>(v.clone()).ok())
        {
            group.mode = rec.mode;
            group.membership_epoch = rec.membership_epoch;
            group.next_slot = rec.next_slot;
            group.members = rec
                .members
                .into_iter()
                .map(|m| (m.node_id.clone(), m))
                .collect();
        } else {
            group.persist_membership().await?;
        }

        // Recover committed leases & monotonic fencing epochs
        let mut lresp = db.client.query("SELECT * FROM sys_mesh_decision_log").await?;
        let lrows: Vec<serde_json::Value> = lresp.take(0).unwrap_or_default();
        for v in lrows {
            if let Ok(lease) = serde_json::from_value::<FencedLease>(v) {
                if lease.group_id == gid {
                    let cur_max = group.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
                    if lease.fencing_epoch > cur_max {
                        group.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
                        group.active_leases.insert(lease.resource_key.clone(), lease.clone());
                    }
                    if lease.qc.slot >= group.next_slot {
                        group.next_slot = lease.qc.slot + 1;
                    }
                }
            }
        }
        Ok(group)
    }

    async fn persist_membership(&self) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch: self.membership_epoch,
            next_slot: self.next_slot,
            members: self.members.values().cloned().collect(),
        };
        let val = serde_json::to_value(&rec)?;
        db.client
            .query("UPSERT type::record('sys_mesh_membership', $id) CONTENT $m;")
            .bind(("id", gkey))
            .bind(("m", val))
            .await?
            .check()?;
        Ok(())
    }

    async fn persist_committed_lease(&self, lease: &FencedLease) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let val = serde_json::to_value(lease)?;
        db.client
            .query("UPSERT type::record('sys_mesh_decision_log', $id) CONTENT $l;")
            .bind(("id", lease.lease_id.clone()))
            .bind(("l", val))
            .await?
            .check()?;
        self.persist_membership().await?;
        Ok(())
    }

    pub fn quorum_size(&self) -> usize {
        self.mode.quorum_size(self.members.len())
    }

    /// Safe quorum-gated membership reconfiguration: requires a valid quorum of CURRENT members
    /// signing the new membership epoch transition before advancing `membership_epoch`!
    pub async fn reconfigure_membership_with_quorum(
        &mut self,
        new_members: Vec<GroupMember>,
        votes: Vec<SignedVote>,
    ) -> Result<u64> {
        let next_epoch = self.membership_epoch + 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NEXUS-MEMBERSHIP-CHANGE-v1|");
        hasher.update(self.group_id.as_bytes());
        hasher.update(&next_epoch.to_be_bytes());
        let mut sorted_ids: Vec<&str> = new_members.iter().map(|m| m.node_id.as_str()).collect();
        sorted_ids.sort_unstable();
        for nid in sorted_ids {
            hasher.update(nid.as_bytes());
            hasher.update(b"|");
        }
        let expected_hash = hasher.finalize().to_hex().to_string();
        let slot = self.next_slot;

        let mut valid_votes = Vec::new();
        let mut unique = HashSet::new();
        for v in votes {
            if v.slot == slot && v.proposal_hash == expected_hash {
                if let Some(eq) = self.record_and_verify_vote(&v)? {
                    anyhow::bail!("Equivocation during membership change from '{}'", eq.voter_node_id);
                }
                if unique.insert(v.voter_node_id.clone()) {
                    valid_votes.push(v);
                }
            }
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

        self.membership_epoch = next_epoch;
        self.next_slot += 1;
        self.members = new_members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        self.persist_membership().await?;
        Ok(self.membership_epoch)
    }

    /// Verify a `SignedVote` against the group's membership and detect equivocation.
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

    /// Verify a `QuorumCertificate` against current `group_id`, `membership_epoch`, `mode`,
    /// member public keys, and quorum size.
    pub fn verify_qc(&self, qc: &QuorumCertificate) -> Result<()> {
        if qc.group_id != self.group_id || qc.mode != self.mode || qc.epoch != self.membership_epoch {
            anyhow::bail!(
                "QC mismatch: expected (group={}, epoch={}, mode={:?}), got (group={}, epoch={}, mode={:?})",
                self.group_id,
                self.membership_epoch,
                self.mode,
                qc.group_id,
                qc.epoch,
                qc.mode
            );
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

    /// Commit an exclusive, quorum-fenced resource lease (persisting durably before returning if
    /// opened via `open_durable`).
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_exclusive_lease(
        &mut self,
        resource_key: &str,
        holder_node_id: &str,
        workload_id: &str,
        ttl_ms: u64,
        now: u64,
        votes: Vec<SignedVote>,
    ) -> Result<FencedLease> {
        if !self.members.contains_key(holder_node_id) {
            anyhow::bail!("Holder '{}' is not an authorized member of group '{}'", holder_node_id, self.group_id);
        }
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
                    "Equivocation detected from '{}' at slot {}",
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
        // Persist-before-publish: durable write succeeds before updating in-memory active_leases
        self.next_slot += 1;
        if let Err(e) = self.persist_committed_lease(&lease).await {
            self.next_slot -= 1;
            return Err(e);
        }
        self.max_fencing_epoch.insert(resource_key.to_string(), next_fencing);
        self.active_leases.insert(resource_key.to_string(), lease.clone());
        Ok(lease)
    }

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

    pub fn now_ms() -> u64 {
        now_ms()
    }
}
