//! Nexus Scoped Hybrid Consensus Foundation (Durable Vote-Locks, Recovery & Authenticated Resource Fencing)
//!
//! Maturity & Scope (Explicit):
//! - **`CftFastPath` (`2f + 1` quorum — `experimental`):** Durable per-voter vote-locks in `nexus-db`
//!   prevent honest voters from signing conflicting proposals for the same `(group_id, epoch, slot)`
//!   across concurrent requests and process restarts. Includes `query_slot_lock` for coordinator
//!   crash recovery, complete canonical membership-transition digests, and `FencedResourceGuard`
//!   with two-phase authenticated lease installation + O(1) local hot-path execution checks.
//! - **`BftSigned` (`3f + 1` quorum — `prototype`):** Adds signed `3f + 1` quorum thresholds and
//!   cryptographic `EquivocationProof` detection. Full multi-round Byzantine view-change
//!   (HotStuff/Tendermint) remains a separate future milestone.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Database;

const FENCE_STRIPE_COUNT: usize = 64;

fn fence_stripe_idx(key: &str) -> usize {
    let h = blake3::hash(key.as_bytes());
    let b = h.as_bytes();
    (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) % FENCE_STRIPE_COUNT
}

static FENCE_STRIPES: Lazy<Vec<tokio::sync::Mutex<()>>> =
    Lazy::new(|| (0..FENCE_STRIPE_COUNT).map(|_| tokio::sync::Mutex::new(())).collect());

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

    pub fn canonical_tag(self) -> &'static str {
        match self {
            Self::CftFastPath => "cft_fast_path",
            Self::BftSigned => "bft_signed",
        }
    }
}

/// Authorized coordination group member binding node, identity, organization, and public key.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcceptedFenceRecord {
    resource_key: String,
    holder_node_id: String,
    highest_epoch: u64,
    expires_at_ms: u64,
    lease_id: String,
    lease_digest: String,
    updated_at_ms: u64,
}

fn push_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
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

/// Single canonical length-prefixed lease digest covering EVERY authority & validity field:
/// `group_id`, `lease_id`, `resource_key`, `holder_node_id`, `workload_id`, `fencing_epoch`,
/// `issued_at_ms`, and `expires_at_ms`. Altering even 1ms of `expires_at_ms` invalidates the QC!
#[allow(clippy::too_many_arguments)]
pub fn hash_lease_proposal(
    group_id: &str,
    lease_id: &str,
    resource_key: &str,
    holder_node_id: &str,
    workload_id: &str,
    fencing_epoch: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NEXUS-LEASE-PROPOSAL-v2");
    for field in [
        group_id.as_bytes(),
        lease_id.as_bytes(),
        resource_key.as_bytes(),
        holder_node_id.as_bytes(),
        workload_id.as_bytes(),
    ] {
        push_len_prefixed(&mut hasher, field);
    }
    hasher.update(&fencing_epoch.to_be_bytes());
    hasher.update(&issued_at_ms.to_be_bytes());
    hasher.update(&expires_at_ms.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

impl FencedLease {
    pub fn canonical_digest(&self) -> String {
        hash_lease_proposal(
            &self.group_id,
            &self.lease_id,
            &self.resource_key,
            &self.holder_node_id,
            &self.workload_id,
            self.fencing_epoch,
            self.issued_at_ms,
            self.expires_at_ms,
        )
    }
}

/// Complete canonical digest of a membership transition covering `group_id`, `next_epoch`, `mode`,
/// and every member's `(node_id, identity_id, org_id, ed25519_pubkey)` sorted by `node_id`.
/// Rejects duplicate `node_id`s to prevent membership spoofing.
pub fn hash_membership_change(
    group_id: &str,
    next_epoch: u64,
    mode: ConsensusMode,
    new_members: &[GroupMember],
) -> Result<String> {
    let mut sorted = new_members.to_vec();
    sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let mut seen = HashSet::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NEXUS-MEMBERSHIP-CHANGE-v2");
    push_len_prefixed(&mut hasher, group_id.as_bytes());
    hasher.update(&next_epoch.to_be_bytes());
    push_len_prefixed(&mut hasher, mode.canonical_tag().as_bytes());
    hasher.update(&(sorted.len() as u32).to_be_bytes());
    for m in &sorted {
        if !seen.insert(m.node_id.as_str()) {
            anyhow::bail!("Duplicate node_id '{}' in membership transition", m.node_id);
        }
        push_len_prefixed(&mut hasher, m.node_id.as_bytes());
        push_len_prefixed(&mut hasher, m.identity_id.as_bytes());
        push_len_prefixed(&mut hasher, m.org_id.as_bytes());
        push_len_prefixed(&mut hasher, m.ed25519_pubkey.as_bytes());
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Independent durable voter node backed by its own `nexus-db` instance.
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

    fn slot_lock_key(&self, group_id: &str, epoch: u64, slot: u64) -> String {
        format!(
            "{}_{}_{}_{}",
            &blake3::hash(group_id.as_bytes()).to_hex().as_str()[..12],
            epoch,
            slot,
            self.node_id
        )
    }

    /// Query this voter's durable lock for `(group_id, epoch, slot)` to support coordinator crash recovery!
    pub async fn query_slot_lock(&self, group_id: &str, epoch: u64, slot: u64) -> Result<Option<SignedVote>> {
        self.ensure_tables().await?;
        let lock_key = self.slot_lock_key(group_id, epoch, slot);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_voter_lock', $id)")
            .bind(("id", lock_key))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<DurableVoterLock>(v.clone()).ok())
            .map(|existing| SignedVote {
                group_id: existing.group_id,
                epoch: existing.epoch,
                slot: existing.slot,
                proposal_hash: existing.proposal_hash,
                voter_node_id: existing.voter_node_id,
                signature: existing.signature,
            }))
    }

    /// Atomically acquire durable vote-lock (`CREATE` insert-if-absent) BEFORE returning signature.
    pub async fn cast_vote(&self, req: &VoteRequest) -> Result<SignedVote> {
        self.ensure_tables().await?;
        let lock_key = self.slot_lock_key(&req.group_id, req.epoch, req.slot);
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

        let existing = self
            .query_slot_lock(&req.group_id, req.epoch, req.slot)
            .await?
            .ok_or_else(|| anyhow!("Failed to acquire or read durable voter lock"))?;

        if existing.proposal_hash == req.proposal_hash {
            return Ok(existing);
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

/// Authenticated resource-boundary fencing guard enforced directly at the protected resource.
///
/// Two-phase design:
/// 1. **`install_lease(lease, group, now)`**: Cryptographically verifies the full `QuorumCertificate`,
///    proposal hash binding, and expiry, then atomically advances the durable monotonic fence in
///    `nexus-db` (never regressing under concurrent out-of-order arrivals).
/// 2. **`authorize_local_exec(resource_key, holder_node_id, fencing_epoch, now)`**: O(1) cheap local
///    hot-path check against accepted ownership state (zero Ed25519 verification or DB I/O per op).
#[derive(Clone)]
pub struct FencedResourceGuard {
    db: Arc<Database>,
    local_accepted: Arc<RwLock<HashMap<String, AcceptedFenceRecord>>>,
}

impl FencedResourceGuard {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            local_accepted: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let _ = self
            .db
            .client
            .query("DEFINE TABLE IF NOT EXISTS sys_mesh_resource_fence SCHEMALESS;")
            .await;
        Ok(())
    }

    /// Authenticate a `FencedLease` (complete canonical lease digest + QC + group binding +
    /// validity interval + max TTL) and atomically install its monotonic `fencing_epoch` at the
    /// resource boundary.
    ///
    /// Strictly idempotent CAS rules:
    /// - Higher epoch: accept after full QC verification.
    /// - Same epoch + exact same `(lease_id, lease_digest)`: idempotent success.
    /// - Same epoch + different lease/workload/expiry: REJECT.
    /// - Lower epoch: REJECT.
    pub async fn install_lease(
        &self,
        lease: &FencedLease,
        group: &CoordinationGroup,
        now: u64,
    ) -> Result<u64> {
        if lease.group_id != group.group_id {
            anyhow::bail!(
                "Lease group_id '{}' does not match authorized group '{}'",
                lease.group_id,
                group.group_id
            );
        }
        if lease.fencing_epoch == 0 {
            anyhow::bail!("Fencing epoch must be >= 1");
        }
        if lease.expires_at_ms <= lease.issued_at_ms {
            anyhow::bail!("Lease '{}' has invalid validity interval (expires_at_ms <= issued_at_ms)", lease.lease_id);
        }
        if lease.expires_at_ms - lease.issued_at_ms > group.max_lease_ttl_ms {
            anyhow::bail!(
                "Lease '{}' duration ({}ms) exceeds group max_lease_ttl_ms ({}ms)",
                lease.lease_id,
                lease.expires_at_ms - lease.issued_at_ms,
                group.max_lease_ttl_ms
            );
        }
        if now >= lease.expires_at_ms {
            anyhow::bail!("Cannot install expired lease '{}' at resource boundary", lease.lease_id);
        }
        // 1. Cryptographically authenticate the complete lease directly at the resource boundary!
        group.verify_qc(&lease.qc)?;
        let expected_digest = lease.canonical_digest();
        if lease.qc.proposal_hash != expected_digest {
            anyhow::bail!("Lease QC proposal_hash does not match complete canonical lease digest (tampering detected)");
        }

        // 2. Database-enforced strictly idempotent monotonic CAS
        let _guard = FENCE_STRIPES[fence_stripe_idx(&lease.resource_key)].lock().await;
        self.ensure_tables().await?;
        let key = blake3::hash(lease.resource_key.as_bytes()).to_hex().to_string();

        let rec = AcceptedFenceRecord {
            resource_key: lease.resource_key.clone(),
            holder_node_id: lease.holder_node_id.clone(),
            highest_epoch: lease.fencing_epoch,
            expires_at_ms: lease.expires_at_ms,
            lease_id: lease.lease_id.clone(),
            lease_digest: expected_digest.clone(),
            updated_at_ms: now,
        };
        let rec_val = serde_json::to_value(&rec)?;

        let create_res = self
            .db
            .client
            .query("CREATE type::record('sys_mesh_resource_fence', $id) CONTENT $r;")
            .bind(("id", key.clone()))
            .bind(("r", rec_val))
            .await;
        let created = match create_res {
            Ok(resp) => resp.check().is_ok(),
            Err(_) => false,
        };
        if !created {
            let mut upd = self
                .db
                .client
                .query(
                    "UPDATE type::record('sys_mesh_resource_fence', $id) \
                     SET holder_node_id = $holder, highest_epoch = $ep, expires_at_ms = $exp, lease_id = $lid, lease_digest = $dig, updated_at_ms = $now \
                     WHERE highest_epoch < $ep OR (highest_epoch == $ep AND lease_id == $lid AND lease_digest == $dig);",
                )
                .bind(("id", key))
                .bind(("holder", lease.holder_node_id.clone()))
                .bind(("ep", lease.fencing_epoch))
                .bind(("exp", lease.expires_at_ms))
                .bind(("lid", lease.lease_id.clone()))
                .bind(("dig", expected_digest))
                .bind(("now", now))
                .await?;
            let updated_rows: Vec<serde_json::Value> = upd.take(0).unwrap_or_default();
            if updated_rows.is_empty() {
                anyhow::bail!(
                    "Resource boundary rejected stale or conflicting lease '{}' (epoch={}) for '{}'",
                    lease.lease_id,
                    lease.fencing_epoch,
                    lease.resource_key
                );
            }
        }

        // 3. Publish to cheap local hot-path cache ONLY after durable DB operation succeeds
        if let Ok(mut map) = self.local_accepted.write() {
            map.insert(lease.resource_key.clone(), rec);
        }
        Ok(lease.fencing_epoch)
    }

    /// Cheap O(1) local hot-path execution check (zero signature verification or DB reads on cache hit).
    pub async fn authorize_local_exec(
        &self,
        resource_key: &str,
        holder_node_id: &str,
        fencing_epoch: u64,
        now: u64,
    ) -> Result<u64> {
        if let Ok(map) = self.local_accepted.read() {
            if let Some(rec) = map.get(resource_key) {
                if fencing_epoch < rec.highest_epoch {
                    anyhow::bail!(
                        "Stale fencing_epoch {} rejected on hot path (highest accepted: {})",
                        fencing_epoch,
                        rec.highest_epoch
                    );
                }
                if fencing_epoch != rec.highest_epoch || rec.holder_node_id != holder_node_id {
                    anyhow::bail!(
                        "Unauthorized holder '{}' / epoch {} (installed: '{}' @ {})",
                        holder_node_id,
                        fencing_epoch,
                        rec.holder_node_id,
                        rec.highest_epoch
                    );
                }
                if now >= rec.expires_at_ms {
                    anyhow::bail!("Installed lease '{}' has expired", rec.lease_id);
                }
                return Ok(rec.highest_epoch);
            }
        }
        // Cold miss (e.g., after process restart): hydrate from durable DB record
        self.ensure_tables().await?;
        let key = blake3::hash(resource_key.as_bytes()).to_hex().to_string();
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_resource_fence', $id)")
            .bind(("id", key))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let rec: AcceptedFenceRecord = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("No authenticated lease installed for '{}'", resource_key))?;
        if let Ok(mut map) = self.local_accepted.write() {
            map.insert(resource_key.to_string(), rec.clone());
        }
        if fencing_epoch != rec.highest_epoch || rec.holder_node_id != holder_node_id || now >= rec.expires_at_ms {
            anyhow::bail!(
                "Resource boundary rejected execution by '{}' at epoch {} (installed: '{}' @ {})",
                holder_node_id,
                fencing_epoch,
                rec.holder_node_id,
                rec.highest_epoch
            );
        }
        Ok(rec.highest_epoch)
    }
}

/// Independent partitioned coordination group with optional `nexus-db` durability & crash recovery.
#[derive(Clone)]
pub struct CoordinationGroup {
    pub group_id: String,
    pub mode: ConsensusMode,
    pub membership_epoch: u64,
    pub next_slot: u64,
    pub max_lease_ttl_ms: u64,
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
            max_lease_ttl_ms: 300_000,
            members: map,
            active_leases: HashMap::new(),
            max_fencing_epoch: HashMap::new(),
            seen_votes: HashMap::new(),
            equivocations: Vec::new(),
            db: None,
        }
    }

    pub async fn open_durable(
        db: Arc<Database>,
        group_id: impl Into<String>,
        mode: ConsensusMode,
        initial_members: Vec<GroupMember>,
    ) -> Result<Self> {
        let gid = group_id.into();
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_mesh_membership SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_mesh_decision_log SCHEMALESS;";
        let _ = db.client.query(ddl).await;

        let mut group = Self::new(gid.clone(), mode, initial_members);
        group.db = Some(db.clone());

        let gkey = blake3::hash(gid.as_bytes()).to_hex().to_string();
        let mut mresp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_membership', $id)")
            .bind(("id", gkey))
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
            group.persist_membership_record(group.membership_epoch, group.next_slot, &group.members.values().cloned().collect::<Vec<_>>()).await?;
        }

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

    async fn persist_membership_record(
        &self,
        membership_epoch: u64,
        next_slot: u64,
        members: &[GroupMember],
    ) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch,
            next_slot,
            members: members.to_vec(),
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

    async fn persist_committed_lease(&self, lease: &FencedLease, new_next_slot: u64) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let val = serde_json::to_value(lease)?;
        db.client
            .query("UPSERT type::record('sys_mesh_decision_log', $id) CONTENT $l;")
            .bind(("id", lease.lease_id.clone()))
            .bind(("l", val))
            .await?
            .check()?;
        let mems: Vec<GroupMember> = self.members.values().cloned().collect();
        self.persist_membership_record(self.membership_epoch, new_next_slot, &mems)
            .await?;
        Ok(())
    }

    pub fn quorum_size(&self) -> usize {
        self.mode.quorum_size(self.members.len())
    }

    /// Safe coordinator crash recovery for `slot`:
    /// 1. Checks if a committed decision already exists in `active_leases` for `slot` (if so,
    ///    verifies no conflicting quorum exists in `locked_votes` and returns the committed QC).
    /// 2. Otherwise checks all durable voter locks for `(group_id, membership_epoch, slot)` and
    ///    verifies at most ONE proposal achieved quorum (failing closed if conflicting quorums exist).
    pub fn recover_safe_slot_decision(&self, slot: u64, locked_votes: Vec<SignedVote>) -> Result<Option<QuorumCertificate>> {
        let existing_committed = self
            .active_leases
            .values()
            .find(|l| l.qc.slot == slot && l.qc.epoch == self.membership_epoch);

        let mut by_hash: HashMap<String, Vec<SignedVote>> = HashMap::new();
        for v in locked_votes {
            if v.group_id == self.group_id && v.epoch == self.membership_epoch && v.slot == slot {
                by_hash.entry(v.proposal_hash.clone()).or_default().push(v);
            }
        }

        let mut valid_qcs = Vec::new();
        for (proposal_hash, votes) in by_hash {
            let qc = QuorumCertificate {
                group_id: self.group_id.clone(),
                epoch: self.membership_epoch,
                slot,
                proposal_hash,
                mode: self.mode,
                votes,
            };
            if self.verify_qc(&qc).is_ok() {
                valid_qcs.push(qc);
            }
        }
        if valid_qcs.len() > 1 {
            anyhow::bail!("CRITICAL: Conflicting quorum certificates detected during slot {} recovery!", slot);
        }
        if let Some(committed) = existing_committed {
            if let Some(ref recovered) = valid_qcs.first() {
                if recovered.proposal_hash != committed.qc.proposal_hash {
                    anyhow::bail!("CRITICAL: Recovered voter quorum conflicts with already-persisted lease for slot {}!", slot);
                }
            }
            return Ok(Some(committed.qc.clone()));
        }
        Ok(valid_qcs.into_iter().next())
    }

    /// Safe quorum-gated membership reconfiguration:
    /// 1. Hashes the COMPLETE canonical new membership record (node_id, identity_id, org_id, pubkey).
    /// 2. Rejects duplicate `node_id`s.
    /// 3. Verifies current-epoch quorum certificate.
    /// 4. Persists durable membership record BEFORE mutating in-memory state!
    pub async fn reconfigure_membership_with_quorum(
        &mut self,
        new_members: Vec<GroupMember>,
        votes: Vec<SignedVote>,
    ) -> Result<u64> {
        let next_epoch = self.membership_epoch + 1;
        let expected_hash = hash_membership_change(&self.group_id, next_epoch, self.mode, &new_members)?;
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

        // Persist-before-mutate!
        let new_next_slot = self.next_slot + 1;
        self.persist_membership_record(next_epoch, new_next_slot, &new_members)
            .await?;

        self.membership_epoch = next_epoch;
        self.next_slot = new_next_slot;
        self.members = new_members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        Ok(self.membership_epoch)
    }

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

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_exclusive_lease(
        &mut self,
        lease_id: &str,
        resource_key: &str,
        holder_node_id: &str,
        workload_id: &str,
        issued_at_ms: u64,
        expires_at_ms: u64,
        now: u64,
        votes: Vec<SignedVote>,
    ) -> Result<FencedLease> {
        if !self.members.contains_key(holder_node_id) {
            anyhow::bail!("Holder '{}' is not an authorized member of group '{}'", holder_node_id, self.group_id);
        }
        if expires_at_ms <= issued_at_ms {
            anyhow::bail!("Invalid lease interval: expires_at_ms ({}) <= issued_at_ms ({})", expires_at_ms, issued_at_ms);
        }
        if expires_at_ms - issued_at_ms > self.max_lease_ttl_ms {
            anyhow::bail!(
                "Requested lease duration ({}ms) exceeds group max_lease_ttl_ms ({}ms)",
                expires_at_ms - issued_at_ms,
                self.max_lease_ttl_ms
            );
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
        let expected_hash = hash_lease_proposal(
            &self.group_id,
            lease_id,
            resource_key,
            holder_node_id,
            workload_id,
            next_fencing,
            issued_at_ms,
            expires_at_ms,
        );

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
            lease_id: lease_id.to_string(),
            group_id: self.group_id.clone(),
            resource_key: resource_key.to_string(),
            holder_node_id: holder_node_id.to_string(),
            workload_id: workload_id.to_string(),
            fencing_epoch: next_fencing,
            issued_at_ms,
            expires_at_ms,
            qc,
        };
        let new_next_slot = self.next_slot + 1;
        // Persist-before-publish
        self.persist_committed_lease(&lease, new_next_slot).await?;
        self.next_slot = new_next_slot;
        self.max_fencing_epoch.insert(resource_key.to_string(), next_fencing);
        self.active_leases.insert(resource_key.to_string(), lease.clone());
        Ok(lease)
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
