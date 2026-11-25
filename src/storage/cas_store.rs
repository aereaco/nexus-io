use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::observability::global_metrics;
use crate::storage::BlobBridge;

const OWNERSHIP_LEDGER_KEY: &str = "ownership.json";
const MAX_CAS_RETRIES: usize = 8;

/// Default crash-recovery TTL for stale `DeleteClaim`s (30 seconds).
pub const DEFAULT_DELETE_CLAIM_TTL_MS: u64 = 30_000;
/// Default distributed execution lease duration (30 seconds, renewable via heartbeat).
pub const DEFAULT_EXECUTION_LEASE_TTL_MS: u64 = 30_000;

/// Typed fail-fast error returned when an operation attempts to acquire ownership of a CID
/// that is currently in the durable `Deleting` state (after CAS 1 claim, before CAS 2 finalize).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobDeletingConflict {
    pub cid: String,
    pub claim_generation: u64,
}

impl std::fmt::Display for BlobDeletingConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlobDeletingConflict: CID '{}' is currently under durable deletion claim (gen={})",
            self.cid, self.claim_generation
        )
    }
}

impl std::error::Error for BlobDeletingConflict {}

/// Durable deletion claim preventing any new owner acquisition while physical deletion is in flight.
/// Survives process crashes so another node can idempotently finish deletion once expired.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteClaim {
    pub generation: u64,
    pub holder: String,
    pub claimed_at_ms: u64,
}

/// 3-State Durable Rust-Inspired Ownership Ledger:
/// 1. `Live` (`owners[cid]` non-empty): borrowed; cannot be deleted.
/// 2. `Tombstoned` (`pending_delete[cid] = gen`): zero owners; revivable by `acquire_owner`.
/// 3. `Deleting` (`deleting[cid] = DeleteClaim`): hard barrier; `acquire_owner` fails fast with
///    `BlobDeletingConflict`, physical deletion runs under this claim, and CAS 2 finalizes it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlobOwnershipTable {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub owners: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub pending_delete: BTreeMap<String, u64>,
    #[serde(default)]
    pub deleting: BTreeMap<String, DeleteClaim>,
}

/// Distributed single-writer execution lease with a strictly monotonic `fencing_token`.
/// Stored atomically via CAS in `BlobBridge` so stale holders that pause past `expires_at_ms`
/// are rejected by the commit path even if they resume later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionLease {
    pub holder: String,
    pub fencing_token: u64,
    pub acquired_at_ms: u64,
    pub expires_at_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Shared atomic storage primitive built on `BlobBridge`:
/// - **Versioned CAS Manifest Commits:** Atomic compare-and-swap via `put_object_cas`.
/// - **Verified Content-Addressed Blobs:** BLAKE3 verification on every read.
/// - **3-State Race-Free Ownership (`Live` -> `Tombstoned` -> `Deleting`):** Fail-fast
///   `BlobDeletingConflict` barrier and crash-recoverable deletion claims.
/// - **Fenced Distributed Execution Leases:** Renewable CAS leases with monotonic fencing tokens.
#[derive(Clone)]
pub struct CasStore {
    blobs: Arc<BlobBridge>,
}

impl CasStore {
    pub fn new(blobs: Arc<BlobBridge>) -> Self {
        Self { blobs }
    }

    /// Read a JSON manifest and its current CAS ETag (if present).
    pub async fn read_manifest<T: DeserializeOwned>(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(T, String)>> {
        global_metrics().inc_blob_read();
        let Some(meta) = self.blobs.head_object(bucket, key).await? else {
            return Ok(None);
        };
        let Some(bytes) = self.blobs.get_object(bucket, key).await? else {
            return Ok(None);
        };
        let val: T = serde_json::from_slice(&bytes)
            .with_context(|| format!("Corrupted JSON manifest '{}/{}'", bucket, key))?;
        Ok(Some((val, meta.etag)))
    }

    /// Atomically commit a JSON manifest using Compare-And-Swap (`expected_etag`).
    pub async fn commit_manifest_cas<T: Serialize>(
        &self,
        bucket: &str,
        key: &str,
        value: &T,
        expected_etag: Option<&str>,
    ) -> Result<String> {
        let _ = self.blobs.create_bucket(bucket).await;
        let bytes = Bytes::from(serde_json::to_vec(value)?);
        let if_none_match = expected_etag.is_none();
        match self
            .blobs
            .put_object_cas(bucket, key, bytes, expected_etag, if_none_match)
            .await
        {
            Ok(new_etag) => {
                global_metrics().inc_blob_write();
                Ok(new_etag)
            }
            Err(e) => {
                if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                    .is_some()
                {
                    global_metrics().inc_cas_conflict();
                }
                Err(e)
            }
        }
    }

    /// Store an immutable content-addressed blob under `<prefix><blake3_cid>` and return its CID.
    /// Note: writing bytes alone does NOT grant ownership; callers must still acquire ownership
    /// through the durable ledger protocol (`acquire_owner` / `transfer_manifest_ownership`).
    pub async fn put_verified_blob(
        &self,
        bucket: &str,
        prefix: &str,
        bytes: Bytes,
    ) -> Result<String> {
        let _ = self.blobs.create_bucket(bucket).await;
        let cid = blake3::hash(&bytes).to_hex().to_string();
        // Check if CID is actively under a durable Deleting claim; fail fast rather than racing
        if let Some((table, _)) = self
            .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
            .await?
        {
            if let Some(claim) = table.deleting.get(&cid) {
                return Err(anyhow::Error::new(BlobDeletingConflict {
                    cid,
                    claim_generation: claim.generation,
                }));
            }
        }
        let key = format!("{}{}", prefix, cid);
        self.blobs.put_object(bucket, &key, bytes).await?;
        global_metrics().inc_blob_write();
        Ok(cid)
    }

    /// Read a content-addressed blob under `<prefix><cid>` and verify its BLAKE3 content hash.
    pub async fn get_verified_blob(
        &self,
        bucket: &str,
        prefix: &str,
        expected_cid: &str,
    ) -> Result<Bytes> {
        global_metrics().inc_blob_read();
        let key = format!("{}{}", prefix, expected_cid);
        let data = self
            .blobs
            .get_object(bucket, &key)
            .await?
            .ok_or_else(|| anyhow!("Missing content-addressed blob '{}/{}'", bucket, key))?;
        let actual_cid = blake3::hash(&data).to_hex().to_string();
        if actual_cid != expected_cid {
            global_metrics().inc_corrupt_read();
            anyhow::bail!(
                "Blob integrity failure for '{}/{}': expected BLAKE3 {}, got {}",
                bucket,
                key,
                expected_cid,
                actual_cid
            );
        }
        Ok(data)
    }

    /// Safe startup reconciliation for crash-leftover blobs: NEVER deletes any CID that is
    /// present in `owners`, `pending_delete`, OR `deleting` in the durable ownership ledger.
    pub async fn gc_unreferenced_blobs(
        &self,
        bucket: &str,
        prefix: &str,
        referenced_cids: &HashSet<String>,
    ) -> Result<usize> {
        let ledger = self
            .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
            .await?
            .map(|(t, _)| t)
            .unwrap_or_default();
        let objects = self.blobs.list_objects(bucket, Some(prefix)).await?;
        let mut deleted = 0usize;
        for obj in objects {
            if let Some(cid) = obj.key.strip_prefix(prefix) {
                let protected = referenced_cids.contains(cid)
                    || ledger.owners.contains_key(cid)
                    || ledger.pending_delete.contains_key(cid)
                    || ledger.deleting.contains_key(cid);
                if !protected {
                    if self.blobs.delete_object(bucket, &obj.key).await.is_ok() {
                        deleted += 1;
                    }
                }
            }
        }
        Ok(deleted)
    }

    /// Acquire a named owner borrow on `cid` in the durable ownership ledger.
    /// Fails fast with `BlobDeletingConflict` if `cid` is currently under a durable `Deleting` claim.
    pub async fn acquire_owner(&self, bucket: &str, cid: &str, owner_id: &str) -> Result<()> {
        for _ in 0..MAX_CAS_RETRIES {
            let (mut table, etag) = match self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            {
                Some((t, e)) => (t, Some(e)),
                None => (BlobOwnershipTable::default(), None),
            };
            if let Some(claim) = table.deleting.get(cid) {
                return Err(anyhow::Error::new(BlobDeletingConflict {
                    cid: cid.to_string(),
                    claim_generation: claim.generation,
                }));
            }
            table.generation += 1;
            table.pending_delete.remove(cid);
            table
                .owners
                .entry(cid.to_string())
                .or_default()
                .insert(owner_id.to_string());
            match self
                .commit_manifest_cas(bucket, OWNERSHIP_LEDGER_KEY, &table, etag.as_deref())
                .await
            {
                Ok(_) => return Ok(()),
                Err(e)
                    if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                        .is_some() =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!(
            "CAS contention acquiring ownership of '{}' for '{}'",
            cid,
            owner_id
        )
    }

    /// Step 1 of 3-state reclamation: release `owner_id`'s borrow via CAS.
    /// If `cid` reaches zero owners, transitions `Live` -> `Tombstoned` (`pending_delete[cid] = gen`).
    pub async fn mark_release_tombstone(
        &self,
        bucket: &str,
        cid: &str,
        owner_id: &str,
    ) -> Result<Option<u64>> {
        for _ in 0..MAX_CAS_RETRIES {
            let (mut table, etag) = match self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            {
                Some((t, e)) => (t, Some(e)),
                None => return Ok(None),
            };
            let mut tombstone_gen = None;
            if let Some(set) = table.owners.get_mut(cid) {
                set.remove(owner_id);
                if set.is_empty() {
                    table.owners.remove(cid);
                    table.generation += 1;
                    let g = table.generation;
                    table.pending_delete.insert(cid.to_string(), g);
                    tombstone_gen = Some(g);
                }
            }
            match self
                .commit_manifest_cas(bucket, OWNERSHIP_LEDGER_KEY, &table, etag.as_deref())
                .await
            {
                Ok(_) => return Ok(tombstone_gen),
                Err(e)
                    if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                        .is_some() =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!(
            "CAS contention releasing ownership of '{}' for '{}'",
            cid,
            owner_id
        )
    }

    /// CAS 1 of reclamation: atomically transition `Tombstoned` -> `Deleting` (`DeleteClaim`).
    /// Once this succeeds, NO operation can acquire ownership of `cid` until physical deletion
    /// completes and CAS 2 (`finalize_delete_claim`) removes the claim.
    pub async fn claim_tombstone_for_delete(
        &self,
        bucket: &str,
        cid: &str,
        expected_gen: u64,
        holder: &str,
    ) -> Result<Option<DeleteClaim>> {
        for _ in 0..MAX_CAS_RETRIES {
            let Some((mut table, etag)) = self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            else {
                return Ok(None);
            };
            let eligible = table.pending_delete.get(cid) == Some(&expected_gen)
                && !table.owners.contains_key(cid)
                && !table.deleting.contains_key(cid);
            if !eligible {
                return Ok(None);
            }
            table.pending_delete.remove(cid);
            table.generation += 1;
            let claim = DeleteClaim {
                generation: table.generation,
                holder: holder.to_string(),
                claimed_at_ms: now_ms(),
            };
            table.deleting.insert(cid.to_string(), claim.clone());
            match self
                .commit_manifest_cas(bucket, OWNERSHIP_LEDGER_KEY, &table, Some(&etag))
                .await
            {
                Ok(_) => return Ok(Some(claim)),
                Err(e)
                    if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                        .is_some() =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!(
            "CAS contention claiming tombstone '{}' (gen={}) for deletion",
            cid,
            expected_gen
        )
    }

    /// CAS 2 of reclamation: physically delete `<prefix><cid>` under the durable `DeleteClaim`,
    /// then atomically finalize (remove) `deleting[cid]` ONLY AFTER physical deletion succeeds.
    /// If physical deletion fails, `deleting[cid]` is RETAINED for crash recovery.
    pub async fn execute_and_finalize_delete_claim(
        &self,
        bucket: &str,
        prefix: &str,
        cid: &str,
        claim_gen: u64,
    ) -> Result<bool> {
        // Physical delete happens strictly under the durable DeleteClaim
        self.blobs
            .delete_object(bucket, &format!("{}{}", prefix, cid))
            .await
            .with_context(|| {
                format!(
                    "Physical delete failed for '{}/{}{}' (retaining DeleteClaim gen={} for recovery)",
                    bucket, prefix, cid, claim_gen
                )
            })?;

        for _ in 0..MAX_CAS_RETRIES {
            let Some((mut table, etag)) = self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            else {
                return Ok(false);
            };
            let matches = table
                .deleting
                .get(cid)
                .map(|c| c.generation == claim_gen)
                .unwrap_or(false);
            if !matches {
                return Ok(false);
            }
            table.deleting.remove(cid);
            table.generation += 1;
            match self
                .commit_manifest_cas(bucket, OWNERSHIP_LEDGER_KEY, &table, Some(&etag))
                .await
            {
                Ok(_) => return Ok(true),
                Err(e)
                    if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                        .is_some() =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!(
            "CAS contention finalizing DeleteClaim '{}' (gen={})",
            cid,
            claim_gen
        )
    }

    /// Complete race-free reclamation of a tombstoned CID (`Tombstoned` -> `Deleting` -> delete -> finalize).
    pub async fn reclaim_tombstone(
        &self,
        bucket: &str,
        prefix: &str,
        cid: &str,
        expected_gen: u64,
    ) -> Result<bool> {
        let holder = self.blobs.node_id().to_string();
        let Some(claim) = self
            .claim_tombstone_for_delete(bucket, cid, expected_gen, &holder)
            .await?
        else {
            return Ok(false);
        };
        self.execute_and_finalize_delete_claim(bucket, prefix, cid, claim.generation)
            .await
    }

    /// Crash-recovery sweep for expired `DeleteClaim`s (default `ttl_ms = 30_000`):
    /// idempotently finishes physical deletion and finalizes any claim older than `ttl_ms`.
    pub async fn recover_expired_delete_claims(
        &self,
        bucket: &str,
        prefix: &str,
        ttl_ms: u64,
    ) -> Result<usize> {
        let Some((table, _)) = self
            .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
            .await?
        else {
            return Ok(0);
        };
        let now = now_ms();
        let expired: Vec<(String, u64)> = table
            .deleting
            .into_iter()
            .filter(|(_, c)| now.saturating_sub(c.claimed_at_ms) >= ttl_ms)
            .map(|(cid, c)| (cid, c.generation))
            .collect();
        let mut recovered = 0usize;
        for (cid, claim_gen) in expired {
            if self
                .execute_and_finalize_delete_claim(bucket, prefix, &cid, claim_gen)
                .await?
            {
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    /// Release `owner_id`'s borrow on `cid` and deterministically reclaim via the 3-state protocol.
    pub async fn release_owner(
        &self,
        bucket: &str,
        prefix: &str,
        cid: &str,
        owner_id: &str,
    ) -> Result<bool> {
        match self.mark_release_tombstone(bucket, cid, owner_id).await? {
            Some(gen_token) => self.reclaim_tombstone(bucket, prefix, cid, gen_token).await,
            None => Ok(false),
        }
    }

    /// Single-CAS atomic ownership transfer for `owner_id` from `prev_cids` to `next_cids`.
    /// Fails fast with `BlobDeletingConflict` if any CID in `next_cids` is currently `Deleting`.
    pub async fn transfer_manifest_ownership(
        &self,
        bucket: &str,
        prefix: &str,
        owner_id: &str,
        prev_cids: &HashSet<String>,
        next_cids: &HashSet<String>,
    ) -> Result<usize> {
        let to_acquire: Vec<String> = next_cids.difference(prev_cids).cloned().collect();
        let to_release: Vec<String> = prev_cids.difference(next_cids).cloned().collect();
        if to_acquire.is_empty() && to_release.is_empty() {
            return Ok(0);
        }

        let mut tombstones: Vec<(String, u64)> = Vec::new();
        let mut committed = false;

        for _ in 0..MAX_CAS_RETRIES {
            let (mut table, etag) = match self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            {
                Some((t, e)) => (t, Some(e)),
                None => (BlobOwnershipTable::default(), None),
            };
            for cid in &to_acquire {
                if let Some(claim) = table.deleting.get(cid) {
                    return Err(anyhow::Error::new(BlobDeletingConflict {
                        cid: cid.clone(),
                        claim_generation: claim.generation,
                    }));
                }
            }
            tombstones.clear();

            for cid in &to_acquire {
                table.generation += 1;
                table.pending_delete.remove(cid);
                table
                    .owners
                    .entry(cid.clone())
                    .or_default()
                    .insert(owner_id.to_string());
            }
            for cid in &to_release {
                if let Some(set) = table.owners.get_mut(cid) {
                    set.remove(owner_id);
                    if set.is_empty() {
                        table.owners.remove(cid);
                        table.generation += 1;
                        let g = table.generation;
                        table.pending_delete.insert(cid.clone(), g);
                        tombstones.push((cid.clone(), g));
                    }
                }
            }

            match self
                .commit_manifest_cas(bucket, OWNERSHIP_LEDGER_KEY, &table, etag.as_deref())
                .await
            {
                Ok(_) => {
                    committed = true;
                    break;
                }
                Err(e)
                    if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                        .is_some() =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        if !committed {
            anyhow::bail!(
                "CAS contention during atomic ownership transfer for '{}'",
                owner_id
            );
        }

        let mut dropped = 0usize;
        for (cid, gen_token) in tombstones {
            if self.reclaim_tombstone(bucket, prefix, &cid, gen_token).await? {
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    // -------------------------------------------------------------------------
    // Distributed Fenced Execution Leases (Atomic CAS + Renewal + Fencing Token)
    // -------------------------------------------------------------------------

    /// Atomically acquire a distributed single-writer execution lease via CAS, returning a
    /// strictly monotonic `fencing_token`. Succeeds if no lease exists or the prior lease expired.
    pub async fn acquire_execution_lease(
        &self,
        bucket: &str,
        lease_key: &str,
        holder: &str,
        ttl_ms: u64,
    ) -> Result<ExecutionLease> {
        for _ in 0..MAX_CAS_RETRIES {
            let now = now_ms();
            let (prev_token, expected_etag) = match self
                .read_manifest::<ExecutionLease>(bucket, lease_key)
                .await?
            {
                Some((existing, etag)) => {
                    if existing.expires_at_ms > now && existing.holder != holder {
                        anyhow::bail!(
                            "Execution lease '{}' held by '{}' (fencing_token={}) until {}",
                            lease_key,
                            existing.holder,
                            existing.fencing_token,
                            existing.expires_at_ms
                        );
                    }
                    (existing.fencing_token, Some(etag))
                }
                None => (0, None),
            };

            let next = ExecutionLease {
                holder: holder.to_string(),
                fencing_token: prev_token + 1,
                acquired_at_ms: now,
                expires_at_ms: now.saturating_add(ttl_ms),
            };
            match self
                .commit_manifest_cas(bucket, lease_key, &next, expected_etag.as_deref())
                .await
            {
                Ok(_) => return Ok(next),
                Err(e)
                    if e.downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
                        .is_some() =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!("CAS contention acquiring execution lease '{}'", lease_key)
    }

    /// Renew an active execution lease via CAS ONLY IF `holder` and `fencing_token` still match.
    pub async fn renew_execution_lease(
        &self,
        bucket: &str,
        lease_key: &str,
        holder: &str,
        fencing_token: u64,
        ttl_ms: u64,
    ) -> Result<ExecutionLease> {
        let Some((mut existing, etag)) = self
            .read_manifest::<ExecutionLease>(bucket, lease_key)
            .await?
        else {
            anyhow::bail!("Execution lease '{}' no longer exists", lease_key);
        };
        if existing.holder != holder || existing.fencing_token != fencing_token {
            anyhow::bail!(
                "Execution lease '{}' fenced out (expected holder='{}' token={}, found holder='{}' token={})",
                lease_key,
                holder,
                fencing_token,
                existing.holder,
                existing.fencing_token
            );
        }
        existing.expires_at_ms = now_ms().saturating_add(ttl_ms);
        self.commit_manifest_cas(bucket, lease_key, &existing, Some(&etag))
            .await?;
        Ok(existing)
    }

    /// Release an active execution lease via CAS by expiring it immediately while preserving
    /// `fencing_token` so the monotonic counter never resets backwards.
    pub async fn release_execution_lease(
        &self,
        bucket: &str,
        lease_key: &str,
        holder: &str,
        fencing_token: u64,
    ) -> Result<()> {
        let Some((mut existing, etag)) = self
            .read_manifest::<ExecutionLease>(bucket, lease_key)
            .await?
        else {
            return Ok(());
        };
        if existing.holder != holder || existing.fencing_token != fencing_token {
            return Ok(());
        }
        existing.expires_at_ms = 0;
        let _ = self
            .commit_manifest_cas(bucket, lease_key, &existing, Some(&etag))
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test(flavor = "multi_thread")]
    async fn cas_store_enforces_3_state_deleting_barrier_recovery_and_fenced_leases() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let cas = CasStore::new(blobs.clone());

        // 1. Atomic CAS manifest commit + conflict detection
        let etag1 = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 1}), None)
            .await
            .unwrap();
        assert!(cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 99}), None)
            .await
            .is_err());
        let etag2 = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 2}), Some(&etag1))
            .await
            .unwrap();
        assert_ne!(etag1, etag2);

        // 2. Verified blob read detects silent corruption
        let live_cid = cas
            .put_verified_blob("cas-test", "blobs/", Bytes::from_static(b"hello-world"))
            .await
            .unwrap();
        blobs
            .put_object("cas-test", &format!("blobs/{}", live_cid), Bytes::from_static(b"CORRUPTED"))
            .await
            .unwrap();
        assert!(cas.get_verified_blob("cas-test", "blobs/", &live_cid).await.is_err());

        // 3. 3-State Deleting Barrier Test:
        //    Owner A releases -> Tombstoned -> CAS 1 moves to Deleting ->
        //    Owner B tries acquire_owner AFTER CAS 1 -> MUST fail fast with BlobDeletingConflict!
        let cid = cas
            .put_verified_blob("own-test", "blobs/", Bytes::from_static(b"critical-payload"))
            .await
            .unwrap();
        cas.acquire_owner("own-test", &cid, "cell:a").await.unwrap();
        let tomb_gen = cas
            .mark_release_tombstone("own-test", &cid, "cell:a")
            .await
            .unwrap()
            .unwrap();
        let claim = cas
            .claim_tombstone_for_delete("own-test", &cid, tomb_gen, "node-1")
            .await
            .unwrap()
            .expect("CAS 1 claim should succeed");

        let conflict = cas
            .acquire_owner("own-test", &cid, "cell:b")
            .await
            .unwrap_err();
        let typed = conflict
            .downcast_ref::<BlobDeletingConflict>()
            .expect("must fail fast with typed BlobDeletingConflict");
        assert_eq!(typed.cid, cid);
        assert_eq!(typed.claim_generation, claim.generation);

        // 4. Crash-recovery of abandoned DeleteClaim (ttl_ms = 0 simulates expired claim)
        let recovered = cas
            .recover_expired_delete_claims("own-test", "blobs/", 0)
            .await
            .unwrap();
        assert_eq!(recovered, 1);
        assert!(cas.get_verified_blob("own-test", "blobs/", &cid).await.is_err());

        // 5. Distributed Fenced Execution Lease: expiry + monotonic token + stale renewal rejection
        let lease_a = cas
            .acquire_execution_lease("lease-test", "db.lease.json", "node-a", 1)
            .await
            .unwrap();
        assert_eq!(lease_a.fencing_token, 1);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let lease_b = cas
            .acquire_execution_lease("lease-test", "db.lease.json", "node-b", 30_000)
            .await
            .unwrap();
        assert_eq!(lease_b.fencing_token, 2);

        // Node A's stale renewal MUST be fenced out
        assert!(cas
            .renew_execution_lease("lease-test", "db.lease.json", "node-a", lease_a.fencing_token, 30_000)
            .await
            .is_err());
        // Node B's active renewal succeeds
        assert!(cas
            .renew_execution_lease("lease-test", "db.lease.json", "node-b", lease_b.fencing_token, 30_000)
            .await
            .is_ok());
        cas.release_execution_lease("lease-test", "db.lease.json", "node-b", lease_b.fencing_token)
            .await
            .unwrap();
    }
}
