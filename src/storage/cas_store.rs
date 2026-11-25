use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use crate::observability::global_metrics;
use crate::storage::BlobBridge;

const OWNERSHIP_LEDGER_KEY: &str = "ownership.json";
const MAX_CAS_RETRIES: usize = 8;

/// Durable Rust-inspired ownership ledger with 2-phase tombstone reclamation:
/// - `owners`: maps each content-addressed blob CID to the set of live `OwnerId`s borrowing it.
/// - `pending_delete`: when a CID's last owner releases it, it transitions atomically via CAS into
///   `pending_delete[cid] = generation` instead of deleting unlocked.
/// - If another process acquires `cid` before Phase 2 reclamation runs, `pending_delete.remove(cid)`
///   invalidates the tombstone so stale reclaimers abort cleanly without deleting a re-borrowed blob.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct BlobOwnershipTable {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub owners: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub pending_delete: BTreeMap<String, u64>,
}

/// Shared atomic storage primitive built on `BlobBridge`:
/// - **Versioned CAS Manifest Commits:** Reads `(manifest, etag)` and commits updates only if the
///   stored ETag still matches `expected_etag` (`put_object_cas`).
/// - **Verified Content-Addressed Blobs:** Writes immutable blobs keyed by BLAKE3 CID and verifies
///   the BLAKE3 digest on every read to catch silent corruption.
/// - **Race-Free Deterministic Ownership (`Drop`):** Single-CAS atomic ownership transfers and
///   2-phase generation-checked tombstone reclamation (no stop-the-world GC).
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

    /// Atomically commit a JSON manifest using Compare-And-Swap (`expected_etag`):
    /// - If `expected_etag` is `None`, succeeds ONLY if the manifest does not yet exist (`if_none_match = true`).
    /// - If `expected_etag` is `Some(etag)`, succeeds ONLY if the stored ETag still matches `etag`.
    /// - Returns `CasConflictError` on concurrent modification.
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
    pub async fn put_verified_blob(
        &self,
        bucket: &str,
        prefix: &str,
        bytes: Bytes,
    ) -> Result<String> {
        let _ = self.blobs.create_bucket(bucket).await;
        let cid = blake3::hash(&bytes).to_hex().to_string();
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

    /// Reference-tracked startup reconciliation for crash-leftover blobs (e.g. SIGKILL mid-upload).
    /// Normal runtime reclamation uses 2-phase tombstone deterministic `Drop`.
    pub async fn gc_unreferenced_blobs(
        &self,
        bucket: &str,
        prefix: &str,
        referenced_cids: &HashSet<String>,
    ) -> Result<usize> {
        let objects = self.blobs.list_objects(bucket, Some(prefix)).await?;
        let mut deleted = 0usize;
        for obj in objects {
            if let Some(cid) = obj.key.strip_prefix(prefix) {
                if !referenced_cids.contains(cid) {
                    if self.blobs.delete_object(bucket, &obj.key).await.is_ok() {
                        deleted += 1;
                    }
                }
            }
        }
        Ok(deleted)
    }

    /// Acquire a named owner borrow on `cid` in the durable ownership ledger.
    /// Clears any pending tombstone for `cid` atomically in the same CAS commit.
    pub async fn acquire_owner(&self, bucket: &str, cid: &str, owner_id: &str) -> Result<()> {
        for _ in 0..MAX_CAS_RETRIES {
            let (mut table, etag) = match self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            {
                Some((t, e)) => (t, Some(e)),
                None => (BlobOwnershipTable::default(), None),
            };
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

    /// Phase 1 of 2-phase tombstone reclamation: release `owner_id`'s borrow on `cid` via CAS.
    /// If `cid` now has zero owners, records `pending_delete[cid] = gen` and returns `Ok(Some(gen))`.
    /// Never falls through on CAS retry exhaustion (strictly returns `Err`).
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

    /// Phase 2 of 2-phase tombstone reclamation: conditionally reclaim `<prefix><cid>` ONLY IF
    /// `pending_delete[cid] == expected_gen` AND `owners[cid]` is empty.
    /// If another process re-acquired `cid` in the meantime, aborts cleanly and returns `Ok(false)`.
    pub async fn reclaim_tombstone(
        &self,
        bucket: &str,
        prefix: &str,
        cid: &str,
        expected_gen: u64,
    ) -> Result<bool> {
        for _ in 0..MAX_CAS_RETRIES {
            let Some((mut table, etag)) = self
                .read_manifest::<BlobOwnershipTable>(bucket, OWNERSHIP_LEDGER_KEY)
                .await?
            else {
                return Ok(false);
            };
            let still_tombstoned = table.pending_delete.get(cid) == Some(&expected_gen)
                && !table.owners.contains_key(cid);
            if !still_tombstoned {
                // Re-acquired or already reclaimed by another process — do NOT delete!
                return Ok(false);
            }
            // Atomically claim & clear the tombstone via CAS BEFORE deleting the blob
            table.pending_delete.remove(cid);
            table.generation += 1;
            match self
                .commit_manifest_cas(bucket, OWNERSHIP_LEDGER_KEY, &table, Some(&etag))
                .await
            {
                Ok(_) => {
                    let _ = self
                        .blobs
                        .delete_object(bucket, &format!("{}{}", prefix, cid))
                        .await;
                    return Ok(true);
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
        anyhow::bail!(
            "CAS contention reclaiming tombstone '{}' (gen={})",
            cid,
            expected_gen
        )
    }

    /// Release `owner_id`'s borrow on `cid` and deterministically reclaim `<prefix><cid>`
    /// via the race-free 2-phase tombstone protocol if zero owners remain.
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

    /// Single-CAS atomic ownership transfer for `owner_id` from `prev_cids` to `next_cids`:
    /// 1. In ONE atomic CAS commit on `ownership.json`, acquires all new CIDs (clearing any
    ///    pending tombstones) AND releases all superseded CIDs (marking zero-owner CIDs as tombstoned).
    /// 2. Reclaims each newly tombstoned CID via conditional `reclaim_tombstone`.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test(flavor = "multi_thread")]
    async fn cas_store_enforces_atomic_cas_verifies_hashes_and_tombstone_drop_prevents_races() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let cas = CasStore::new(blobs.clone());

        // 1. Atomic CAS manifest commit + conflict detection
        let etag1 = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 1}), None)
            .await
            .unwrap();
        let dup = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 99}), None)
            .await
            .unwrap_err();
        assert!(dup
            .downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
            .is_some());

        let etag2 = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 2}), Some(&etag1))
            .await
            .unwrap();
        assert_ne!(etag1, etag2);
        assert!(cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 3}), Some(&etag1))
            .await
            .is_err());

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

        // 3. Deterministic 2-phase tombstone Drop: shared blob survives while borrowed
        let shared_cid = cas
            .put_verified_blob("own-test", "blobs/", Bytes::from_static(b"shared-runtime-bytes"))
            .await
            .unwrap();
        cas.acquire_owner("own-test", &shared_cid, "cell:a").await.unwrap();
        cas.acquire_owner("own-test", &shared_cid, "cell:b").await.unwrap();

        assert!(!cas.release_owner("own-test", "blobs/", &shared_cid, "cell:a").await.unwrap());
        assert!(cas.get_verified_blob("own-test", "blobs/", &shared_cid).await.is_ok());

        // 4. Race-safety test: Owner B marks tombstone, then Owner C re-acquires BEFORE Phase 2 runs.
        //    Owner B's stale Phase 2 reclaim MUST abort and preserve the blob!
        let stale_gen = cas
            .mark_release_tombstone("own-test", &shared_cid, "cell:b")
            .await
            .unwrap()
            .expect("last owner should produce tombstone generation");
        cas.acquire_owner("own-test", &shared_cid, "cell:c").await.unwrap();
        assert!(
            !cas.reclaim_tombstone("own-test", "blobs/", &shared_cid, stale_gen)
                .await
                .unwrap(),
            "stale reclaimer must abort when another owner re-acquired the CID"
        );
        assert!(cas.get_verified_blob("own-test", "blobs/", &shared_cid).await.is_ok());

        // Finally Owner C releases -> zero owners left -> reclaimed cleanly
        assert!(cas.release_owner("own-test", "blobs/", &shared_cid, "cell:c").await.unwrap());
        assert!(cas.get_verified_blob("own-test", "blobs/", &shared_cid).await.is_err());
    }
}
