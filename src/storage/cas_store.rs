use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

use crate::observability::global_metrics;
use crate::storage::BlobBridge;

/// Shared atomic storage primitive built on `BlobBridge`:
/// - **Versioned CAS Manifest Commits:** Reads `(manifest, etag)` and commits updates only if the
///   stored ETag still matches `expected_etag` (`put_object_cas`), coordinating safely across both
///   threads and separate processes/nodes sharing the same `BlobBridge` backend.
/// - **Verified Content-Addressed Blobs:** Writes immutable blobs keyed by BLAKE3 CID and verifies
///   the BLAKE3 digest on every read to catch silent corruption.
/// - **Reference-Tracked Garbage Collection:** Reclaims unreferenced content-addressed blobs safely.
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
        // Immutable content-addressed blobs need not be rewritten if already present
        if self.blobs.head_object(bucket, &key).await?.is_none() {
            self.blobs.put_object(bucket, &key, bytes).await?;
            global_metrics().inc_blob_write();
        }
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

    /// Reference-tracked garbage collector: deletes any object under `prefix` in `bucket`
    /// whose trailing CID is NOT in `referenced_cids`. Returns the number of reclaimed blobs.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test(flavor = "multi_thread")]
    async fn cas_store_enforces_atomic_cas_verifies_hashes_and_gcs_unreferenced_blobs() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let cas = CasStore::new(blobs.clone());

        // 1. Atomic CAS manifest commit + conflict detection
        let etag1 = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 1}), None)
            .await
            .unwrap();
        // Concurrent creator with None must fail with CasConflictError
        let dup = cas
            .commit_manifest_cas("cas-test", "m.json", &serde_json::json!({"v": 99}), None)
            .await
            .unwrap_err();
        assert!(dup
            .downcast_ref::<crate::storage::blob_bridge::CasConflictError>()
            .is_some());

        // Updating with matching ETag succeeds; stale ETag fails
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
        let orphan_cid = cas
            .put_verified_blob("cas-test", "blobs/", Bytes::from_static(b"orphan-data"))
            .await
            .unwrap();
        assert_eq!(
            cas.get_verified_blob("cas-test", "blobs/", &live_cid).await.unwrap(),
            Bytes::from_static(b"hello-world")
        );

        // Corrupt the stored blob in-place and verify get_verified_blob rejects it
        blobs
            .put_object("cas-test", &format!("blobs/{}", live_cid), Bytes::from_static(b"CORRUPTED"))
            .await
            .unwrap();
        assert!(cas.get_verified_blob("cas-test", "blobs/", &live_cid).await.is_err());

        // Restore live blob and run GC: orphan_cid is reclaimed, live_cid survives
        blobs
            .put_object("cas-test", &format!("blobs/{}", live_cid), Bytes::from_static(b"hello-world"))
            .await
            .unwrap();
        let mut live_set = HashSet::new();
        live_set.insert(live_cid.clone());
        let reclaimed = cas
            .gc_unreferenced_blobs("cas-test", "blobs/", &live_set)
            .await
            .unwrap();
        assert_eq!(reclaimed, 1);
        assert!(cas.get_verified_blob("cas-test", "blobs/", &live_cid).await.is_ok());
        assert!(cas.get_verified_blob("cas-test", "blobs/", &orphan_cid).await.is_err());
    }
}
