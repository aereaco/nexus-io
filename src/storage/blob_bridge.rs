use anyhow::Result;
use bytes::Bytes;
#[cfg(feature = "storage-s3")]
use futures::StreamExt;
#[cfg(feature = "storage-p2p")]
use iroh::protocol::Router;
#[cfg(feature = "storage-p2p")]
use iroh::Endpoint;
#[cfg(feature = "storage-p2p")]
use iroh_blobs::store::fs::FsStore;
#[cfg(feature = "storage-p2p")]
use iroh_blobs::{BlobsProtocol, Hash as BlobHash};
use once_cell::sync::Lazy;
#[cfg(feature = "storage-s3")]
use s3s::dto::{
    Bucket as S3Bucket, CreateBucketInput, CreateBucketOutput, DeleteObjectInput,
    DeleteObjectOutput, ETag, GetObjectInput, GetObjectOutput, HeadObjectInput, HeadObjectOutput,
    ListBucketsInput, ListBucketsOutput, ListObjectsV2Input, ListObjectsV2Output,
    Object as S3Object, PutObjectInput, PutObjectOutput, StreamingBlob,
};
#[cfg(feature = "storage-s3")]
use s3s::{s3_error, S3Request, S3Response, S3Result, S3};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::storage_config::create_dev_config;
use crate::db::Database;

/// Global singleton blob store (`iroh-blobs` P2P router when `p2p-storage` is enabled,
/// or lightweight local BLAKE3 CAS directory in `profile-core`).
struct BlobNode {
    #[cfg(feature = "storage-p2p")]
    store: Arc<FsStore>,
    #[cfg(feature = "storage-p2p")]
    endpoint: Endpoint,
    #[cfg(feature = "storage-p2p")]
    _router: Router,
    #[cfg(not(feature = "storage-p2p"))]
    local_dir: std::path::PathBuf,
    node_id: String,
}

static BLOB_NODE: Lazy<Arc<RwLock<Option<Arc<BlobNode>>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Initialize or get the global blob store in `data_dir`.
async fn init_blob_node(data_dir: &std::path::Path) -> Result<Arc<BlobNode>> {
    let mut node_lock = BLOB_NODE.write().await;

    if node_lock.is_none() {
        let vpn_ip = crate::storage::wireguard::WireGuardInterface::get_vpn_ip();
        let bind_addr = vpn_ip.clone().map(|ip| format!("{}:3900", ip));
        let mut config = create_dev_config(bind_addr);
        let blob_path = data_dir.join("nexus-blobs");
        config.data_dir = blob_path.to_string_lossy().to_string();

        if let Some(ip) = &vpn_ip {
            println!("🔒 Secure Mesh Detected: Binding storage to {}", ip);
        } else {
            println!("⚠️  Secure Mesh NOT Detected: Localhost storage mode");
        }

        #[cfg(feature = "storage-p2p")]
        let node = {
            let store = Arc::new(
                FsStore::load(&config.data_dir)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to initialize iroh-blobs FsStore: {}", e))?,
            );

            let endpoint = Endpoint::bind(iroh::endpoint::presets::N0)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to bind iroh Endpoint: {}", e))?;
            let node_id = endpoint.id().to_string();

            let blobs_proto = BlobsProtocol::new(&store, None);
            let router = Router::builder(endpoint.clone())
                .accept(iroh_blobs::ALPN, blobs_proto)
                .spawn();

            println!("✅ iroh-blobs FsStore + P2P Endpoint {} ready at {}", node_id, config.data_dir);
            Arc::new(BlobNode {
                store,
                endpoint,
                _router: router,
                node_id,
            })
        };

        #[cfg(not(feature = "storage-p2p"))]
        let node = {
            tokio::fs::create_dir_all(&blob_path).await?;
            let node_id = format!("local-{}", blake3::hash(config.data_dir.as_bytes()).to_hex());
            println!("✅ Local BLAKE3 CAS BlobStore ({}) ready at {}", &node_id[..16], config.data_dir);
            Arc::new(BlobNode {
                local_dir: blob_path,
                node_id,
            })
        };

        *node_lock = Some(node);
    }

    Ok(node_lock.as_ref().unwrap().clone())
}

/// Deterministic Rendezvous (HRW) Hashing over active peer `NodeId`s using `blake3`.
/// Every node computes the exact same top-`n` replica targets for `(bucket, key)` without consensus.
pub fn select_hrw_replicas(object_key: &str, peers: &[String], n: usize) -> Vec<String> {
    let mut scored: Vec<([u8; 32], &String)> = peers
        .iter()
        .map(|peer| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(object_key.as_bytes());
            hasher.update(b":");
            hasher.update(peer.as_bytes());
            (*hasher.finalize().as_bytes(), peer)
        })
        .collect();

    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored.into_iter().take(n).map(|(_, p)| p.clone()).collect()
}

/// Object metadata stored in SurrealDB (`sys::object`).
#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub size: u64,
}

/// Error returned when a Compare-And-Swap (`If-Match` / `If-None-Match`) precondition fails.
#[derive(Debug)]
pub struct CasConflictError(pub String);

impl std::fmt::Display for CasConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CAS precondition failed: {}", self.0)
    }
}

impl std::error::Error for CasConflictError {}

/// Cross-platform Object & Blob Bridge (`s3s` + `iroh` + `iroh-blobs` + SurrealDB metadata).
#[derive(Clone)]
pub struct BlobBridge {
    node: Arc<BlobNode>,
    db: Arc<Database>,
}

impl BlobBridge {
    pub async fn new(db: Arc<Database>) -> Result<Self> {
        Self::new_in(db, ".").await
    }

    /// Initialize `BlobBridge` inside an explicit writable `data_dir` (required on Android/iOS sandboxes).
    pub async fn new_in(db: Arc<Database>, data_dir: impl AsRef<std::path::Path>) -> Result<Self> {
        let node = init_blob_node(data_dir.as_ref()).await?;

        // Ensure storage metadata tables exist in `pinned` `nexus::system` and register this node in `sys::node`.
        db.client.use_ns("nexus").use_db("system").await?;
        let _ = db
            .client
            .query(
                "DEFINE TABLE IF NOT EXISTS `sys::bucket` SCHEMALESS;
                 DEFINE TABLE IF NOT EXISTS `sys::object` SCHEMALESS;
                 DEFINE TABLE IF NOT EXISTS `sys::node` SCHEMALESS;
                 UPSERT type::record('sys::node', $id) SET pubkey = $id, status = 'active', updated_at = time::now();",
            )
            .bind(("id", node.node_id.clone()))
            .await;

        let bridge = Self { node, db };
        bridge.spawn_repair_loop();
        Ok(bridge)
    }

    pub fn node_id(&self) -> &str {
        &self.node.node_id
    }

    /// Always pin `BlobBridge` metadata operations to the `pinned` `nexus::system` scope
    /// so concurrent `elastic` cell `(ns, db)` switches never leak into storage metadata.
    async fn system_db(&self) -> Result<&crate::db::DbClient> {
        self.db.client.use_ns("nexus").use_db("system").await?;
        Ok(&self.db.client)
    }

    /// Background anti-entropy scrub loop: verifies local HRW-assigned blobs and pulls missing replicas via `iroh-blobs`.
    pub fn spawn_repair_loop(&self) {
        let bridge = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = bridge.repair_once(3).await {
                    eprintln!("⚠️  Blob anti-entropy repair tick warning: {}", e);
                }
            }
        });
    }

    /// Run one pass of HRW anti-entropy verification/repair.
    #[cfg(feature = "storage-p2p")]
    pub async fn repair_once(&self, replication_factor: usize) -> Result<usize> {
        let client = self.system_db().await?;
        let mut peer_resp = client
            .query("SELECT pubkey FROM `sys::node` WHERE status = 'active'")
            .await?;
        let peer_rows: Vec<HashMap<String, serde_json::Value>> = peer_resp.take(0)?;
        let peers: Vec<String> = peer_rows
            .into_iter()
            .filter_map(|r| r.get("pubkey").and_then(|v| v.as_str()).map(String::from))
            .collect();

        if peers.is_empty() {
            return Ok(0);
        }

        let mut obj_resp = client
            .query("SELECT bucket, key, blake3 FROM `sys::object` WHERE deleted != true")
            .await?;
        let objects: Vec<HashMap<String, serde_json::Value>> = obj_resp.take(0)?;

        let mut repaired = 0usize;
        for row in objects {
            let (Some(bucket), Some(key), Some(hash_str)) = (
                row.get("bucket").and_then(|v| v.as_str()),
                row.get("key").and_then(|v| v.as_str()),
                row.get("blake3").and_then(|v| v.as_str()),
            ) else {
                continue;
            };

            let obj_id = format!("{}/{}", bucket, key);
            let targets = select_hrw_replicas(&obj_id, &peers, replication_factor);
            if !targets.iter().any(|p| p == &self.node.node_id) {
                continue;
            }

            let Ok(hash) = hash_str.parse::<BlobHash>() else {
                continue;
            };
            if self.node.store.blobs().has(hash).await.unwrap_or(false) {
                continue;
            }

            for peer in targets.iter().filter(|p| *p != &self.node.node_id) {
                let Ok(peer_id) = peer.parse::<iroh::EndpointId>() else {
                    continue;
                };
                if let Ok(conn) = self.node.endpoint.connect(peer_id, iroh_blobs::ALPN).await {
                    if self.node.store.remote().fetch(conn, hash).await.is_ok() {
                        repaired += 1;
                        break;
                    }
                }
            }
        }

        Ok(repaired)
    }

    #[cfg(not(feature = "storage-p2p"))]
    pub async fn repair_once(&self, _replication_factor: usize) -> Result<usize> {
        Ok(0)
    }

    /// Create a bucket in SurrealDB metadata (`sys::bucket`).
    pub async fn create_bucket(&self, name: &str) -> Result<()> {
        let client = self.system_db().await?;
        let query = "UPSERT type::record('sys::bucket', $id) SET name = $name, created_at = time::now()";
        let response = client
            .query(query)
            .bind(("id", name.to_string()))
            .bind(("name", name.to_string()))
            .await?;

        response.check()?;
        println!("✅ Bucket '{}' created (s3s + iroh-blobs)", name);
        Ok(())
    }

    /// Record a mesh peer in SurrealDB (`sys::node`) for HRW placement and `iroh-blobs` sync.
    pub async fn connect_peer(&self, pubkey: &str, endpoint: &str) -> Result<()> {
        let client = self.system_db().await?;
        let query = "UPSERT type::record('sys::node', $id) SET pubkey = $pubkey, endpoint = $endpoint, status = 'active', updated_at = time::now()";
        let response = client
            .query(query)
            .bind(("id", pubkey.to_string()))
            .bind(("pubkey", pubkey.to_string()))
            .bind(("endpoint", endpoint.to_string()))
            .await?;
        response.check()?;
        println!("✅ Registered storage mesh peer {} -> {}", pubkey, endpoint);
        Ok(())
    }

    /// List all buckets from SurrealDB.
    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        let client = self.system_db().await?;
        let mut response = client.query("SELECT name FROM `sys::bucket`").await?;
        let rows: Vec<HashMap<String, serde_json::Value>> = response.take(0)?;

        let names: Vec<String> = rows
            .into_iter()
            .filter_map(|row| row.get("name").and_then(|v| v.as_str()).map(String::from))
            .collect();

        Ok(names)
    }

    /// Put object without CAS preconditions.
    pub async fn put_object(&self, bucket: &str, key: &str, value: Bytes) -> Result<()> {
        let _ = self.put_object_cas(bucket, key, value, None, false).await?;
        Ok(())
    }

    /// Put object with optional S3 Compare-And-Swap (`If-Match` / `If-None-Match: "*"`) semantics.
    /// Returns the `blake3` ETag hex string.
    pub async fn put_object_cas(
        &self,
        bucket: &str,
        key: &str,
        value: Bytes,
        if_match: Option<&str>,
        if_none_match: bool,
    ) -> Result<String> {
        if if_match.is_some() || if_none_match {
            let existing = self.head_object(bucket, key).await?;
            match (existing, if_match, if_none_match) {
                (Some(_), _, true) => {
                    return Err(CasConflictError("Object already exists (If-None-Match: *)".into()).into());
                }
                (None, Some(expected), _) => {
                    return Err(CasConflictError(format!(
                        "Object missing; expected ETag {}",
                        expected
                    ))
                    .into());
                }
                (Some(meta), Some(expected), _) => {
                    let clean = expected.trim_matches('"');
                    if meta.etag != clean {
                        return Err(CasConflictError(format!(
                            "ETag mismatch: expected {}, got {}",
                            clean, meta.etag
                        ))
                        .into());
                    }
                }
                _ => {}
            }
        }

        let len = value.len() as u64;
        #[cfg(feature = "storage-p2p")]
        let hash_hex = {
            let outcome = self.node.store.blobs().add_bytes(value).await?;
            outcome.hash.to_hex().to_string()
        };
        #[cfg(not(feature = "storage-p2p"))]
        let hash_hex = {
            let hex = blake3::hash(&value).to_hex().to_string();
            let path = self.node.local_dir.join(&hex);
            if !path.exists() {
                tokio::fs::write(&path, &value).await?;
            }
            hex
        };

        let obj_id = format!("{}/{}", bucket, key);
        let client = self.system_db().await?;
        let query = "UPSERT type::record('sys::object', $id) SET bucket = $bucket, key = $key, blake3 = $hash, etag = $hash, size = $size, deleted = false, updated_at = time::now()";
        let response = client
            .query(query)
            .bind(("id", obj_id))
            .bind(("bucket", bucket.to_string()))
            .bind(("key", key.to_string()))
            .bind(("hash", hash_hex.clone()))
            .bind(("size", len))
            .await?;
        response.check()?;

        Ok(hash_hex)
    }

    /// Head object - retrieve metadata (`ETag`, `size`) without reading bytes.
    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<Option<ObjectMeta>> {
        let obj_id = format!("{}/{}", bucket, key);
        let client = self.system_db().await?;
        let mut response = client
            .query("SELECT blake3, size, deleted FROM type::record('sys::object', $id)")
            .bind(("id", obj_id))
            .await?;

        let rows: Vec<HashMap<String, serde_json::Value>> = response.take(0)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        if row.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Ok(None);
        }

        let Some(etag) = row.get("blake3").and_then(|v| v.as_str()).map(String::from) else {
            return Ok(None);
        };
        let size = row.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

        Ok(Some(ObjectMeta {
            bucket: bucket.to_string(),
            key: key.to_string(),
            etag,
            size,
        }))
    }

    /// List non-deleted objects in a bucket matching an optional prefix.
    pub async fn list_objects(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<ObjectMeta>> {
        let client = self.system_db().await?;
        let mut response = client
            .query("SELECT key, blake3, size FROM `sys::object` WHERE bucket = $bucket AND deleted != true")
            .bind(("bucket", bucket.to_string()))
            .await?;
        let rows: Vec<HashMap<String, serde_json::Value>> = response.take(0)?;

        let out = rows
            .into_iter()
            .filter_map(|row| {
                let key = row.get("key")?.as_str()?.to_string();
                if let Some(pfx) = prefix {
                    if !key.starts_with(pfx) {
                        return None;
                    }
                }
                let etag = row.get("blake3")?.as_str()?.to_string();
                let size = row.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                Some(ObjectMeta {
                    bucket: bucket.to_string(),
                    key,
                    etag,
                    size,
                })
            })
            .collect();

        Ok(out)
    }

    /// Get object - zero-copy read (`bytes::Bytes`) from `iroh-blobs` or local BLAKE3 CAS.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Option<Bytes>> {
        let Some(meta) = self.head_object(bucket, key).await? else {
            return Ok(None);
        };

        #[cfg(feature = "storage-p2p")]
        {
            let hash: BlobHash = meta
                .etag
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid BLAKE3 hash '{}': {:?}", meta.etag, e))?;

            let data = self.node.store.blobs().get_bytes(hash).await?;
            Ok(Some(data))
        }

        #[cfg(not(feature = "storage-p2p"))]
        {
            let path = self.node.local_dir.join(&meta.etag);
            let raw = tokio::fs::read(&path).await?;
            Ok(Some(Bytes::from(raw)))
        }
    }

    /// Delete object - mark tombstone in SurrealDB metadata.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let obj_id = format!("{}/{}", bucket, key);
        let client = self.system_db().await?;
        let response = client
            .query("UPDATE type::record('sys::object', $id) SET deleted = true, updated_at = time::now()")
            .bind(("id", obj_id))
            .await?;
        response.check()?;
        Ok(())
    }
}

#[cfg(feature = "storage-s3")]
#[salvo::prelude::async_trait]
impl S3 for BlobBridge {
    async fn create_bucket(
        &self,
        req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        self.create_bucket(&req.input.bucket)
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?;
        Ok(S3Response::new(CreateBucketOutput::default()))
    }

    async fn list_buckets(
        &self,
        _req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        let names = self
            .list_buckets()
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?;
        let buckets = names
            .into_iter()
            .map(|name| S3Bucket {
                name: Some(name),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(ListBucketsOutput {
            buckets: Some(buckets),
            ..Default::default()
        }))
    }

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        let PutObjectInput {
            bucket,
            key,
            body,
            if_match,
            if_none_match,
            ..
        } = req.input;

        let mut buf = Vec::new();
        if let Some(mut stream) = body {
            while let Some(chunk) = stream.next().await {
                let bytes = chunk.map_err(|e| s3_error!(InternalError, "{}", e))?;
                buf.extend_from_slice(&bytes);
            }
        }

        let if_match_str = match &if_match {
            Some(s3s::dto::ETagCondition::ETag(ETag::Strong(s) | ETag::Weak(s))) => Some(s.clone()),
            _ => None,
        };
        let if_none_match_any = matches!(if_none_match, Some(s3s::dto::ETagCondition::Any));

        let etag = self
            .put_object_cas(
                &bucket,
                &key,
                Bytes::from(buf),
                if_match_str.as_deref(),
                if_none_match_any,
            )
            .await
            .map_err(|e| {
                if e.downcast_ref::<CasConflictError>().is_some() {
                    s3_error!(PreconditionFailed, "{}", e)
                } else {
                    s3_error!(InternalError, "{}", e)
                }
            })?;

        Ok(S3Response::new(PutObjectOutput {
            e_tag: Some(ETag::Strong(etag)),
            ..Default::default()
        }))
    }

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        let meta = self
            .head_object(&req.input.bucket, &req.input.key)
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?
            .ok_or_else(|| s3_error!(NoSuchKey, "Object not found"))?;

        let data = self
            .get_object(&req.input.bucket, &req.input.key)
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?
            .ok_or_else(|| s3_error!(NoSuchKey, "Object not found"))?;

        Ok(S3Response::new(GetObjectOutput {
            body: Some(StreamingBlob::from_bytes(data)),
            content_length: Some(meta.size as i64),
            e_tag: Some(ETag::Strong(meta.etag)),
            ..Default::default()
        }))
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        let meta = self
            .head_object(&req.input.bucket, &req.input.key)
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?
            .ok_or_else(|| s3_error!(NoSuchKey, "Object not found"))?;

        Ok(S3Response::new(HeadObjectOutput {
            content_length: Some(meta.size as i64),
            e_tag: Some(ETag::Strong(meta.etag)),
            ..Default::default()
        }))
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.delete_object(&req.input.bucket, &req.input.key)
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?;
        Ok(S3Response::new(DeleteObjectOutput::default()))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let items = self
            .list_objects(&req.input.bucket, req.input.prefix.as_deref())
            .await
            .map_err(|e| s3_error!(InternalError, "{}", e))?;
        let count = items.len() as i32;
        let contents = items
            .into_iter()
            .map(|m| S3Object {
                key: Some(m.key),
                size: Some(m.size as i64),
                e_tag: Some(ETag::Strong(m.etag)),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(ListObjectsV2Output {
            name: Some(req.input.bucket),
            prefix: req.input.prefix,
            key_count: Some(count),
            contents: Some(contents),
            ..Default::default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hrw_placement_is_deterministic_and_bounded() {
        let peers = vec![
            "node-a".to_string(),
            "node-b".to_string(),
            "node-c".to_string(),
            "node-d".to_string(),
        ];
        let first = select_hrw_replicas("bucket/cell-1", &peers, 3);
        let second = select_hrw_replicas("bucket/cell-1", &peers, 3);
        assert_eq!(first, second);
        assert_eq!(first.len(), 3);
    }

    #[test]
    fn blob_bridge_crud_and_cas() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_stack_size(16 * 1024 * 1024)
                    .build()
                    .unwrap();
                rt.block_on(Box::pin(async {
        let db = Arc::new(Database::open_mem());
        let bridge = BlobBridge::new(db).await.unwrap();

        bridge.create_bucket("cells").await.unwrap();
        assert!(bridge.list_buckets().await.unwrap().contains(&"cells".to_string()));

        // If-None-Match: * succeeds on first write, conflicts on second
        let etag = bridge
            .put_object_cas("cells", "doc-1", Bytes::from_static(b"v1"), None, true)
            .await
            .unwrap();
        assert!(bridge
            .put_object_cas("cells", "doc-1", Bytes::from_static(b"v2"), None, true)
            .await
            .is_err());

        // Wrong If-Match fails; matching If-Match succeeds
        assert!(bridge
            .put_object_cas("cells", "doc-1", Bytes::from_static(b"v2"), Some("bad-etag"), false)
            .await
            .is_err());
        let etag2 = bridge
            .put_object_cas("cells", "doc-1", Bytes::from_static(b"v2"), Some(&etag), false)
            .await
            .unwrap();
        assert_ne!(etag, etag2);

        let fetched = bridge.get_object("cells", "doc-1").await.unwrap().unwrap();
        assert_eq!(fetched.as_ref(), b"v2");

        let listed = bridge.list_objects("cells", Some("doc-")).await.unwrap();
        assert_eq!(listed.len(), 1);

        bridge.delete_object("cells", "doc-1").await.unwrap();
        assert!(bridge.get_object("cells", "doc-1").await.unwrap().is_none());
                }));
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
