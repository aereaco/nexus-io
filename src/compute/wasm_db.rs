use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::compute::crystal::{CrystalEngine, WasiRunConfig};
use crate::compute::wasm_registry::{ResolvedRuntime, WasmRuntimeRegistry};
use crate::storage::cas_store::DEFAULT_EXECUTION_LEASE_TTL_MS;
use crate::storage::{BlobBridge, CasStore};

pub const WASM_DB_BUCKET: &str = "nexus-wasm-db";

/// Multi-file virtual filesystem manifest persisted per `(app, cell_id)` in `BlobBridge`.
/// Carries a monotonic `fencing_token` from the distributed `ExecutionLease` so stale writers
/// that paused past lease expiry are strictly rejected at commit time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmDbFsManifest {
    pub version: u64,
    #[serde(default)]
    pub fencing_token: u64,
    /// Relative POSIX path inside `mount_path` (e.g. `"main.db"`, `"main.db-wal"`, `"pgdata/PG_VERSION"`)
    /// mapped to its content-addressed BLAKE3 CID in `BlobBridge`.
    pub files: BTreeMap<String, String>,
}

/// Production-grade Wasmtime-hosted database mount for `CellDbMode::WasmEngine`
/// (`sqlite.wasm`, `pglite.wasm`, `duckdb.wasm`, `nexus-db.wasm`):
/// - Reuses a single shared `Arc<CrystalEngine>` (with compiled `Module` caching) — never recreates
///   a Wasmtime `Engine` per query.
/// - Serializes concurrent read/modify/write queries per `(app, cell_id)` via an async mutex.
/// - Hydrates and atomically commits the entire multi-file virtual directory tree (DB + WAL + journals)
///   to `BlobBridge`, strictly propagating all persistence errors (never silently dropping writes).
#[derive(Clone)]
pub struct WasmDbMount {
    crystal: Arc<CrystalEngine>,
    cell_locks: Arc<RwLock<HashMap<(String, String), Arc<Mutex<()>>>>>,
}

impl WasmDbMount {
    pub fn new(crystal: Arc<CrystalEngine>) -> Self {
        Self {
            crystal,
            cell_locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn cell_lock(&self, app: &str, cell_id: &str) -> Arc<Mutex<()>> {
        let key = (app.to_string(), cell_id.to_string());
        if let Some(lock) = self.cell_locks.read().await.get(&key).cloned() {
            return lock;
        }
        let mut guard = self.cell_locks.write().await;
        // Bounded lock map hygiene: evict uncontended locks when map exceeds 256 entries
        if guard.len() >= 256 {
            guard.retain(|_, v| Arc::strong_count(v) > 1);
        }
        guard
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Explicitly evict uncontended per-cell locks (called on cell hibernation/cleanup).
    pub async fn evict_idle_locks(&self) -> usize {
        let mut guard = self.cell_locks.write().await;
        let before = guard.len();
        guard.retain(|_, v| Arc::strong_count(v) > 1);
        before.saturating_sub(guard.len())
    }

    /// Read the current multi-file manifest for `(app, cell_id)` from `BlobBridge`.
    pub async fn read_manifest(
        blobs: &Arc<BlobBridge>,
        app: &str,
        cell_id: &str,
    ) -> Result<WasmDbFsManifest> {
        let manifest_key = format!("cells/{}/{}/manifest.json", app, cell_id);
        match blobs.get_object(WASM_DB_BUCKET, &manifest_key).await? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("Corrupted WasmDbFsManifest for {}/{}", app, cell_id)),
            None => Ok(WasmDbFsManifest::default()),
        }
    }

    /// Execute a query against a Wasm-hosted DB engine for `(app, cell_id)` with:
    /// 1. Per-cell serialization lock (preventing concurrent read/modify/write races),
    /// 2. Full multi-file directory hydration from `BlobBridge`,
    /// 3. Shared `CrystalEngine` execution with fuel metering,
    /// 4. Strict multi-file flush & atomic manifest commit back to `BlobBridge`.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_query(
        &self,
        blobs: &Arc<BlobBridge>,
        registry: &WasmRuntimeRegistry,
        app: &str,
        cell_id: &str,
        engine_name: &str,
        module_cid: &str,
        mount_path: &str,
        flavor: &str,
        query: &str,
        fuel_limit: u64,
    ) -> Result<JsonValue> {
        // 1. Serialize in-process concurrency AND acquire distributed fenced ExecutionLease
        //    covering the entire hydrate -> execute -> persist cycle across processes/nodes.
        let lock = self.cell_lock(app, cell_id).await;
        let _guard = lock.lock().await;

        let cas = CasStore::new(blobs.clone());
        let lease_key = format!("leases/wasmdb/{}/{}.lease.json", app, cell_id);
        let holder = format!("{}:{}", blobs.node_id(), uuid::Uuid::new_v4().simple());
        let lease = cas
            .acquire_execution_lease(
                WASM_DB_BUCKET,
                &lease_key,
                &holder,
                DEFAULT_EXECUTION_LEASE_TTL_MS,
            )
            .await?;

        // Background lease heartbeat renewal (every ttl / 3) for long-running queries
        let hb_cas = cas.clone();
        let hb_key = lease_key.clone();
        let hb_holder = holder.clone();
        let hb_token = lease.fencing_token;
        let hb_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(
                DEFAULT_EXECUTION_LEASE_TTL_MS / 3,
            ));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if hb_cas
                    .renew_execution_lease(
                        WASM_DB_BUCKET,
                        &hb_key,
                        &hb_holder,
                        hb_token,
                        DEFAULT_EXECUTION_LEASE_TTL_MS,
                    )
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let exec_result = self
            .execute_query_under_lease(
                &cas,
                registry,
                app,
                cell_id,
                engine_name,
                module_cid,
                mount_path,
                flavor,
                query,
                fuel_limit,
                lease.fencing_token,
            )
            .await;

        hb_task.abort();
        let _ = cas
            .release_execution_lease(WASM_DB_BUCKET, &lease_key, &holder, lease.fencing_token)
            .await;
        exec_result
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_query_under_lease(
        &self,
        cas: &CasStore,
        registry: &WasmRuntimeRegistry,
        app: &str,
        cell_id: &str,
        engine_name: &str,
        module_cid: &str,
        mount_path: &str,
        flavor: &str,
        query: &str,
        fuel_limit: u64,
        fencing_token: u64,
    ) -> Result<JsonValue> {
        // 2. Resolve Wasm/AOT DB engine module
        let resolved = match registry.resolve_runtime(module_cid).await {
            Ok(r) => r,
            Err(_) => registry.resolve_runtime(engine_name).await?,
        };

        // 3. Hydrate entire multi-file virtual directory tree via shared CasStore (BLAKE3 verified)
        let manifest_key = format!("cells/{}/{}/manifest.json", app, cell_id);
        let (prev_manifest, prev_etag) = match cas.read_manifest::<WasmDbFsManifest>(WASM_DB_BUCKET, &manifest_key).await? {
            Some((m, etag)) => (m, Some(etag)),
            None => (WasmDbFsManifest::default(), None),
        };
        // Reject stale fenced writers immediately
        if fencing_token < prev_manifest.fencing_token {
            anyhow::bail!(
                "Fenced out: lease fencing_token {} < manifest fencing_token {} for {}/{}",
                fencing_token,
                prev_manifest.fencing_token,
                app,
                cell_id
            );
        }
        let work_dir = std::env::temp_dir().join(format!(
            "nexus_wasmdb_{}_{}_{}",
            sanitize(app),
            sanitize(cell_id),
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::create_dir_all(&work_dir).await?;

        for (rel_path, cid) in &prev_manifest.files {
            let dest = safe_join(&work_dir, rel_path)?;
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let data = cas
                .get_verified_blob(WASM_DB_BUCKET, "blobs/", cid)
                .await
                .with_context(|| {
                    format!(
                        "Failed to hydrate verified Wasm DB file '{}' (cid={}) for {}/{}",
                        rel_path, cid, app, cell_id
                    )
                })?;
            tokio::fs::write(&dest, &data).await?;
        }

        // 4. Execute WASI DB engine on the shared `CrystalEngine` (with Module cache)
        let mount = if mount_path.is_empty() {
            "/data".to_string()
        } else {
            mount_path.to_string()
        };
        let cfg = WasiRunConfig {
            args: vec![format!("{}.wasm", engine_name)],
            env: vec![
                ("NEXUS_DB_ENGINE".to_string(), engine_name.to_string()),
                ("NEXUS_DB_FLAVOR".to_string(), flavor.to_string()),
                ("NEXUS_DB_QUERY".to_string(), query.to_string()),
                ("NEXUS_DB_MOUNT".to_string(), mount.clone()),
                ("NEXUS_CELL_APP".to_string(), app.to_string()),
                ("NEXUS_CELL_ID".to_string(), cell_id.to_string()),
            ],
            stdin: query.as_bytes().to_vec(),
            preopen_dirs: vec![(work_dir.clone(), mount, true)],
            fuel_limit,
        };

        let crystal = self.crystal.clone();
        let exec_res = tokio::task::spawn_blocking(move || -> Result<_> {
            match resolved {
                ResolvedRuntime::Aot(aot) => crystal.run_wasi_p1_aot(&aot, cfg),
                #[cfg(not(target_os = "ios"))]
                ResolvedRuntime::Wasm(wasm) => crystal.run_wasi_p1(&wasm, cfg),
                #[cfg(target_os = "ios")]
                ResolvedRuntime::Wasm(_) => {
                    Err(anyhow!("iOS requires AOT pre-compiled .cwasm DB runtime"))
                }
            }
        })
        .await;

        let out = match exec_res {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
                return Err(e);
            }
            Err(join_err) => {
                let _ = tokio::fs::remove_dir_all(&work_dir).await;
                return Err(anyhow!("Wasm DB worker panicked: {}", join_err));
            }
        };

        if out.exit_code != 0 {
            let _ = tokio::fs::remove_dir_all(&work_dir).await;
            let err_msg = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!(
                "Wasm DB engine '{}' exited with code {}: {}",
                engine_name,
                out.exit_code,
                err_msg.trim()
            );
        }

        // 5. Walk workspace, store verified immutable blobs, and atomically commit manifest via CAS.
        // Coordinates safely across processes/nodes; every persistence error is strictly propagated.
        let commit_res: Result<()> = async {
            let walked = collect_dir_files(&work_dir, &work_dir).await?;
            let mut next_files = BTreeMap::new();
            for (rel_path, full_path) in walked {
                let bytes = tokio::fs::read(&full_path).await?;
                let cid = cas
                    .put_verified_blob(WASM_DB_BUCKET, "blobs/", Bytes::from(bytes))
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to persist Wasm DB file '{}' for {}/{}",
                            rel_path, app, cell_id
                        )
                    })?;
                next_files.insert(rel_path, cid);
            }

            let next_manifest = WasmDbFsManifest {
                version: prev_manifest.version + 1,
                fencing_token,
                files: next_files,
            };
            cas.commit_manifest_cas(
                WASM_DB_BUCKET,
                &manifest_key,
                &next_manifest,
                prev_etag.as_deref(),
            )
            .await
            .with_context(|| {
                format!(
                    "Atomic CAS commit failed for WasmDbFsManifest v{} ({}/{})",
                    next_manifest.version, app, cell_id
                )
            })?;

            // Single-CAS atomic ownership transfer: propagate errors (never ignore bookkeeping failures)
            let owner_id = format!("wasmdb:{}/{}", app, cell_id);
            let prev_cids: std::collections::HashSet<String> =
                prev_manifest.files.values().cloned().collect();
            let next_cids: std::collections::HashSet<String> =
                next_manifest.files.values().cloned().collect();
            cas.transfer_manifest_ownership(
                WASM_DB_BUCKET,
                "blobs/",
                &owner_id,
                &prev_cids,
                &next_cids,
            )
            .await
            .with_context(|| {
                format!(
                    "Atomic ownership transfer failed for WasmDbFsManifest v{} ({}/{})",
                    next_manifest.version, app, cell_id
                )
            })?;
            Ok(())
        }
        .await;

        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        commit_res?;

        let stdout_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stdout_str.is_empty() {
            Ok(JsonValue::Array(Vec::new()))
        } else {
            Ok(serde_json::from_str(&stdout_str).unwrap_or(JsonValue::String(stdout_str)))
        }
    }
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => anyhow::bail!("Illegal path component in Wasm DB manifest: '{}'", rel),
        }
    }
    Ok(out)
}

fn collect_dir_files<'a>(
    root: &'a Path,
    dir: &'a Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<(String, PathBuf)>>> + Send + 'a>> {
    Box::pin(async move {
        let mut results = Vec::new();
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let meta = entry.metadata().await?;
            if meta.is_dir() {
                results.extend(collect_dir_files(root, &path).await?);
            } else if meta.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| anyhow!("Strip prefix error: {}", e))?
                    .to_string_lossy()
                    .replace('\\', "/");
                results.push((rel, path));
            }
        }
        Ok(results)
    })
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test(flavor = "multi_thread")]
    async fn wasm_db_mount_executes_aot_db_engine_and_returns_json() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let registry = WasmRuntimeRegistry::new(blobs.clone());
        let mount = WasmDbMount::new(Arc::new(CrystalEngine::new().unwrap()));

        let db_engine_wat = br#"
            (module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 16) "[{\"engine\":\"pglite-wasm\",\"ok\":true}]")
                (func (export "_start")
                    (i32.store (i32.const 0) (i32.const 16))
                    (i32.store (i32.const 4) (i32.const 36))
                    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                )
            )
        "#;

        let rec = registry.register_runtime("pglite", db_engine_wat).await.unwrap();
        assert!(rec.aot_cached);

        let result = mount
            .execute_query(
                &blobs,
                &registry,
                "shop",
                "orders",
                "pglite",
                &rec.cid,
                "/data",
                "postgres",
                "SELECT 1",
                1_000_000,
            )
            .await
            .unwrap();

        assert_eq!(result[0]["engine"], "pglite-wasm");
        assert_eq!(result[0]["ok"], true);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wasm_db_mount_survives_concurrent_queries_multi_file_wal_and_restart_recovery() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let registry = WasmRuntimeRegistry::new(blobs.clone());
        let mount = WasmDbMount::new(Arc::new(CrystalEngine::new().unwrap()));

        // Real WASI Preview 1 multi-file stateful DB guest:
        // 1. Opens `counter.db` in preopened dir fd=3 (O_CREAT), reads 1-byte counter (default 0),
        //    increments it by 1, rewrites `counter.db` (O_TRUNC).
        // 2. Opens `wal.log` in preopened dir fd=3 (O_CREAT | FD_APPEND), appends 1 byte ('W').
        // 3. Writes the ASCII digit of the new counter value to stdout.
        let stateful_db_wat = br#"
            (module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_read"
                    (func $fd_read (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_close"
                    (func $fd_close (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 100) "counter.db")
                (data (i32.const 120) "wal.log")
                (data (i32.const 140) "W")
                (func (export "_start")
                    (local $fd i32)
                    (local $cnt i32)
                    ;; 1. Open counter.db for read (oflags=1 O_CREAT, rights_base=0x42 READ|WRITE)
                    (drop (call $path_open
                        (i32.const 3) (i32.const 0)
                        (i32.const 100) (i32.const 10)
                        (i32.const 1) (i64.const 66) (i64.const 66) (i32.const 0)
                        (i32.const 200)))
                    (local.set $fd (i32.load (i32.const 200)))
                    ;; Read 1 byte into offset 210
                    (i32.store8 (i32.const 210) (i32.const 0))
                    (i32.store (i32.const 0) (i32.const 210))
                    (i32.store (i32.const 4) (i32.const 1))
                    (drop (call $fd_read (local.get $fd) (i32.const 0) (i32.const 1) (i32.const 204)))
                    (drop (call $fd_close (local.get $fd)))
                    (local.set $cnt (i32.add (i32.load8_u (i32.const 210)) (i32.const 1)))

                    ;; 2. Re-open counter.db with O_CREAT|O_TRUNC (oflags=9) and write new count byte
                    (drop (call $path_open
                        (i32.const 3) (i32.const 0)
                        (i32.const 100) (i32.const 10)
                        (i32.const 9) (i64.const 66) (i64.const 66) (i32.const 0)
                        (i32.const 200)))
                    (local.set $fd (i32.load (i32.const 200)))
                    (i32.store8 (i32.const 210) (local.get $cnt))
                    (i32.store (i32.const 0) (i32.const 210))
                    (i32.store (i32.const 4) (i32.const 1))
                    (drop (call $fd_write (local.get $fd) (i32.const 0) (i32.const 1) (i32.const 204)))
                    (drop (call $fd_close (local.get $fd)))

                    ;; 3. Open wal.log with O_CREAT (oflags=1) and FD_APPEND (fdflags=1), append 'W'
                    (drop (call $path_open
                        (i32.const 3) (i32.const 0)
                        (i32.const 120) (i32.const 7)
                        (i32.const 1) (i64.const 66) (i64.const 66) (i32.const 1)
                        (i32.const 200)))
                    (local.set $fd (i32.load (i32.const 200)))
                    (i32.store (i32.const 0) (i32.const 140))
                    (i32.store (i32.const 4) (i32.const 1))
                    (drop (call $fd_write (local.get $fd) (i32.const 0) (i32.const 1) (i32.const 204)))
                    (drop (call $fd_close (local.get $fd)))

                    ;; 4. Write ASCII count digit ('0' + cnt) to stdout
                    (i32.store8 (i32.const 220) (i32.add (i32.const 48) (local.get $cnt)))
                    (i32.store (i32.const 0) (i32.const 220))
                    (i32.store (i32.const 4) (i32.const 1))
                    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 204)))
                )
            )
        "#;

        let rec = registry
            .register_runtime("sqlite-stateful", stateful_db_wat)
            .await
            .unwrap();

        // Fire 8 concurrent queries against the exact same cell DB
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = mount.clone();
            let b = blobs.clone();
            let r = registry.clone();
            let cid = rec.cid.clone();
            handles.push(tokio::spawn(async move {
                m.execute_query(
                    &b,
                    &r,
                    "ledger",
                    "acct_1",
                    "sqlite-stateful",
                    &cid,
                    "/data",
                    "sqlite",
                    "UPDATE counter SET n = n + 1",
                    5_000_000,
                )
                .await
                .unwrap()
            }));
        }
        let mut seen = Vec::new();
        for h in handles {
            let v = h.await.unwrap();
            seen.push(v.as_i64().unwrap());
        }
        seen.sort();
        // Per-cell mutex guarantees strictly serialized 1..=8 with zero lost updates
        assert_eq!(seen, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        // Verify multi-file manifest persisted BOTH counter.db AND wal.log (with 8 WAL entries)
        let manifest = WasmDbMount::read_manifest(&blobs, "ledger", "acct_1")
            .await
            .unwrap();
        assert_eq!(manifest.version, 8);
        assert!(manifest.files.contains_key("counter.db"));
        let wal_cid = manifest.files.get("wal.log").expect("wal.log persisted");
        let wal_bytes = blobs
            .get_object(WASM_DB_BUCKET, &format!("blobs/{}", wal_cid))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(wal_bytes.len(), 8);

        // Simulate full node restart: brand-new WasmDbMount & WasmRuntimeRegistry over same BlobBridge
        let fresh_registry = WasmRuntimeRegistry::new(blobs.clone());
        let fresh_mount = WasmDbMount::new(Arc::new(CrystalEngine::new().unwrap()));
        let after_restart = fresh_mount
            .execute_query(
                &blobs,
                &fresh_registry,
                "ledger",
                "acct_1",
                "sqlite-stateful",
                &rec.cid,
                "/data",
                "sqlite",
                "UPDATE counter SET n = n + 1",
                5_000_000,
            )
            .await
            .unwrap();
        assert_eq!(after_restart.as_i64(), Some(9));
    }
}
