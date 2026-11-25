use anyhow::Result;
use bytes::Bytes;
use serde_json::Value as JsonValue;
use std::sync::Arc;

use crate::compute::crystal::{CrystalEngine, WasiRunConfig};
use crate::compute::wasm_registry::{ResolvedRuntime, WasmRuntimeRegistry};
use crate::storage::BlobBridge;

pub const WASM_DB_BUCKET: &str = "nexus-wasm-db";

/// Executes queries against a Wasmtime-hosted database engine (`CellDbMode::WasmEngine`, e.g.
/// `sqlite.wasm`, `pglite.wasm`, `duckdb.wasm`, `nexus-db.wasm`) with automatic virtual filesystem
/// hydration and persistence backed by `BlobBridge`.
///
/// Every Wasm DB engine sees a capability-scoped directory mounted at `mount_path` (e.g. `/data`),
/// receives `NEXUS_DB_ENGINE`, `NEXUS_DB_FLAVOR`, `NEXUS_DB_QUERY`, `NEXUS_DB_MOUNT`, and the query
/// payload on `stdin`, and returns JSON results on `stdout`.
pub struct WasmDbMount;

impl WasmDbMount {
    /// Execute a query against a Wasm-hosted DB engine for `(app, cell_id)`, hydrating persisted
    /// state from `BlobBridge` before execution and flushing modified state back afterward.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_query(
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
        // Resolve the Wasm DB engine by CID first, falling back to logical engine name
        let resolved = match registry.resolve_runtime(module_cid).await {
            Ok(r) => r,
            Err(_) => registry.resolve_runtime(engine_name).await?,
        };

        // Hydrate scoped virtual DB workspace from BlobBridge
        let _ = blobs.create_bucket(WASM_DB_BUCKET).await;
        let state_key = format!("cells/{}/{}/state.bin", app, cell_id);
        let work_dir = std::env::temp_dir().join(format!(
            "nexus_wasmdb_{}_{}_{}",
            sanitize(app),
            sanitize(cell_id),
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::create_dir_all(&work_dir).await?;
        let state_file = work_dir.join("state.bin");
        if let Some(existing) = blobs.get_object(WASM_DB_BUCKET, &state_key).await? {
            tokio::fs::write(&state_file, &existing).await?;
        }

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

        let out = tokio::task::spawn_blocking(move || -> Result<_> {
            let crystal = CrystalEngine::new()?;
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
        .await??;

        // Flush updated DB state file back into BlobBridge for elastic hibernation & mesh sync
        if let Ok(updated) = tokio::fs::read(&state_file).await {
            let _ = blobs
                .put_object(WASM_DB_BUCKET, &state_key, Bytes::from(updated))
                .await;
        }
        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        if out.exit_code != 0 {
            let err_msg = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!(
                "Wasm DB engine '{}' exited with code {}: {}",
                engine_name,
                out.exit_code,
                err_msg.trim()
            );
        }

        let stdout_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stdout_str.is_empty() {
            Ok(JsonValue::Array(Vec::new()))
        } else {
            Ok(serde_json::from_str(&stdout_str).unwrap_or(JsonValue::String(stdout_str)))
        }
    }

    /// Snapshot/export the current Wasm DB state blob for `(app, cell_id)` from `BlobBridge`.
    pub async fn export_state(blobs: &Arc<BlobBridge>, app: &str, cell_id: &str) -> Result<Option<Bytes>> {
        let state_key = format!("cells/{}/{}/state.bin", app, cell_id);
        blobs.get_object(WASM_DB_BUCKET, &state_key).await
    }

    /// Import a Wasm DB state blob for `(app, cell_id)` into `BlobBridge` (e.g. during mesh sync).
    pub async fn import_state(
        blobs: &Arc<BlobBridge>,
        app: &str,
        cell_id: &str,
        data: Bytes,
    ) -> Result<()> {
        let _ = blobs.create_bucket(WASM_DB_BUCKET).await;
        let state_key = format!("cells/{}/{}/state.bin", app, cell_id);
        blobs.put_object(WASM_DB_BUCKET, &state_key, data).await?;
        Ok(())
    }
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

        // Minimal WASI DB guest module (protocol-compatible with sqlite.wasm / pglite.wasm)
        // writing a JSON query result to stdout via `fd_write(1, ...)`
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

        let result = WasmDbMount::execute_query(
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
}
