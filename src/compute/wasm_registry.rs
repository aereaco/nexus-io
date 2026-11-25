use anyhow::{anyhow, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::compute::crystal::CrystalEngine;
use crate::storage::BlobBridge;

pub const RUNTIMES_BUCKET: &str = "nexus-runtimes";

/// Metadata for a registered WASI guest runtime (e.g. `quickjs`, `php-cgi`, `sqlite`, `pglite`, `duckdb`, `nexus-db`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeRecord {
    pub name: String,
    pub cid: String,
    pub size_bytes: usize,
    pub aot_cached: bool,
}

/// Resolved executable artifact ready for `CrystalEngine`.
#[derive(Debug, Clone)]
pub enum ResolvedRuntime {
    /// Pre-compiled native `.cwasm` artifact (sub-millisecond instantiation, iOS `W^X` safe).
    Aot(Vec<u8>),
    /// Raw `.wasm` or `.wat` module bytes (compiled via Cranelift on non-iOS).
    Wasm(Vec<u8>),
}

/// Content-addressed registry of WASI guest runtimes stored in `BlobBridge` with automatic
/// AOT `.cwasm` precompilation. Powers `quickjs.wasm`, `php-cgi.wasm`, `sqlite.wasm`, `pglite.wasm`,
/// `duckdb.wasm`, and custom polyglot cell runtimes without bloating the host binary.
#[derive(Clone)]
pub struct WasmRuntimeRegistry {
    blobs: Arc<BlobBridge>,
    index: Arc<RwLock<BTreeMap<String, RuntimeRecord>>>,
}

impl WasmRuntimeRegistry {
    pub fn new(blobs: Arc<BlobBridge>) -> Self {
        Self {
            blobs,
            index: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Register a `.wasm` or `.wat` guest runtime under `name` (e.g. `"quickjs"`, `"php-cgi"`, `"sqlite"`),
    /// store it content-addressed in `BlobBridge`, and pre-compile an AOT `.cwasm` artifact on non-iOS.
    pub async fn register_runtime(&self, name: &str, wasm_or_wat: &[u8]) -> Result<RuntimeRecord> {
        let norm = name.trim().to_ascii_lowercase();
        if norm.is_empty() {
            anyhow::bail!("Runtime name cannot be empty");
        }
        let _ = self.blobs.create_bucket(RUNTIMES_BUCKET).await;

        let cid = blake3::hash(wasm_or_wat).to_hex().to_string();
        let raw_bytes = Bytes::copy_from_slice(wasm_or_wat);
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("raw/{}.wasm", norm), raw_bytes.clone())
            .await?;
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("cid/{}", cid), raw_bytes)
            .await?;

        #[cfg(not(target_os = "ios"))]
        let aot_cached = {
            let input = wasm_or_wat.to_vec();
            let compiled = tokio::task::spawn_blocking(move || {
                let crystal = CrystalEngine::new()?;
                crystal.compile_aot(&input)
            })
            .await??;
            let aot_bytes = Bytes::from(compiled);
            self.blobs
                .put_object(RUNTIMES_BUCKET, &format!("aot/{}.cwasm", norm), aot_bytes.clone())
                .await?;
            self.blobs
                .put_object(RUNTIMES_BUCKET, &format!("aot-cid/{}.cwasm", cid), aot_bytes)
                .await?;
            true
        };

        #[cfg(target_os = "ios")]
        let aot_cached = false;

        let rec = RuntimeRecord {
            name: norm.clone(),
            cid,
            size_bytes: wasm_or_wat.len(),
            aot_cached,
        };
        self.index.write().await.insert(norm, rec.clone());
        Ok(rec)
    }

    /// Register a pre-compiled AOT `.cwasm` runtime directly (used on iOS or when shipping pre-compiled artifacts).
    pub async fn register_aot_runtime(&self, name: &str, aot_bytes: &[u8]) -> Result<RuntimeRecord> {
        let norm = name.trim().to_ascii_lowercase();
        let _ = self.blobs.create_bucket(RUNTIMES_BUCKET).await;
        let cid = blake3::hash(aot_bytes).to_hex().to_string();
        let bytes = Bytes::copy_from_slice(aot_bytes);
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("aot/{}.cwasm", norm), bytes.clone())
            .await?;
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("aot-cid/{}.cwasm", cid), bytes)
            .await?;

        let rec = RuntimeRecord {
            name: norm.clone(),
            cid,
            size_bytes: aot_bytes.len(),
            aot_cached: true,
        };
        self.index.write().await.insert(norm, rec.clone());
        Ok(rec)
    }

    /// Resolve a runtime by logical name (e.g. `"quickjs"`, `"sqlite"`) or BLAKE3 CID.
    /// Prefers pre-compiled AOT `.cwasm` from `BlobBridge`, falling back to raw `.wasm` in `BlobBridge`
    /// or local disk (`NEXUS_RUNTIMES_DIR` / `./runtimes/<name>.wasm`).
    pub async fn resolve_runtime(&self, name_or_cid: &str) -> Result<ResolvedRuntime> {
        let key = name_or_cid.trim().to_ascii_lowercase();

        // 1. Prefer pre-compiled AOT `.cwasm` (by name or CID)
        for aot_key in [format!("aot/{}.cwasm", key), format!("aot-cid/{}.cwasm", key)] {
            if let Some(bytes) = self.blobs.get_object(RUNTIMES_BUCKET, &aot_key).await? {
                return Ok(ResolvedRuntime::Aot(bytes.to_vec()));
            }
        }

        // 2. Fallback to raw `.wasm` in BlobBridge (by name or CID)
        for raw_key in [format!("raw/{}.wasm", key), format!("cid/{}", key)] {
            if let Some(bytes) = self.blobs.get_object(RUNTIMES_BUCKET, &raw_key).await? {
                return Ok(ResolvedRuntime::Wasm(bytes.to_vec()));
            }
        }

        // 3. Optional local filesystem fallback (`NEXUS_RUNTIMES_DIR/<name>.wasm` or `./runtimes/<name>.wasm`)
        let base_dir = std::env::var("NEXUS_RUNTIMES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("runtimes"));
        let disk_cwasm = base_dir.join(format!("{}.cwasm", key));
        if let Ok(bytes) = tokio::fs::read(&disk_cwasm).await {
            return Ok(ResolvedRuntime::Aot(bytes));
        }
        let disk_wasm = base_dir.join(format!("{}.wasm", key));
        if let Ok(bytes) = tokio::fs::read(&disk_wasm).await {
            return Ok(ResolvedRuntime::Wasm(bytes));
        }

        Err(anyhow!(
            "WASI runtime '{}' is not registered. Upload via `PUT /cells/_runtimes/{}` or place `{}.wasm` in `{}`.",
            name_or_cid,
            key,
            key,
            base_dir.display()
        ))
    }

    pub async fn list_runtimes(&self) -> Vec<RuntimeRecord> {
        self.index.read().await.values().cloned().collect()
    }
}
