use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use nexus_db::Value as DbValue;
use tokio::sync::RwLock;

use crate::db::sql_compiler::execute_unified_query;
use crate::db::StateEngine;
use crate::storage::BlobBridge;

/// Connection / transport methods allowed to reach a cell's database instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellDbTransport {
    Internal,
    HttpRest,
    WebSocketRpc,
    PgWire,
    MySqlWire,
    SqliteHrana,
    MeshWal,
}

/// Replication role when a cell's DB binds into the multi-node scaling mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshDbRole {
    Leader,
    Follower,
    ReadReplica,
}

/// Declarative per-cell database topology: stateless, dedicated, cross-cell reference, or scaling mesh.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellDbMode {
    /// Stateless cell — zero DB allocation or exposure.
    None,
    /// Dedicated isolated `(app, cell_id)` `nexus-db` instance.
    Dedicated,
    /// Shared reference to another app cell's DB instance.
    Reference {
        target_app: String,
        target_cell_id: String,
        read_only: bool,
    },
    /// Bound into the multi-node database scaling mesh (`ReplicationLog` WAL).
    Mesh {
        cluster: String,
        target_app: String,
        target_cell_id: String,
        role: MeshDbRole,
    },
    /// Database engine itself runs inside Wasmtime (e.g. `pglite.wasm`, `sqlite.wasm`, `duckdb.wasm`,
    /// or sandboxed `nexus-db.wasm`) backed by `BlobBridge` virtual storage.
    WasmEngine {
        engine: String,
        module_cid: String,
        mount_path: String,
    },
}

/// Unified per-cell declarative database configuration governing topology (`mode`),
/// exposed query `flavors`, and allowed connection methods (`transports`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CellDbConfig {
    pub mode: CellDbMode,
    pub flavors: Vec<String>,
    pub transports: Vec<CellDbTransport>,
}

impl Default for CellDbConfig {
    fn default() -> Self {
        Self::dedicated_full()
    }
}

impl CellDbConfig {
    pub fn stateless() -> Self {
        Self {
            mode: CellDbMode::None,
            flavors: Vec::new(),
            transports: Vec::new(),
        }
    }

    pub fn dedicated_minimal() -> Self {
        Self {
            mode: CellDbMode::Dedicated,
            flavors: vec!["surql".into(), "kv".into()],
            transports: vec![CellDbTransport::Internal],
        }
    }

    pub fn dedicated_full() -> Self {
        Self {
            mode: CellDbMode::Dedicated,
            flavors: vec![
                "surql".into(),
                "sqlite".into(),
                "postgres".into(),
                "mysql".into(),
                "graphql".into(),
                "gql".into(),
                "kv".into(),
            ],
            transports: vec![
                CellDbTransport::Internal,
                CellDbTransport::HttpRest,
                CellDbTransport::WebSocketRpc,
                CellDbTransport::PgWire,
                CellDbTransport::MySqlWire,
                CellDbTransport::SqliteHrana,
                CellDbTransport::MeshWal,
            ],
        }
    }

    pub fn reference(target_app: impl Into<String>, target_cell_id: impl Into<String>, read_only: bool) -> Self {
        Self {
            mode: CellDbMode::Reference {
                target_app: target_app.into(),
                target_cell_id: target_cell_id.into(),
                read_only,
            },
            flavors: vec!["surql".into(), "sqlite".into(), "postgres".into(), "mysql".into(), "graphql".into(), "gql".into()],
            transports: vec![CellDbTransport::Internal, CellDbTransport::HttpRest],
        }
    }

    pub fn mesh(
        cluster: impl Into<String>,
        target_app: impl Into<String>,
        target_cell_id: impl Into<String>,
        role: MeshDbRole,
    ) -> Self {
        Self {
            mode: CellDbMode::Mesh {
                cluster: cluster.into(),
                target_app: target_app.into(),
                target_cell_id: target_cell_id.into(),
                role,
            },
            flavors: vec!["surql".into(), "sqlite".into(), "postgres".into(), "mysql".into()],
            transports: vec![
                CellDbTransport::Internal,
                CellDbTransport::HttpRest,
                CellDbTransport::MeshWal,
            ],
        }
    }

    /// Mount a Wasmtime-hosted database engine (e.g. `pglite`, `sqlite`, `duckdb`, `nexus-db`)
    /// backed by `BlobBridge` virtual storage.
    pub fn wasm_engine(
        engine: impl Into<String>,
        module_cid: impl Into<String>,
        flavor: impl Into<String>,
    ) -> Self {
        Self {
            mode: CellDbMode::WasmEngine {
                engine: engine.into(),
                module_cid: module_cid.into(),
                mount_path: "/data".to_string(),
            },
            flavors: vec![flavor.into()],
            transports: vec![CellDbTransport::Internal, CellDbTransport::HttpRest],
        }
    }
}

/// Resolved target `(ns, db)` and access constraints returned by `CellManager::resolve_db_binding`.
#[derive(Debug, Clone)]
pub struct ResolvedDbBinding {
    pub target_ns: String,
    pub target_db: String,
    pub read_only: bool,
    pub mesh_cluster: Option<String>,
}

/// Lifecycle policy governing a scoped `(Namespace, Database)` cell on the unified Nexus-IO kernel.
#[derive(Debug, Clone)]
pub enum CellPolicy {
    /// Always hot in shared memory (`nexus::system`, IAM, shared catalogs, global Nexus-UX dashboards).
    Pinned,
    /// `celld`-compatible elastic actor: single-writer CAS lease + idle hibernation to `iroh-blobs`.
    Elastic {
        idle_timeout: Duration,
        lease_bucket: String,
    },
}

impl CellPolicy {
    pub fn elastic_default() -> Self {
        Self::Elastic {
            idle_timeout: Duration::from_secs(60),
            lease_bucket: "nexus-cells".to_string(),
        }
    }

    /// Aggressive mobile hibernation preset for iOS Jetsam / Android memory limits.
    pub fn elastic_mobile() -> Self {
        Self::Elastic {
            idle_timeout: Duration::from_secs(10),
            lease_bucket: "nexus-cells".to_string(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CellKey {
    pub app: String,
    pub cell_id: String,
}

/// Universal compute workload executed by a `CellManager` actor.
/// Wasmtime (`WasiModule`, `WasiCgi`, `JsOnWasm`) is the primary microkernel compute primitive;
/// `NativeJs` (`quickrs-core`) is retained as a transitional path during the `quickjs.wasm` migration.
#[derive(Debug, Clone)]
pub enum CellWorkload {
    NativeJs {
        script: String,
    },
    JsOnWasm {
        script: String,
        engine_wasm: Vec<u8>,
        is_aot: bool,
        fuel_limit: u64,
    },
    WasiModule {
        module_bytes: Vec<u8>,
        args: Vec<String>,
        env: Vec<(String, String)>,
        preopen_dirs: Vec<(std::path::PathBuf, String, bool)>,
        fuel_limit: u64,
    },
    WasiCgi {
        module_bytes: Vec<u8>,
        doc_root: Option<std::path::PathBuf>,
        fuel_limit: u64,
    },
}

/// HTTP response returned by `CellManager::invoke_http` for WASI CGI / WASI / JS-on-Wasm cells.
#[derive(Debug, Clone)]
pub struct CellHttpResponse {
    pub status: u16,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Explicit formal cell lifecycle state machine governing every transition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellLifecycleState {
    Declared,
    Provisioning,
    Running,
    Hibernating,
    Hibernated,
    Restoring,
    Failed(String),
}

/// Enforced per-cell execution resource limits (CPU fuel, output cap, concurrency, and deadline).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CellResourceLimits {
    pub max_fuel: u64,
    pub max_output_bytes: usize,
    pub max_concurrent_execs: usize,
    pub deadline_ms: u64,
}

impl Default for CellResourceLimits {
    fn default() -> Self {
        Self {
            max_fuel: 50_000_000,
            max_output_bytes: 4 * 1024 * 1024,
            max_concurrent_execs: 16,
            deadline_ms: 15_000,
        }
    }
}

struct ActiveCell {
    policy: CellPolicy,
    workload: CellWorkload,
    limits: CellResourceLimits,
    exec_permits: Arc<tokio::sync::Semaphore>,
    lease_etag: Option<String>,
    last_active: Instant,
}

/// Unified `CellManager` actor pool supporting both `pinned` and `elastic` (`celld`) cells
/// on top of Wasmtime (`CrystalEngine`, `WasmRuntimeRegistry`, `WasmDbMount`), `StateEngine` (`nexus-db`),
/// and `BlobBridge`, with declarative per-cell `CellDbConfig` (topology mode, query flavors, transports).
#[derive(Clone)]
pub struct CellManager {
    engine: Arc<dyn StateEngine>,
    blobs: Arc<BlobBridge>,
    #[cfg(feature = "runtime-wasm")]
    crystal: Arc<crate::compute::crystal::CrystalEngine>,
    #[cfg(feature = "runtime-wasm")]
    runtimes: crate::compute::wasm_registry::WasmRuntimeRegistry,
    #[cfg(feature = "runtime-wasm")]
    wasm_db: crate::compute::wasm_db::WasmDbMount,
    active: Arc<RwLock<HashMap<CellKey, ActiveCell>>>,
    states: Arc<RwLock<HashMap<CellKey, CellLifecycleState>>>,
    db_configs: Arc<RwLock<HashMap<CellKey, CellDbConfig>>>,
}

const PERSISTED_CELLS_BUCKET: &str = "nexus-cell-workloads";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedWasmWorkload {
    app: String,
    cell_id: String,
    kind: String, // "wasi_module" | "wasi_cgi"
    fuel_limit: u64,
    module_b64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CellSummary {
    pub app: String,
    pub cell_id: String,
    pub state: String,
    pub is_wasm: bool,
}

impl CellManager {
    pub fn new(engine: Arc<dyn StateEngine>, blobs: Arc<BlobBridge>) -> Self {
        #[cfg(feature = "runtime-wasm")]
        let crystal = Arc::new(
            crate::compute::crystal::CrystalEngine::new()
                .expect("failed to initialize shared Wasmtime CrystalEngine"),
        );
        #[cfg(feature = "runtime-wasm")]
        let runtimes = crate::compute::wasm_registry::WasmRuntimeRegistry::new(blobs.clone());
        #[cfg(feature = "runtime-wasm")]
        let wasm_db = crate::compute::wasm_db::WasmDbMount::new(crystal.clone());
        Self {
            engine,
            blobs,
            #[cfg(feature = "runtime-wasm")]
            crystal,
            #[cfg(feature = "runtime-wasm")]
            runtimes,
            #[cfg(feature = "runtime-wasm")]
            wasm_db,
            active: Arc::new(RwLock::new(HashMap::new())),
            states: Arc::new(RwLock::new(HashMap::new())),
            db_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Access the underlying `BlobBridge` for CAS manifest inspection and node identity.
    pub fn blobs(&self) -> &Arc<BlobBridge> {
        &self.blobs
    }

    /// Inspect the current formal lifecycle state of `(app, cell_id)`.
    pub async fn cell_state(&self, app: &str, cell_id: &str) -> CellLifecycleState {
        self.states
            .read()
            .await
            .get(&CellKey {
                app: app.to_string(),
                cell_id: cell_id.to_string(),
            })
            .cloned()
            .unwrap_or(CellLifecycleState::Declared)
    }

    #[cfg(feature = "runtime-wasm")]
    pub fn runtimes(&self) -> &crate::compute::wasm_registry::WasmRuntimeRegistry {
        &self.runtimes
    }

    /// Transactionally declare and persist `CellDbConfig` for `(app, cell_id)`:
    /// writes durably to `BlobBridge` FIRST and only updates in-memory state after persistence succeeds.
    pub async fn set_db_config(&self, app: &str, cell_id: &str, config: CellDbConfig) -> Result<()> {
        let _ = self.blobs.create_bucket("nexus-cells").await;
        let json = serde_json::to_vec(&config)?;
        let key = format!("meta/{}/{}.dbconfig.json", app, cell_id);
        self.blobs
            .put_object("nexus-cells", &key, bytes::Bytes::from(json))
            .await?;

        self.db_configs.write().await.insert(
            CellKey {
                app: app.to_string(),
                cell_id: cell_id.to_string(),
            },
            config,
        );
        Ok(())
    }

    pub async fn get_db_config(&self, app: &str, cell_id: &str) -> CellDbConfig {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };
        if let Some(cfg) = self.db_configs.read().await.get(&key).cloned() {
            return cfg;
        }
        // Hydrate persisted CellDbConfig from BlobBridge after restart
        let blob_key = format!("meta/{}/{}.dbconfig.json", app, cell_id);
        if let Ok(Some(bytes)) = self.blobs.get_object("nexus-cells", &blob_key).await {
            if let Ok(cfg) = serde_json::from_slice::<CellDbConfig>(&bytes) {
                self.db_configs.write().await.insert(key, cfg.clone());
                return cfg;
            }
        }
        CellDbConfig::default()
    }

    /// Single unified authorization & topology resolver for BOTH internal cells and external transports.
    pub async fn resolve_db_binding(
        &self,
        app: &str,
        cell_id: &str,
        transport: CellDbTransport,
        flavor: &str,
    ) -> Result<ResolvedDbBinding> {
        let cfg = self.get_db_config(app, cell_id).await;
        Self::check_db_config(&cfg, app, cell_id, transport, flavor)
    }

    pub fn check_db_config(
        cfg: &CellDbConfig,
        app: &str,
        cell_id: &str,
        transport: CellDbTransport,
        flavor: &str,
    ) -> Result<ResolvedDbBinding> {
        if matches!(cfg.mode, CellDbMode::None) {
            anyhow::bail!("Cell {}/{} is declared stateless (CellDbMode::None)", app, cell_id);
        }
        if !cfg.transports.contains(&transport) {
            anyhow::bail!(
                "Transport {:?} is not enabled in CellDbConfig for {}/{}",
                transport,
                app,
                cell_id
            );
        }
        let norm_flavor = match flavor.trim().to_ascii_lowercase().as_str() {
            "" | "surreal" | "surrealql" => "surql",
            "pg" | "postgresql" => "postgres",
            other => other,
        }
        .to_string();
        if !cfg.flavors.iter().any(|f| f.eq_ignore_ascii_case(&norm_flavor)) {
            anyhow::bail!(
                "Query flavor '{}' is not enabled in CellDbConfig for {}/{}",
                norm_flavor,
                app,
                cell_id
            );
        }
        match &cfg.mode {
            CellDbMode::None => unreachable!(),
            CellDbMode::Dedicated => Ok(ResolvedDbBinding {
                target_ns: app.to_string(),
                target_db: cell_id.to_string(),
                read_only: false,
                mesh_cluster: None,
            }),
            CellDbMode::Reference {
                target_app,
                target_cell_id,
                read_only,
            } => Ok(ResolvedDbBinding {
                target_ns: target_app.clone(),
                target_db: target_cell_id.clone(),
                read_only: *read_only,
                mesh_cluster: None,
            }),
            CellDbMode::Mesh {
                cluster,
                target_app,
                target_cell_id,
                role,
            } => Ok(ResolvedDbBinding {
                target_ns: target_app.clone(),
                target_db: target_cell_id.clone(),
                read_only: !matches!(role, MeshDbRole::Leader),
                mesh_cluster: Some(cluster.clone()),
            }),
            CellDbMode::WasmEngine { .. } => Ok(ResolvedDbBinding {
                target_ns: app.to_string(),
                target_db: cell_id.to_string(),
                read_only: false,
                mesh_cluster: None,
            }),
        }
    }

    /// Wake (or reuse) a JS/TS cell under `policy`.
    pub async fn wake(
        &self,
        app: &str,
        cell_id: &str,
        policy: CellPolicy,
        script: String,
    ) -> Result<()> {
        self.wake_workload(app, cell_id, policy, CellWorkload::NativeJs { script })
            .await
    }

    /// Wake (or reuse) any universal `CellWorkload` (`WasiModule`, `WasiCgi`, `JsOnWasm`, or `NativeJs`)
    /// under `policy`, acquiring a single-writer CAS lease and hydrating hibernated snapshots for `Elastic` cells.
    pub async fn wake_workload(
        &self,
        app: &str,
        cell_id: &str,
        policy: CellPolicy,
        workload: CellWorkload,
    ) -> Result<()> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };

        if let Some(existing) = self.active.write().await.get_mut(&key) {
            existing.last_active = Instant::now();
            existing.workload = workload;
            return Ok(());
        }

        let prev_state = self.cell_state(app, cell_id).await;
        let transition_state = if prev_state == CellLifecycleState::Hibernated {
            CellLifecycleState::Restoring
        } else {
            CellLifecycleState::Provisioning
        };
        self.states.write().await.insert(key.clone(), transition_state);

        let mut lease_etag = None;
        if let CellPolicy::Elastic { lease_bucket, .. } = &policy {
            let _ = self.blobs.create_bucket(lease_bucket).await;
            let lease_key = format!("leases/{}/{}.lease", app, cell_id);
            let lease_payload = bytes::Bytes::from(format!("owner:{}", self.blobs.node_id()));
            let etag = match self
                .blobs
                .put_object_cas(lease_bucket, &lease_key, lease_payload, None, true)
                .await
            {
                Ok(e) => e,
                Err(err) => {
                    self.states
                        .write()
                        .await
                        .insert(key, CellLifecycleState::Failed(err.to_string()));
                    crate::observability::global_metrics().inc_cell_failure();
                    return Err(err);
                }
            };
            lease_etag = Some(etag);

            // Hydrate snapshot from `BlobBridge` if the cell was previously hibernated
            let snap_key = format!("snapshots/{}/{}.json", app, cell_id);
            if let Some(snap) = self.blobs.get_object(lease_bucket, &snap_key).await? {
                self.engine.import_snapshot(app, cell_id, snap).await?;
            }
        }

        let persist_rec = match &workload {
            CellWorkload::WasiModule { module_bytes, fuel_limit, .. } => {
                use base64::Engine as _;
                Some(PersistedWasmWorkload {
                    app: app.to_string(),
                    cell_id: cell_id.to_string(),
                    kind: "wasi_module".to_string(),
                    fuel_limit: *fuel_limit,
                    module_b64: base64::engine::general_purpose::STANDARD.encode(module_bytes),
                })
            }
            CellWorkload::WasiCgi { module_bytes, fuel_limit, .. } => {
                use base64::Engine as _;
                Some(PersistedWasmWorkload {
                    app: app.to_string(),
                    cell_id: cell_id.to_string(),
                    kind: "wasi_cgi".to_string(),
                    fuel_limit: *fuel_limit,
                    module_b64: base64::engine::general_purpose::STANDARD.encode(module_bytes),
                })
            }
            _ => None,
        };
        if let Some(rec) = persist_rec {
            if let Ok(bytes) = serde_json::to_vec(&rec) {
                let _ = self.blobs.create_bucket(PERSISTED_CELLS_BUCKET).await;
                let wkey = format!("workloads/{}/{}.json", app, cell_id);
                let _ = self
                    .blobs
                    .put_object(PERSISTED_CELLS_BUCKET, &wkey, bytes::Bytes::from(bytes))
                    .await;
            }
        }

        let limits = CellResourceLimits::default();
        let exec_permits = Arc::new(tokio::sync::Semaphore::new(limits.max_concurrent_execs));
        self.active.write().await.insert(
            key.clone(),
            ActiveCell {
                policy,
                workload,
                limits,
                exec_permits,
                lease_etag,
                last_active: Instant::now(),
            },
        );
        self.states
            .write()
            .await
            .insert(key, CellLifecycleState::Running);
        crate::observability::global_metrics().inc_cell_wake();
        Ok(())
    }

    /// Restore all durably persisted Wasm cell workloads from `BlobBridge` on node boot.
    pub async fn restore_persisted_workloads(&self) -> Result<usize> {
        use base64::Engine as _;
        let objects = match self.blobs.list_objects(PERSISTED_CELLS_BUCKET, Some("workloads/")).await {
            Ok(list) => list,
            Err(_) => return Ok(0),
        };
        let mut restored = 0usize;
        for meta in objects {
            if !meta.key.ends_with(".json") {
                continue;
            }
            let Ok(Some(raw)) = self.blobs.get_object(PERSISTED_CELLS_BUCKET, &meta.key).await else {
                continue;
            };
            let Ok(rec) = serde_json::from_slice::<PersistedWasmWorkload>(&raw) else {
                continue;
            };
            let Ok(module_bytes) = base64::engine::general_purpose::STANDARD.decode(&rec.module_b64) else {
                continue;
            };
            let workload = match rec.kind.as_str() {
                "wasi_cgi" => CellWorkload::WasiCgi {
                    module_bytes,
                    doc_root: None,
                    fuel_limit: rec.fuel_limit,
                },
                _ => CellWorkload::WasiModule {
                    module_bytes,
                    args: vec!["cell.wasm".to_string()],
                    env: Vec::new(),
                    preopen_dirs: Vec::new(),
                    fuel_limit: rec.fuel_limit,
                },
            };
            // Clear any stale lease from a prior process lifecycle before re-waking
            let lease_key = format!("leases/{}/{}.lease", rec.app, rec.cell_id);
            let _ = self.blobs.delete_object("nexus-cells", &lease_key).await;
            if self
                .wake_workload(&rec.app, &rec.cell_id, CellPolicy::elastic_default(), workload)
                .await
                .is_ok()
            {
                restored += 1;
            }
        }
        Ok(restored)
    }

    /// List all known cells (running or hibernated) for UI/admin inspection.
    pub async fn list_cells(&self) -> Vec<CellSummary> {
        let active = self.active.read().await;
        let states = self.states.read().await;
        let mut out = Vec::new();
        for (key, state) in states.iter() {
            let is_wasm = active
                .get(key)
                .map(|c| {
                    matches!(
                        c.workload,
                        CellWorkload::WasiModule { .. }
                            | CellWorkload::WasiCgi { .. }
                            | CellWorkload::JsOnWasm { .. }
                    )
                })
                .unwrap_or(false);
            out.push(CellSummary {
                app: key.app.clone(),
                cell_id: key.cell_id.clone(),
                state: format!("{:?}", state),
                is_wasm,
            });
        }
        out.sort_by(|a, b| (&a.app, &a.cell_id).cmp(&(&b.app, &b.cell_id)));
        out
    }

    /// Wake a JS/TS cell backed by a registered WASI JavaScript engine (`quickjs.wasm` / Javy)
    /// resolved from `WasmRuntimeRegistry` (preferring pre-compiled AOT `.cwasm`).
    #[cfg(feature = "runtime-wasm")]
    pub async fn wake_js_wasm(
        &self,
        app: &str,
        cell_id: &str,
        policy: CellPolicy,
        script: String,
        runtime_name: &str,
        fuel_limit: u64,
    ) -> Result<()> {
        let resolved = self.runtimes.resolve_runtime(runtime_name).await?;
        let (engine_wasm, is_aot) = match resolved {
            crate::compute::wasm_registry::ResolvedRuntime::Aot(b) => (b, true),
            crate::compute::wasm_registry::ResolvedRuntime::Wasm(b) => (b, false),
        };
        self.wake_workload(
            app,
            cell_id,
            policy,
            CellWorkload::JsOnWasm {
                script,
                engine_wasm,
                is_aot,
                fuel_limit,
            },
        )
        .await
    }

    /// Universal cell database query executor supporting BOTH kernel-native `nexus-db`
    /// (`Dedicated`, `Reference`, `Mesh`) AND Wasmtime-hosted DB engines (`CellDbMode::WasmEngine`,
    /// e.g. `sqlite.wasm`, `pglite.wasm`, `duckdb.wasm`, `nexus-db.wasm`).
    #[allow(clippy::too_many_arguments)]
    pub async fn query_cell(
        &self,
        app: &str,
        cell_id: &str,
        transport: CellDbTransport,
        flavor: &str,
        query: &str,
        params: Vec<DbValue>,
        auth: Option<nexus_db::auth::AuthContext>,
    ) -> Result<serde_json::Value> {
        let cfg = self.get_db_config(app, cell_id).await;
        let binding = Self::check_db_config(&cfg, app, cell_id, transport, flavor)?;

        #[cfg(feature = "runtime-wasm")]
        if let CellDbMode::WasmEngine {
            engine,
            module_cid,
            mount_path,
        } = &cfg.mode
        {
            return self
                .wasm_db
                .execute_query(
                    &self.blobs,
                    &self.runtimes,
                    app,
                    cell_id,
                    engine,
                    module_cid,
                    mount_path,
                    flavor,
                    query,
                    50_000_000,
                )
                .await;
        }

        let nexus = self
            .engine
            .as_nexus_db()
            .ok_or_else(|| anyhow::anyhow!("Kernel StateEngine is not backed by NexusDb"))?;
        let effective_auth = if binding.read_only {
            Some(nexus_db::auth::AuthContext {
                level: nexus_db::auth::AuthLevel::Database(
                    binding.target_ns.clone(),
                    binding.target_db.clone(),
                ),
                roles: vec![nexus_db::auth::Role::Viewer],
                actor: auth.and_then(|a| a.actor),
                access_name: None,
                token_claims: None,
            })
        } else {
            auth
        };
        execute_unified_query(
            nexus,
            &binding.target_ns,
            &binding.target_db,
            flavor,
            query,
            params,
            effective_auth,
        )
    }

    /// Returns `true` if `(app, cell_id)` is currently awake with a Wasmtime workload (`WasiModule`, `WasiCgi`, or `JsOnWasm`).
    pub async fn is_wasm_workload(&self, app: &str, cell_id: &str) -> bool {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };
        matches!(
            self.active.read().await.get(&key).map(|c| &c.workload),
            Some(
                CellWorkload::WasiModule { .. }
                    | CellWorkload::WasiCgi { .. }
                    | CellWorkload::JsOnWasm { .. }
            )
        )
    }

    /// Invoke an HTTP request against a Wasmtime cell (`WasiCgi`, `WasiModule`, or `JsOnWasm`)
    /// with its `NexusHostContext` (`CellDbConfig`, `StateEngine`, `BlobBridge`) automatically attached.
    #[cfg(all(feature = "runtime-wasm", not(target_os = "ios")))]
    pub async fn invoke_http(
        &self,
        app: &str,
        cell_id: &str,
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
    ) -> Result<CellHttpResponse> {
        self.invoke_http_with_request_id(app, cell_id, method, path, query_string, body, None)
            .await
    }

    /// Same as `invoke_http`, propagating an end-to-end correlation `request_id` (`X-Request-Id`)
    /// into `NexusHostContext` for structured host logs & diagnostics.
    #[cfg(all(feature = "runtime-wasm", not(target_os = "ios")))]
    #[allow(clippy::too_many_arguments)]
    pub async fn invoke_http_with_request_id(
        &self,
        app: &str,
        cell_id: &str,
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
        request_id: Option<String>,
    ) -> Result<CellHttpResponse> {
        self.invoke_http_with_auth(app, cell_id, method, path, query_string, body, request_id, None)
            .await
    }

    /// Same as `invoke_http_with_request_id`, also intersecting the caller's verified IAM
    /// `AuthContext` into `NexusHostContext` so Wasmtime `nexus_host` syscalls enforce the
    /// caller's real capability ceiling (e.g. `VIEWER` cannot invoke `DbWrite` or `BlobWrite`).
    #[cfg(all(feature = "runtime-wasm", not(target_os = "ios")))]
    #[allow(clippy::too_many_arguments)]
    pub async fn invoke_http_with_auth(
        &self,
        app: &str,
        cell_id: &str,
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
        request_id: Option<String>,
        auth: Option<nexus_db::auth::AuthContext>,
    ) -> Result<CellHttpResponse> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };
        let (workload, limits, permits) = {
            let mut map = self.active.write().await;
            let cell = map
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("Cell {}/{} is not awake", app, cell_id))?;
            cell.last_active = Instant::now();
            (
                cell.workload.clone(),
                cell.limits.clone(),
                cell.exec_permits.clone(),
            )
        };
        let _exec_permit = permits
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("Cell {}/{} concurrency limiter closed", app, cell_id))?;
        let deadline = Duration::from_millis(limits.deadline_ms);

        let db_config = self.get_db_config(app, cell_id).await;
        let host = crate::compute::crystal::NexusHostContext::new(
            app,
            cell_id,
            db_config,
            self.engine.clone(),
            self.blobs.clone(),
        )
        .with_auth(auth.as_ref())
        .with_request_id(request_id);
        let crystal = self.crystal.clone();

        match workload {
            CellWorkload::WasiCgi {
                module_bytes,
                doc_root,
                fuel_limit,
            } => {
                let method = method.to_string();
                let path = path.to_string();
                let query = query_string.to_string();
                let body_vec = body.to_vec();
                let cgi = tokio::task::spawn_blocking(move || {
                    crystal.invoke_wasi_cgi_with_host(
                        &module_bytes,
                        &method,
                        &path,
                        &query,
                        &body_vec,
                        doc_root.as_deref(),
                        Some(host),
                        fuel_limit,
                    )
                })
                .await??;
                Ok(CellHttpResponse {
                    status: cgi.status,
                    headers: cgi.headers,
                    body: cgi.body,
                })
            }
            CellWorkload::WasiModule {
                module_bytes,
                args,
                env,
                preopen_dirs,
                fuel_limit,
            } => {
                let mut env = env;
                env.push(("REQUEST_METHOD".to_string(), method.to_ascii_uppercase()));
                env.push(("PATH_INFO".to_string(), path.to_string()));
                env.push(("QUERY_STRING".to_string(), query_string.to_string()));
                let cfg = crate::compute::crystal::WasiRunConfig {
                    args,
                    env,
                    stdin: body.to_vec(),
                    preopen_dirs,
                    fuel_limit,
                    ..crate::compute::crystal::WasiRunConfig::default()
                };
                let out = tokio::task::spawn_blocking(move || {
                    crystal.run_wasi_with_host(&module_bytes, cfg, host)
                })
                .await??;
                Ok(CellHttpResponse {
                    status: if out.exit_code == 0 { 200 } else { 500 },
                    headers: std::collections::BTreeMap::new(),
                    body: out.stdout,
                })
            }
            CellWorkload::JsOnWasm {
                script,
                engine_wasm,
                is_aot,
                fuel_limit,
            } => {
                let js_script = if super::transformer::is_likely_ts(&script) {
                    super::transformer::transform_ts_to_js(&script).unwrap_or(script)
                } else {
                    script
                };
                let body_vec = body.to_vec();
                let fuel_cap = fuel_limit.min(limits.max_fuel);
                let out = tokio::time::timeout(
                    deadline,
                    tokio::task::spawn_blocking(move || {
                        if is_aot {
                            let cfg = crate::compute::crystal::WasiRunConfig {
                                args: vec!["quickjs.wasm".to_string()],
                                env: vec![("NEXUS_JS_SOURCE".to_string(), js_script)],
                                stdin: body_vec,
                                preopen_dirs: Vec::new(),
                                fuel_limit: fuel_cap,
                                ..crate::compute::crystal::WasiRunConfig::default()
                            };
                            crystal.run_wasi_aot_with_host(&engine_wasm, cfg, host)
                        } else {
                            crystal.invoke_js_wasm(&engine_wasm, &js_script, &body_vec, Some(host), fuel_cap)
                        }
                    }),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Cell {}/{} execution exceeded deadline ({}ms)", app, cell_id, limits.deadline_ms))???;
                if out.stdout.len() > limits.max_output_bytes {
                    anyhow::bail!(
                        "Cell {}/{} output exceeded limit ({} > {} bytes)",
                        app,
                        cell_id,
                        out.stdout.len(),
                        limits.max_output_bytes
                    );
                }
                Ok(CellHttpResponse {
                    status: if out.exit_code == 0 { 200 } else { 500 },
                    headers: std::collections::BTreeMap::new(),
                    body: out.stdout,
                })
            }
            CellWorkload::NativeJs { .. } => {
                let expr = String::from_utf8_lossy(body).to_string();
                let out = self.eval_in_cell(app, cell_id, &expr).await?;
                Ok(CellHttpResponse {
                    status: 200,
                    headers: std::collections::BTreeMap::new(),
                    body: out.into_bytes(),
                })
            }
        }
    }

    /// Ensure a cell is awake (acquiring its CAS lease, hydrating any hibernated snapshot from
    /// the default `nexus-cells` bucket, and registering it in `self.active`) before executing
    /// an external multi-flavor query against `(app, cell_id)`.
    pub async fn ensure_awake(&self, app: &str, cell_id: &str) -> Result<()> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };
        if let Some(existing) = self.active.write().await.get_mut(&key) {
            existing.last_active = Instant::now();
            return Ok(());
        }
        self.wake(app, cell_id, CellPolicy::elastic_default(), String::new())
            .await
    }

    /// Direct native QuickJS eval has been removed in favor of Wasmtime guest cells.
    /// Run JS/TS cells via `wake_js_wasm` / `wake_workload` + `invoke_http`.
    pub async fn eval_in_cell(&self, app: &str, cell_id: &str, _expr: &str) -> Result<String> {
        anyhow::bail!(
            "Nexus-IO uses Wasmtime as its sole guest runtime. Run cell {}/{} via `wake_js_wasm` / `wake_workload` + `invoke_http`.",
            app,
            cell_id
        )
    }

    /// Transactionally hibernate an `Elastic` cell:
    /// 1. Keep the cell registered in `self.active` until snapshot export & durable blob write succeed.
    /// 2. Only after durable persistence succeeds, verify lease ownership, release the lease, and evict from RAM.
    pub async fn hibernate(&self, app: &str, cell_id: &str) -> Result<()> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };

        let (policy, lease_etag) = {
            let map = self.active.read().await;
            let Some(cell) = map.get(&key) else {
                return Ok(());
            };
            (cell.policy.clone(), cell.lease_etag.clone())
        };

        self.states
            .write()
            .await
            .insert(key.clone(), CellLifecycleState::Hibernating);

        if let CellPolicy::Elastic { lease_bucket, .. } = &policy {
            let snapshot = self.engine.export_snapshot(app, cell_id).await?;
            let snap_key = format!("snapshots/{}/{}.json", app, cell_id);
            self.blobs.put_object(lease_bucket, &snap_key, snapshot).await?;

            // Release lease only after verifying we still own the matching ETag
            if let Some(expected_etag) = lease_etag {
                let lease_key = format!("leases/{}/{}.lease", app, cell_id);
                if let Ok(Some(meta)) = self.blobs.head_object(lease_bucket, &lease_key).await {
                    if meta.etag == expected_etag {
                        let _ = self.blobs.delete_object(lease_bucket, &lease_key).await;
                    }
                }
            }
        }

        self.active.write().await.remove(&key);
        self.states
            .write()
            .await
            .insert(key, CellLifecycleState::Hibernated);
        #[cfg(feature = "runtime-wasm")]
        let _ = self.wasm_db.evict_idle_locks().await;
        crate::observability::global_metrics().inc_cell_hibernate();
        Ok(())
    }

    /// Evict all `Elastic` cells that exceeded their `idle_timeout`.
    pub async fn hibernate_idle(&self) -> Result<usize> {
        let to_evict: Vec<CellKey> = {
            let map = self.active.read().await;
            map.iter()
                .filter_map(|(k, v)| match &v.policy {
                    CellPolicy::Elastic { idle_timeout, .. }
                        if v.last_active.elapsed() >= *idle_timeout =>
                    {
                        Some(k.clone())
                    }
                    _ => None,
                })
                .collect()
        };

        let count = to_evict.len();
        for k in to_evict {
            self.hibernate(&k.app, &k.cell_id).await?;
        }
        Ok(count)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn cell_db_config_enforces_stateless_reference_mesh_flavors_and_transports() {
        // 1. Stateless cell blocks all DB access
        let stateless = CellDbConfig::stateless();
        assert!(CellManager::check_db_config(
            &stateless,
            "edge",
            "worker1",
            CellDbTransport::Internal,
            "surql"
        )
        .is_err());

        // 2. Minimal dedicated cell allows Internal + surql, blocks HttpRest & mysql
        let minimal = CellDbConfig::dedicated_minimal();
        assert!(CellManager::check_db_config(
            &minimal,
            "billing",
            "ledger",
            CellDbTransport::Internal,
            "surql"
        )
        .is_ok());
        assert!(CellManager::check_db_config(
            &minimal,
            "billing",
            "ledger",
            CellDbTransport::HttpRest,
            "surql"
        )
        .is_err());
        assert!(CellManager::check_db_config(
            &minimal,
            "billing",
            "ledger",
            CellDbTransport::Internal,
            "mysql"
        )
        .is_err());

        // 3. Cross-cell Reference redirects to target cell with read_only flag
        let ref_cfg = CellDbConfig::reference("billing", "ledger", true);
        let bound = CellManager::check_db_config(
            &ref_cfg,
            "analytics",
            "dash",
            CellDbTransport::HttpRest,
            "postgres",
        )
        .unwrap();
        assert_eq!(bound.target_ns, "billing");
        assert_eq!(bound.target_db, "ledger");
        assert!(bound.read_only);

        // 4. Mesh ReadReplica enforces read_only & carries cluster name
        let mesh_cfg = CellDbConfig::mesh("us-east", "billing", "ledger", MeshDbRole::ReadReplica);
        let m_bound = CellManager::check_db_config(
            &mesh_cfg,
            "edge",
            "read1",
            CellDbTransport::MeshWal,
            "mysql",
        )
        .unwrap();
        assert_eq!(m_bound.mesh_cluster.as_deref(), Some("us-east"));
        assert!(m_bound.read_only);
    }

    #[cfg(all(feature = "runtime-wasm", not(target_os = "ios")))]
    #[tokio::test(flavor = "multi_thread")]
    async fn end_to_end_quickjs_wasm_cell_and_wasm_db_engine_via_cell_manager() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
        let manager = CellManager::new(db, blobs);

        // 1. Register an AOT-precompiled WASI JS guest runtime (`quickjs`) that invokes `nexus_host::nexus_db_query`
        let quickjs_stub_wat = br#"
            (module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (import "nexus_host" "nexus_db_query"
                    (func $db_query (param i32 i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 32) "surql")
                (data (i32.const 64) "RETURN 'hello-quickjs-wasm'")
                (func (export "_start")
                    (local $n i32)
                    (local.set $n
                        (call $db_query
                            (i32.const 32) (i32.const 5)
                            (i32.const 64) (i32.const 27)
                            (i32.const 256) (i32.const 256)))
                    (i32.store (i32.const 0) (i32.const 256))
                    (i32.store (i32.const 4) (local.get $n))
                    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                )
            )
        "#;
        let qjs_rec = manager
            .runtimes()
            .register_runtime("quickjs", quickjs_stub_wat)
            .await
            .unwrap();
        assert!(qjs_rec.aot_cached);

        manager
            .wake_js_wasm(
                "web",
                "api_1",
                CellPolicy::Pinned,
                "export default () => 'ts-source'".to_string(),
                "quickjs",
                1_000_000,
            )
            .await
            .unwrap();
        assert!(manager.is_wasm_workload("web", "api_1").await);

        let http_resp = manager
            .invoke_http("web", "api_1", "GET", "/cells/web/api_1", "", b"")
            .await
            .unwrap();
        assert_eq!(http_resp.status, 200);
        assert!(String::from_utf8_lossy(&http_resp.body).contains("hello-quickjs-wasm"));

        // 2. Register a Wasm-hosted DB engine (`sqlite`) and query it through CellManager::query_cell
        let sqlite_wasm_wat = br#"
            (module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 16) "[{\"db\":\"sqlite-wasm\",\"rows\":3}]")
                (func (export "_start")
                    (i32.store (i32.const 0) (i32.const 16))
                    (i32.store (i32.const 4) (i32.const 31))
                    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                )
            )
        "#;
        let sql_rec = manager
            .runtimes()
            .register_runtime("sqlite", sqlite_wasm_wat)
            .await
            .unwrap();
        manager
            .set_db_config(
                "shop",
                "cart_1",
                CellDbConfig::wasm_engine("sqlite", &sql_rec.cid, "sqlite"),
            )
            .await
            .unwrap();

        let rows = manager
            .query_cell(
                "shop",
                "cart_1",
                CellDbTransport::HttpRest,
                "sqlite",
                "SELECT count(*) FROM items",
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(rows[0]["db"], "sqlite-wasm");
        assert_eq!(rows[0]["rows"], 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_isolated_cells_hibernate_and_recover_without_leakage() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
        let manager = CellManager::new(db.clone(), blobs.clone());

        // Spawn 6 concurrent elastic cells, each writing unique isolated state into its own DB,
        // hibernating to BlobBridge, and waking back up to verify zero cross-cell leakage.
        let mut tasks = Vec::new();
        for idx in 0..6u32 {
            let mgr = manager.clone();
            tasks.push(tokio::spawn(async move {
                let app = "multi_tenant";
                let cell_id = format!("tenant_{}", idx);
                let secret = format!("secret_payload_{}", idx);

                mgr.wake_workload(
                    app,
                    &cell_id,
                    CellPolicy::elastic_default(),
                    CellWorkload::WasiModule {
                        module_bytes: Vec::new(),
                        args: Vec::new(),
                        env: Vec::new(),
                        preopen_dirs: Vec::new(),
                        fuel_limit: 1_000_000,
                    },
                )
                .await
                .unwrap();

                // Write isolated record into this cell's scoped DB
                mgr.query_cell(
                    app,
                    &cell_id,
                    CellDbTransport::Internal,
                    "surql",
                    &format!("CREATE item:1 SET owner = '{}', val = {}", secret, idx),
                    Vec::new(),
                    None,
                )
                .await
                .unwrap();

                // Hibernate (exports snapshot to BlobBridge & releases CAS lease)
                mgr.hibernate(app, &cell_id).await.unwrap();

                // Re-wake on a fresh lease (hydrates snapshot from BlobBridge) and verify exact isolation
                mgr.ensure_awake(app, &cell_id).await.unwrap();
                let res = mgr
                    .query_cell(
                        app,
                        &cell_id,
                        CellDbTransport::Internal,
                        "surql",
                        "SELECT owner, val FROM item",
                        Vec::new(),
                        None,
                    )
                    .await
                    .unwrap();
                let text = res.to_string();
                assert!(
                    text.contains(&secret),
                    "tenant {} lost state after hibernation: {}",
                    idx,
                    text
                );
                // Ensure no other tenant's secret leaked into this cell
                for other in 0..6u32 {
                    if other != idx {
                        assert!(
                            !text.contains(&format!("secret_payload_{}", other)),
                            "cross-cell leakage from {} into {}",
                            other,
                            idx
                        );
                    }
                }
            }));
        }

        for t in tasks {
            t.await.unwrap();
        }
    }
}
