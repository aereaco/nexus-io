use anyhow::Result;
use quickrs_core::context::Context;
use quickrs_core::object::{PropFlags, Property};
use quickrs_core::value::{JsResult, PropKey, Value as JsValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use nexus_db::Value as DbValue;
use tokio::sync::RwLock;

use crate::db::sql_compiler::{compile_sql_to_surql, execute_unified_query, SqlDialect};
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

struct ActiveCell {
    policy: CellPolicy,
    workload: CellWorkload,
    lease_etag: Option<String>,
    last_active: Instant,
}

struct CellScope {
    engine: Arc<dyn StateEngine>,
    app: String,
    cell_id: String,
    db_config: CellDbConfig,
}

thread_local! {
    static ACTIVE_CELL_SCOPE: std::cell::RefCell<Option<CellScope>> = std::cell::RefCell::new(None);
}

/// Unified `CellManager` actor pool supporting both `pinned` and `elastic` (`celld`) cells
/// on top of `StateEngine` (`nexus-db`) + `BlobBridge` + `quickrs-core` + `oxc`, with
/// declarative per-cell `CellDbConfig` (topology mode, query flavors, and connection transports).
#[derive(Clone)]
pub struct CellManager {
    engine: Arc<dyn StateEngine>,
    blobs: Arc<BlobBridge>,
    active: Arc<RwLock<HashMap<CellKey, ActiveCell>>>,
    db_configs: Arc<RwLock<HashMap<CellKey, CellDbConfig>>>,
}

impl CellManager {
    pub fn new(engine: Arc<dyn StateEngine>, blobs: Arc<BlobBridge>) -> Self {
        Self {
            engine,
            blobs,
            active: Arc::new(RwLock::new(HashMap::new())),
            db_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Declare the modular `CellDbConfig` (mode, exposed flavors, and allowed connection transports)
    /// for `(app, cell_id)`.
    pub async fn set_db_config(&self, app: &str, cell_id: &str, config: CellDbConfig) {
        self.db_configs.write().await.insert(
            CellKey {
                app: app.to_string(),
                cell_id: cell_id.to_string(),
            },
            config,
        );
    }

    pub async fn get_db_config(&self, app: &str, cell_id: &str) -> CellDbConfig {
        self.db_configs
            .read()
            .await
            .get(&CellKey {
                app: app.to_string(),
                cell_id: cell_id.to_string(),
            })
            .cloned()
            .unwrap_or_default()
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

        let mut lease_etag = None;
        if let CellPolicy::Elastic { lease_bucket, .. } = &policy {
            let _ = self.blobs.create_bucket(lease_bucket).await;
            let lease_key = format!("leases/{}/{}.lease", app, cell_id);
            let lease_payload = bytes::Bytes::from(format!("owner:{}", self.blobs.node_id()));
            let etag = self
                .blobs
                .put_object_cas(lease_bucket, &lease_key, lease_payload, None, true)
                .await?;
            lease_etag = Some(etag);

            // Hydrate snapshot from `BlobBridge` if the cell was previously hibernated
            let snap_key = format!("snapshots/{}/{}.json", app, cell_id);
            if let Some(snap) = self.blobs.get_object(lease_bucket, &snap_key).await? {
                self.engine.import_snapshot(app, cell_id, snap).await?;
            }
        }

        self.active.write().await.insert(
            key,
            ActiveCell {
                policy,
                workload,
                lease_etag,
                last_active: Instant::now(),
            },
        );
        Ok(())
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
    #[cfg(all(feature = "wasm-runtime", not(target_os = "ios")))]
    pub async fn invoke_http(
        &self,
        app: &str,
        cell_id: &str,
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
    ) -> Result<CellHttpResponse> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };
        let workload = {
            let mut map = self.active.write().await;
            let cell = map
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("Cell {}/{} is not awake", app, cell_id))?;
            cell.last_active = Instant::now();
            cell.workload.clone()
        };

        let db_config = self.get_db_config(app, cell_id).await;
        let host = crate::compute::crystal::NexusHostContext::new(
            app,
            cell_id,
            db_config,
            self.engine.clone(),
            self.blobs.clone(),
        );
        let crystal = crate::compute::crystal::CrystalEngine::new()?;

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
                fuel_limit,
            } => {
                let js_script = if super::transformer::is_likely_ts(&script) {
                    super::transformer::transform_ts_to_js(&script, nu_protocol::Span::unknown())
                        .unwrap_or(script)
                } else {
                    script
                };
                let body_vec = body.to_vec();
                let out = tokio::task::spawn_blocking(move || {
                    crystal.invoke_js_wasm(&engine_wasm, &js_script, &body_vec, Some(host), fuel_limit)
                })
                .await??;
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

    /// Execute a request/expression inside the scoped cell with `ctx.storage.sql`, `ctx.storage` KV,
    /// and `ctx.storage.surreal` bound directly to `(app, cell_id)`.
    pub async fn eval_in_cell(&self, app: &str, cell_id: &str, expr: &str) -> Result<String> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };

        let script = {
            let mut map = self.active.write().await;
            let cell = map
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("Cell {}/{} is not awake", app, cell_id))?;
            cell.last_active = Instant::now();
            match &cell.workload {
                CellWorkload::NativeJs { script } | CellWorkload::JsOnWasm { script, .. } => {
                    script.clone()
                }
                _ => anyhow::bail!(
                    "Cell {}/{} is a Wasmtime binary workload; invoke it via CellManager::invoke_http",
                    app,
                    cell_id
                ),
            }
        };

        let engine = self.engine.clone();
        let db_config = self.get_db_config(app, cell_id).await;
        let app_owned = app.to_string();
        let cell_owned = cell_id.to_string();
        let expr_owned = expr.to_string();

        tokio::task::block_in_place(move || {
            ACTIVE_CELL_SCOPE.with(|s| {
                *s.borrow_mut() = Some(CellScope {
                    engine,
                    app: app_owned,
                    cell_id: cell_owned,
                    db_config,
                });
            });

            let mut ctx = create_cell_context();

            // Transpile TypeScript cell script if needed
            let js_script = if super::transformer::is_likely_ts(&script) {
                super::transformer::transform_ts_to_js(&script, nu_protocol::Span::unknown())
                    .unwrap_or(script)
            } else {
                script
            };

            let res = ctx
                .eval_and_run_jobs(&js_script)
                .and_then(|_| ctx.eval_and_run_jobs(&expr_owned));

            ACTIVE_CELL_SCOPE.with(|s| *s.borrow_mut() = None);

            match res {
                Ok(val) => Ok(js_val_to_string(&val)),
                Err(e) => Err(anyhow::anyhow!("Cell execution error: {:?}", e)),
            }
        })
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

fn create_cell_context() -> Context {
    let mut ctx = Context::new();
    let global = ctx.global();

    let register = |c: &mut Context, name: &str, arity: u32, func: quickrs_core::object::NativeFn| {
        let f = c.new_native_function(func, name, arity, 0);
        let key = PropKey::from_string(&c.intern(name));
        c.define_own(&global, key, Property::data(JsValue::Object(f), PropFlags::C_W_E));
    };

    register(&mut ctx, "__cell_query", 3, cell_unified_query_cb);
    register(&mut ctx, "__cell_kv_get", 1, cell_kv_get_cb);
    register(&mut ctx, "__cell_kv_put", 2, cell_kv_put_cb);
    register(&mut ctx, "__cell_kv_delete", 1, cell_kv_delete_cb);

    // Unified multi-flavor `ctx.db.query(q, { flavor, params })` ('surql'|'sqlite'|'postgres'|'mysql'|'graphql'|'gql')
    // plus ergonomic Cloudflare Durable Objects / celld compatible `ctx.storage` aliases.
    let _ = ctx.eval(
        r#"
        const __query = (query, opts = {}) => {
            const flavor = typeof opts === 'string' ? opts : (opts.flavor || 'surql');
            const params = Array.isArray(opts) ? opts : (opts.params || []);
            return __cell_query(flavor, query, params);
        };
        globalThis.ctx = {
            db: {
                query: __query,
            },
            storage: {
                query: __query,
                sql: {
                    exec(query, ...bindings) {
                        const rows = __cell_query('sqlite', query, bindings);
                        return {
                            toArray() { return rows; },
                            one() { return rows[0] ?? null; },
                        };
                    }
                },
                surreal: {
                    query(surql) { return __cell_query('surql', surql, []); }
                },
                get(key) { return __cell_kv_get(String(key)); },
                put(key, val) { return __cell_kv_put(String(key), val); },
                delete(key) { return __cell_kv_delete(String(key)); },
            }
        };
        "#,
    );

    // Install WinterCG Web Standard globals (`Request`, `Response`, `Headers`, `URL`, `crypto`, `TextEncoder`/`TextDecoder`, `Deno.openKv`)
    super::wintercg::install_wintercg_globals(&mut ctx);

    ctx
}

fn js_to_db(val: &JsValue) -> DbValue {
    match val {
        JsValue::Undefined | JsValue::Uninitialized | JsValue::Null => DbValue::Null,
        JsValue::Bool(b) => DbValue::Bool(*b),
        JsValue::Int(i) => DbValue::Int(*i as i64),
        JsValue::Float(f) => DbValue::Float(*f),
        JsValue::Str(s) => DbValue::String(s.to_string()),
        other => DbValue::String(format!("{:?}", other)),
    }
}

fn js_val_to_string(val: &JsValue) -> String {
    match val {
        JsValue::Undefined | JsValue::Uninitialized => "undefined".to_string(),
        JsValue::Null => "null".to_string(),
        JsValue::Bool(b) => b.to_string(),
        JsValue::Int(i) => i.to_string(),
        JsValue::Float(f) => f.to_string(),
        JsValue::Str(s) => s.to_string(),
        other => format!("{:?}", other),
    }
}

fn cell_unified_query_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let flavor = args
        .first()
        .map(js_val_to_string)
        .unwrap_or_else(|| "surql".into())
        .to_ascii_lowercase();
    let query = args.get(1).map(js_val_to_string).unwrap_or_default();
    let mut bind_args = Vec::new();
    if let Some(JsValue::Object(arr_obj)) = args.get(2) {
        let borrowed = arr_obj.borrow();
        if let quickrs_core::object::ObjectData::Array(arr) = &borrowed.data {
            for elem in &arr.elements {
                bind_args.push(js_to_db(elem));
            }
        }
    }

    // Unified CellDbConfig gate + fast path when backed directly by `NexusDb`
    let scope = ACTIVE_CELL_SCOPE.with(|s| {
        s.borrow()
            .as_ref()
            .map(|sc| (sc.engine.clone(), sc.app.clone(), sc.cell_id.clone(), sc.db_config.clone()))
    });
    if let Some((ref engine, ref app, ref cell_id, ref db_cfg)) = scope {
        let binding = match CellManager::check_db_config(
            db_cfg,
            app,
            cell_id,
            CellDbTransport::Internal,
            &flavor,
        ) {
            Ok(b) => b,
            Err(e) => {
                let err_obj = ctx.new_object();
                let k = PropKey::from_string(&ctx.intern("error"));
                let v = JsValue::Str(ctx.intern(&e.to_string()));
                ctx.define_own(&err_obj, k, Property::data(v, PropFlags::C_W_E));
                return Ok(JsValue::Object(err_obj));
            }
        };
        if let Some(nexus) = engine.as_nexus_db() {
            let auth_opt = if binding.read_only {
                Some(nexus_db::auth::AuthContext {
                    level: nexus_db::auth::AuthLevel::Database(
                        binding.target_ns.clone(),
                        binding.target_db.clone(),
                    ),
                    roles: vec![nexus_db::auth::Role::Viewer],
                    actor: Some(format!("cell:{}/{}", app, cell_id)),
                    access_name: None,
                    token_claims: None,
                })
            } else {
                None
            };
            let res_json = match execute_unified_query(
                nexus,
                &binding.target_ns,
                &binding.target_db,
                &flavor,
                &query,
                bind_args,
                auth_opt,
            ) {
                Ok(v) => v,
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            };
            let json_str = serde_json::to_string(&res_json).unwrap_or_else(|_| "null".into());
            return ctx.eval(&format!("({})", json_str));
        }
    }

    match flavor.as_str() {
        "surql" | "surreal" | "surrealql" => run_cell_query(ctx, &query, vec![]),
        "sqlite" | "postgres" | "pg" | "postgresql" | "mysql" => {
            let dialect = match flavor.as_str() {
                "postgres" | "pg" | "postgresql" => SqlDialect::Postgres,
                "mysql" => SqlDialect::Mysql,
                _ => SqlDialect::Sqlite,
            };
            match compile_sql_to_surql(dialect, &query, bind_args) {
                Ok(c) => run_cell_query(ctx, &c.surql, c.bindings),
                Err(e) => {
                    let err_obj = ctx.new_object();
                    let k = PropKey::from_string(&ctx.intern("error"));
                    let v = JsValue::Str(ctx.intern(&e.to_string()));
                    ctx.define_own(&err_obj, k, Property::data(v, PropFlags::C_W_E));
                    Ok(JsValue::Object(err_obj))
                }
            }
        }
        other => {
            let err_obj = ctx.new_object();
            let k = PropKey::from_string(&ctx.intern("error"));
            let v = JsValue::Str(ctx.intern(&format!("Unsupported query flavor '{}'", other)));
            ctx.define_own(&err_obj, k, Property::data(v, PropFlags::C_W_E));
            Ok(JsValue::Object(err_obj))
        }
    }
}

fn run_cell_query(
    ctx: &mut Context,
    surql: &str,
    bindings: Vec<(String, DbValue)>,
) -> JsResult<JsValue> {
    let scope = ACTIVE_CELL_SCOPE.with(|s| {
        s.borrow().as_ref().map(|sc| (sc.engine.clone(), sc.app.clone(), sc.cell_id.clone()))
    });
    let Some((engine, app, cell_id)) = scope else {
        return Ok(JsValue::Undefined);
    };

    let rt = tokio::runtime::Handle::current();
    let rows = rt.block_on(async move { engine.query_scoped(&app, &cell_id, surql, bindings).await });

    match rows {
        Ok(list) => {
            let items: Vec<JsValue> = list.into_iter().map(|v| super::surreal_to_js(ctx, v)).collect();
            Ok(JsValue::Object(ctx.new_array_from(items)))
        }
        Err(e) => {
            let err_obj = ctx.new_object();
            let k = PropKey::from_string(&ctx.intern("error"));
            let v = JsValue::Str(ctx.intern(&e.to_string()));
            ctx.define_own(&err_obj, k, Property::data(v, PropFlags::C_W_E));
            Ok(JsValue::Object(err_obj))
        }
    }
}

fn cell_kv_get_cb(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let key = args.first().map(js_val_to_string).unwrap_or_default();
    let scope = ACTIVE_CELL_SCOPE.with(|s| {
        s.borrow().as_ref().map(|sc| (sc.engine.clone(), sc.app.clone(), sc.cell_id.clone()))
    });
    let Some((engine, app, cell_id)) = scope else {
        return Ok(JsValue::Undefined);
    };
    let rt = tokio::runtime::Handle::current();
    match rt.block_on(async move { engine.kv_get(&app, &cell_id, &key).await }) {
        Ok(Some(v)) => Ok(super::surreal_to_js(ctx, v)),
        _ => Ok(JsValue::Undefined),
    }
}

fn cell_kv_put_cb(
    _ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let key = args.first().map(js_val_to_string).unwrap_or_default();
    let val = args.get(1).map(js_to_db).unwrap_or(DbValue::Null);
    let scope = ACTIVE_CELL_SCOPE.with(|s| {
        s.borrow().as_ref().map(|sc| (sc.engine.clone(), sc.app.clone(), sc.cell_id.clone()))
    });
    let Some((engine, app, cell_id)) = scope else {
        return Ok(JsValue::Undefined);
    };
    let rt = tokio::runtime::Handle::current();
    let _ = rt.block_on(async move { engine.kv_put(&app, &cell_id, &key, val).await });
    Ok(JsValue::Undefined)
}

fn cell_kv_delete_cb(
    _ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let key = args.first().map(js_val_to_string).unwrap_or_default();
    let scope = ACTIVE_CELL_SCOPE.with(|s| {
        s.borrow().as_ref().map(|sc| (sc.engine.clone(), sc.app.clone(), sc.cell_id.clone()))
    });
    let Some((engine, app, cell_id)) = scope else {
        return Ok(JsValue::Undefined);
    };
    let rt = tokio::runtime::Handle::current();
    let _ = rt.block_on(async move { engine.kv_delete(&app, &cell_id, &key).await });
    Ok(JsValue::Undefined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn elastic_cell_supports_sqlite_api_surrealql_and_hibernation() {
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
                    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
                    let manager = CellManager::new(db.clone(), blobs);

                    let ts_cell = r#"
                        interface Todo { title: string; done: number; }
                        ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS todos (title TEXT, done INT)");
                        function addTodo(t: Todo): number {
                            ctx.storage.sql.exec("INSERT INTO todos (title, done) VALUES (?, ?)", t.title, t.done);
                            ctx.storage.put("last_title", t.title);
                            return ctx.storage.sql.exec("SELECT title FROM todos WHERE done = ?", 0).toArray().length;
                        }
                    "#;

                    // 1. Wake elastic cell (acquires CAS lease)
                    manager
                        .wake("demo_app", "room_1", CellPolicy::elastic_default(), ts_cell.to_string())
                        .await
                        .unwrap();

                    // 2. Write via SQLite API + KV, then read the exact same records via SurrealQL
                    let count = manager
                        .eval_in_cell("demo_app", "room_1", r#"addTodo({ title: "ship celld", done: 0 })"#)
                        .await
                        .unwrap();
                    assert_eq!(count, "1");

                    let surql_check = manager
                        .eval_in_cell(
                            "demo_app",
                            "room_1",
                            r#"ctx.storage.surreal.query("SELECT title FROM todos")[0].title"#,
                        )
                        .await
                        .unwrap();
                    assert_eq!(surql_check, "ship celld");

                    // 3. Hibernate cell (flushes snapshot to BlobBridge + releases CAS lease)
                    manager.hibernate("demo_app", "room_1").await.unwrap();

                    // 4. Re-wake cell and verify KV state survived hibernation
                    manager
                        .wake("demo_app", "room_1", CellPolicy::elastic_default(), ts_cell.to_string())
                        .await
                        .unwrap();
                    let restored = manager
                        .eval_in_cell("demo_app", "room_1", r#"ctx.storage.get("last_title")"#)
                        .await
                        .unwrap();
                    assert_eq!(restored, "ship celld");
                }));
            })
            .unwrap()
            .join()
            .unwrap();
    }

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
}
