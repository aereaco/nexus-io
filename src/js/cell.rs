use anyhow::Result;
use quickrs_core::context::Context;
use quickrs_core::object::{PropFlags, Property};
use quickrs_core::value::{JsResult, PropKey, Value as JsValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use nexus_db::Value as DbValue;
use tokio::sync::RwLock;

use crate::db::sql_compiler::{compile_sql_to_surql, SqlDialect};
use crate::db::StateEngine;
use crate::storage::BlobBridge;

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

struct ActiveCell {
    policy: CellPolicy,
    script: String,
    lease_etag: Option<String>,
    last_active: Instant,
}

struct CellScope {
    engine: Arc<dyn StateEngine>,
    app: String,
    cell_id: String,
}

thread_local! {
    static ACTIVE_CELL_SCOPE: std::cell::RefCell<Option<CellScope>> = std::cell::RefCell::new(None);
}

/// Unified `CellManager` actor pool supporting both `pinned` and `elastic` (`celld`) cells
/// on top of `StateEngine` (SurrealDB) + `BlobBridge` (`s3s` + `iroh-blobs`) + `quickrs-core` + `oxc`.
#[derive(Clone)]
pub struct CellManager {
    engine: Arc<dyn StateEngine>,
    blobs: Arc<BlobBridge>,
    active: Arc<RwLock<HashMap<CellKey, ActiveCell>>>,
}

impl CellManager {
    pub fn new(engine: Arc<dyn StateEngine>, blobs: Arc<BlobBridge>) -> Self {
        Self {
            engine,
            blobs,
            active: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Wake (or reuse) a cell under `policy`. For `Elastic` cells, acquires a single-writer CAS lease
    /// in `BlobBridge` and hydrates any persisted snapshot into `(app, cell_id)`.
    pub async fn wake(
        &self,
        app: &str,
        cell_id: &str,
        policy: CellPolicy,
        script: String,
    ) -> Result<()> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };

        if let Some(existing) = self.active.write().await.get_mut(&key) {
            existing.last_active = Instant::now();
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

            // Hydrate snapshot from `iroh-blobs` if the cell was previously hibernated
            let snap_key = format!("snapshots/{}/{}.json", app, cell_id);
            if let Some(snap) = self.blobs.get_object(lease_bucket, &snap_key).await? {
                self.engine.import_snapshot(app, cell_id, snap).await?;
            }
        }

        self.active.write().await.insert(
            key,
            ActiveCell {
                policy,
                script,
                lease_etag,
                last_active: Instant::now(),
            },
        );
        Ok(())
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
            cell.script.clone()
        };

        let engine = self.engine.clone();
        let app_owned = app.to_string();
        let cell_owned = cell_id.to_string();
        let expr_owned = expr.to_string();

        tokio::task::block_in_place(move || {
            ACTIVE_CELL_SCOPE.with(|s| {
                *s.borrow_mut() = Some(CellScope {
                    engine,
                    app: app_owned,
                    cell_id: cell_owned,
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

    /// Hibernate an `Elastic` cell: flush snapshot to `BlobBridge`, release CAS lease, and evict from RAM.
    pub async fn hibernate(&self, app: &str, cell_id: &str) -> Result<()> {
        let key = CellKey {
            app: app.to_string(),
            cell_id: cell_id.to_string(),
        };

        let removed = self.active.write().await.remove(&key);
        let Some(cell) = removed else {
            return Ok(());
        };

        if let CellPolicy::Elastic { lease_bucket, .. } = &cell.policy {
            let snapshot = self.engine.export_snapshot(app, cell_id).await?;
            let snap_key = format!("snapshots/{}/{}.json", app, cell_id);
            self.blobs.put_object(lease_bucket, &snap_key, snapshot).await?;

            if cell.lease_etag.is_some() {
                let lease_key = format!("leases/{}/{}.lease", app, cell_id);
                let _ = self.blobs.delete_object(lease_bucket, &lease_key).await;
            }
        }
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
        "graphql" | "gql" => {
            let scope = ACTIVE_CELL_SCOPE.with(|s| {
                s.borrow()
                    .as_ref()
                    .map(|sc| (sc.engine.clone(), sc.app.clone(), sc.cell_id.clone()))
            });
            let Some((engine, app, cell_id)) = scope else {
                return Ok(JsValue::Undefined);
            };
            let Some(nexus) = engine.as_nexus_db() else {
                return Ok(JsValue::Undefined);
            };
            let res_json = if flavor == "graphql" {
                nexus
                    .graphql(&app, &cell_id, &query)
                    .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }))
            } else {
                match nexus.gql(&app, &cell_id, &query) {
                    Ok(rows) => serde_json::Value::Array(rows.iter().map(|v| v.to_json()).collect()),
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                }
            };
            let json_str = serde_json::to_string(&res_json).unwrap_or_else(|_| "null".into());
            ctx.eval(&format!("({})", json_str))
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
}
