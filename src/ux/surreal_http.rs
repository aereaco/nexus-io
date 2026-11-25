//! Complete SurrealDB-compatible HTTP REST API (`POST /sql`, `POST /rpc`, `POST /signin`,
//! `POST /signup`, `GET/POST /export`, `POST /import`, `/key/<table>[/:id]`, `/api/:ns/:db/<**path>`,
//! `GET /status`, `GET /ready`, `GET /version`).

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use nexus_db::auth::AuthContext;
use nexus_db::Value as DbValue;
use once_cell::sync::Lazy;
use salvo::async_trait;
use salvo::prelude::*;
use serde_json::{json, Value as JsonValue};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-IP sliding-window rate limiter for `/signin` and `/signup` brute-force protection
/// (max 20 attempts per 60 seconds per client IP).
static AUTH_RATE_LIMITER: Lazy<Mutex<HashMap<String, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn check_auth_rate_limit(client_key: &str) -> bool {
    const MAX_ATTEMPTS: usize = 20;
    const WINDOW: Duration = Duration::from_secs(60);
    let now = Instant::now();
    let mut map = AUTH_RATE_LIMITER.lock().unwrap();
    let q = map.entry(client_key.to_string()).or_default();
    while let Some(&front) = q.front() {
        if now.duration_since(front) > WINDOW {
            q.pop_front();
        } else {
            break;
        }
    }
    if q.len() >= MAX_ATTEMPTS {
        return false;
    }
    q.push_back(now);
    true
}

use crate::db::Database;

pub(crate) fn extract_ns_db(req: &Request) -> (String, String) {
    let ns = req
        .headers()
        .get("surreal-ns")
        .or_else(|| req.headers().get("ns"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("nexus")
        .to_string();
    let db = req
        .headers()
        .get("surreal-db")
        .or_else(|| req.headers().get("db"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("system")
        .to_string();
    (ns, db)
}

fn is_loopback_addr(req: &Request) -> bool {
    let addr = req.remote_addr().to_string();
    addr.contains("127.0.0.1") || addr.contains("::1") || addr.contains("localhost")
}

/// Resolve and enforce HTTP authentication for all data/query endpoints.
///
/// Explicit security boundary:
/// - `Authorization: Bearer <jwt|bearer>` or `Basic <base64>` is ALWAYS verified via `nexus-db`.
/// - Missing `Authorization` is REJECTED (`401 Unauthorized`) by default.
/// - Unauthenticated local dev access is ONLY permitted when BOTH `NEXUS_ALLOW_UNAUTH_LOCAL=1`
///   AND the request originates from loopback (`127.0.0.1` / `::1`).
pub(crate) fn resolve_http_auth(
    req: &Request,
    db: &Database,
    ns: &str,
    database: &str,
) -> Result<Option<AuthContext>, String> {
    let Some(header) = req.headers().get("authorization").and_then(|v| v.to_str().ok()) else {
        if std::env::var("NEXUS_ALLOW_UNAUTH_LOCAL").as_deref() == Ok("1") && is_loopback_addr(req) {
            return Ok(None);
        }
        return Err(
            "Authentication required (provide Authorization: Bearer <token> or Basic <creds>; for local dev set NEXUS_ALLOW_UNAUTH_LOCAL=1)"
                .to_string(),
        );
    };
    if let Some(bearer) = header.strip_prefix("Bearer ").or_else(|| header.strip_prefix("bearer ")) {
        return db
            .inner
            .authenticate_token(ns, database, bearer.trim())
            .map(Some)
            .map_err(|e| e.to_string());
    }
    if let Some(b64) = header.strip_prefix("Basic ").or_else(|| header.strip_prefix("basic ")) {
        let decoded = BASE64_STD
            .decode(b64.trim())
            .map_err(|_| "Invalid Basic auth base64".to_string())?;
        let creds = String::from_utf8(decoded).map_err(|_| "Invalid Basic auth UTF-8".to_string())?;
        let (user, pass) = creds
            .split_once(':')
            .ok_or_else(|| "Basic auth must be user:pass".to_string())?;
        let (_, ctx) = db
            .inner
            .signin_user(ns, database, user, pass)
            .map_err(|e| e.to_string())?;
        return Ok(Some(ctx));
    }
    Err("Unsupported Authorization scheme".to_string())
}

/// `POST /sql` — SurrealDB HTTP SQL endpoint.
#[derive(Clone)]
pub struct SurrealSqlHandler {
    pub db: Arc<Database>,
}

#[async_trait]
impl Handler for SurrealSqlHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let (ns, database) = extract_ns_db(req);
        let auth = match resolve_http_auth(req, &self.db, &ns, &database) {
            Ok(a) => a,
            Err(msg) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(json!({ "code": 401, "details": msg })));
                return;
            }
        };
        let body = match req.payload().await {
            Ok(b) => String::from_utf8_lossy(b).to_string(),
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!({ "code": 400, "details": e.to_string() })));
                return;
            }
        };
        let exec = match auth {
            Some(ctx) => self
                .db
                .inner
                .query_scoped_multi_with_auth(&ns, &database, &body, vec![], ctx),
            None => self.db.inner.query_scoped_multi(&ns, &database, &body, vec![]),
        };
        match exec {
            Ok(outcomes) => {
                let frames: Vec<JsonValue> = outcomes
                    .into_iter()
                    .map(|o| {
                        let json_rows: Vec<JsonValue> =
                            o.result.iter().map(DbValue::to_json).collect();
                        json!({
                            "time": format!("{}µs", o.time_us),
                            "status": o.status,
                            "result": json_rows
                        })
                    })
                    .collect();
                res.render(Json(JsonValue::Array(frames)));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!([{
                    "time": "0µs",
                    "status": "ERR",
                    "result": e.to_string()
                }])));
            }
        }
    }
}

/// `POST /rpc` — Stateless SurrealDB HTTP JSON-RPC 2.0 / CBOR endpoint.
#[derive(Clone)]
pub struct SurrealHttpRpcHandler {
    pub db: Arc<Database>,
}

#[async_trait]
impl Handler for SurrealHttpRpcHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let (ns, database) = extract_ns_db(req);
        let mut session = self.db.inner.rpc_session(&ns, &database);
        match resolve_http_auth(req, &self.db, &ns, &database) {
            Ok(Some(ctx)) => session.auth = Some(ctx),
            Ok(None) => {}
            Err(msg) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(json!({ "error": { "code": 401, "message": msg } })));
                return;
            }
        }
        let is_cbor = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("cbor"))
            .unwrap_or(false);
        let payload = match req.payload().await {
            Ok(b) => b.clone(),
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!({ "error": { "code": -32700, "message": e.to_string() } })));
                return;
            }
        };
        if is_cbor {
            let reply = session.handle_cbor(&payload);
            res.headers_mut().insert(
                "content-type",
                "application/cbor".parse().unwrap(),
            );
            let _ = res.write_body(reply);
        } else {
            let reply = session.handle_json(&String::from_utf8_lossy(&payload));
            res.headers_mut().insert(
                "content-type",
                "application/json".parse().unwrap(),
            );
            let _ = res.write_body(reply);
        }
    }
}

/// `POST /signin` & `POST /signup` — Standard SurrealDB HTTP authentication endpoints.
#[derive(Clone)]
pub struct SurrealAuthHandler {
    pub db: Arc<Database>,
    pub is_signup: bool,
}

#[async_trait]
impl Handler for SurrealAuthHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let client_ip = req.remote_addr().to_string();
        if !check_auth_rate_limit(&client_ip) {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(json!({
                "code": 429,
                "details": "Too many authentication attempts; retry after 60 seconds"
            })));
            return;
        }
        let (ns, database) = extract_ns_db(req);
        let mut session = self.db.inner.rpc_session(&ns, &database);
        let body: JsonValue = match req.parse_json().await {
            Ok(v) => v,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!({ "code": 400, "details": e.to_string() })));
                return;
            }
        };
        let method = if self.is_signup { "signup" } else { "signin" };
        let resp = session.handle(nexus_db::rpc::RpcRequest {
            id: Some(json!(1)),
            method: method.to_string(),
            params: vec![body],
        });
        if let Some(err) = resp.error {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(json!({ "code": 403, "details": err.message })));
        } else {
            res.render(Json(json!({
                "code": 200,
                "details": "Authentication succeeded",
                "token": resp.result.unwrap_or(JsonValue::Null)
            })));
        }
    }
}

/// `GET/POST /export` and `POST /import`.
#[derive(Clone)]
pub struct SurrealExportImportHandler {
    pub db: Arc<Database>,
    pub is_import: bool,
}

#[async_trait]
impl Handler for SurrealExportImportHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let (ns, database) = extract_ns_db(req);
        match resolve_http_auth(req, &self.db, &ns, &database) {
            Ok(Some(ctx)) if !ctx.can_admin_iam(&ns, &database) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(json!({ "code": 403, "details": "OWNER role required for export/import" })));
                return;
            }
            Ok(_) => {}
            Err(msg) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(json!({ "code": 401, "details": msg })));
                return;
            }
        }
        if self.is_import {
            let dump = match req.payload().await {
                Ok(b) => String::from_utf8_lossy(b).to_string(),
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(json!({ "code": 400, "details": e.to_string() })));
                    return;
                }
            };
            match self.db.inner.import_surql(&ns, &database, &dump) {
                Ok(count) => res.render(Json(json!({ "status": "OK", "imported_statements": count }))),
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(json!({ "status": "ERR", "details": e.to_string() })));
                }
            }
        } else {
            match self.db.inner.export_surql(&ns, &database) {
                Ok(dump) => res.render(Text::Plain(dump)),
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(json!({ "status": "ERR", "details": e.to_string() })));
                }
            }
        }
    }
}

/// `/key/<table>` and `/key/<table>/<id>` — SurrealDB REST KV/record CRUD endpoints.
#[derive(Clone)]
pub struct SurrealKeyHandler {
    pub db: Arc<Database>,
}

#[async_trait]
impl Handler for SurrealKeyHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let (ns, database) = extract_ns_db(req);
        let table = req.param::<String>("table").unwrap_or_default();
        let id = req.param::<String>("id");
        let target = match id {
            Some(ref i) if !i.is_empty() => format!("{}:{}", table, i),
            _ => table,
        };
        let mut session = self.db.inner.rpc_session(&ns, &database);
        match resolve_http_auth(req, &self.db, &ns, &database) {
            Ok(Some(ctx)) => session.auth = Some(ctx),
            Ok(None) => {}
            Err(msg) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(json!({ "code": 401, "details": msg })));
                return;
            }
        }
        let method = req.method().as_str();
        let rpc_req = match method {
            "GET" => nexus_db::rpc::RpcRequest {
                id: Some(json!(1)),
                method: "select".into(),
                params: vec![json!(target)],
            },
            "POST" => {
                let body: JsonValue = req.parse_json().await.unwrap_or_else(|_| json!({}));
                nexus_db::rpc::RpcRequest {
                    id: Some(json!(1)),
                    method: "create".into(),
                    params: vec![json!(target), body],
                }
            }
            "PUT" => {
                let body: JsonValue = req.parse_json().await.unwrap_or_else(|_| json!({}));
                nexus_db::rpc::RpcRequest {
                    id: Some(json!(1)),
                    method: "upsert".into(),
                    params: vec![json!(target), body],
                }
            }
            "PATCH" => {
                let body: JsonValue = req.parse_json().await.unwrap_or_else(|_| json!([]));
                let m = if body.is_array() { "patch" } else { "merge" };
                nexus_db::rpc::RpcRequest {
                    id: Some(json!(1)),
                    method: m.into(),
                    params: vec![json!(target), body],
                }
            }
            "DELETE" => nexus_db::rpc::RpcRequest {
                id: Some(json!(1)),
                method: "delete".into(),
                params: vec![json!(target)],
            },
            _ => {
                res.status_code(StatusCode::METHOD_NOT_ALLOWED);
                return;
            }
        };
        let resp = session.handle(rpc_req);
        if let Some(err) = resp.error {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(json!([{ "status": "ERR", "result": err.message }])));
        } else {
            res.render(Json(json!([{ "status": "OK", "result": resp.result.unwrap_or(JsonValue::Null) }])));
        }
    }
}

/// `/api/<ns>/<db>/<**path>` — invokes custom `DEFINE API` endpoints in `nexus-db`.
#[derive(Clone)]
pub struct SurrealCustomApiHandler {
    pub db: Arc<Database>,
}

#[async_trait]
impl Handler for SurrealCustomApiHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let ns = req.param::<String>("ns").unwrap_or_else(|| "nexus".into());
        let database = req.param::<String>("db").unwrap_or_else(|| "system".into());
        let rest = req.param::<String>("**path").unwrap_or_default();
        let api_path = format!("/{}", rest.trim_start_matches('/'));
        let body: JsonValue = req.parse_json().await.unwrap_or(JsonValue::Null);
        match self.db.inner.invoke_api(
            &ns,
            &database,
            req.method().as_str(),
            &api_path,
            DbValue::from_json(&body),
        ) {
            Ok(val) => res.render(Json(val.to_json())),
            Err(e) => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(json!({ "code": 404, "details": e.to_string() })));
            }
        }
    }
}

#[handler]
pub async fn surreal_status(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Text::Plain("OK"));
}

#[handler]
pub async fn surreal_ready(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Text::Plain("READY"));
}

#[handler]
pub async fn surreal_version(res: &mut Response) {
    res.render(Text::Plain("nexus-db 0.1.0 (surrealdb-wire-compatible)"));
}

/// Unified External Multi-Flavor Query Handler (`POST /query`, `POST /cells/<app>/<cell_id>/query`, `POST /graphql`).
/// Shares the exact same `execute_unified_query` path as internal `CellManager` (`ctx.db.query`)
/// and wakes hibernated cells automatically before querying.
#[derive(Clone)]
pub struct UnifiedQueryHandler {
    pub db: Arc<Database>,
    pub cells: Arc<crate::js::cell::CellManager>,
    pub default_flavor: &'static str,
}

#[async_trait]
impl Handler for UnifiedQueryHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let body: JsonValue = match req.parse_json().await {
            Ok(v) => v,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!({ "code": 400, "details": e.to_string() })));
                return;
            }
        };

        let flavor = body
            .get("flavor")
            .and_then(|v| v.as_str())
            .unwrap_or(self.default_flavor);

        let (ns, database, force_ro) = match (req.param::<String>("app"), req.param::<String>("cell_id")) {
            (Some(app), Some(cell_id)) => {
                let binding = match self
                    .cells
                    .resolve_db_binding(
                        &app,
                        &cell_id,
                        crate::js::cell::CellDbTransport::HttpRest,
                        flavor,
                    )
                    .await
                {
                    Ok(b) => b,
                    Err(e) => {
                        res.status_code(StatusCode::FORBIDDEN);
                        res.render(Json(json!({ "code": 403, "details": e.to_string() })));
                        return;
                    }
                };
                if let Err(e) = self.cells.ensure_awake(&binding.target_ns, &binding.target_db).await {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(json!({ "code": 500, "details": e.to_string() })));
                    return;
                }
                (binding.target_ns, binding.target_db, binding.read_only)
            }
            _ => {
                let (n, d) = extract_ns_db(req);
                (n, d, false)
            }
        };

        let mut auth = match resolve_http_auth(req, &self.db, &ns, &database) {
            Ok(a) => a,
            Err(msg) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(json!({ "code": 401, "details": msg })));
                return;
            }
        };
        if force_ro {
            auth = Some(AuthContext {
                level: nexus_db::auth::AuthLevel::Database(ns.clone(), database.clone()),
                roles: vec![nexus_db::auth::Role::Viewer],
                actor: auth.and_then(|a| a.actor),
                access_name: None,
                token_claims: None,
            });
        }

        let query = body
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let params: Vec<DbValue> = body
            .get("params")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(DbValue::from_json).collect())
            .unwrap_or_default();

        let query_result = match (req.param::<String>("app"), req.param::<String>("cell_id")) {
            (Some(app), Some(cell_id)) => {
                self.cells
                    .query_cell(
                        &app,
                        &cell_id,
                        crate::js::cell::CellDbTransport::HttpRest,
                        flavor,
                        query,
                        params,
                        auth,
                    )
                    .await
            }
            _ => crate::db::sql_compiler::execute_unified_query(
                &self.db.inner,
                &ns,
                &database,
                flavor,
                query,
                params,
                auth,
            ),
        };

        match query_result {
            Ok(result) => {
                if flavor.eq_ignore_ascii_case("graphql") {
                    res.render(Json(result));
                } else {
                    res.render(Json(json!({
                        "status": "OK",
                        "flavor": flavor,
                        "ns": ns,
                        "db": database,
                        "result": result
                    })));
                }
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!({
                    "status": "ERR",
                    "flavor": flavor,
                    "error": e.to_string()
                })));
            }
        }
    }
}

/// `POST /v2/pipeline` — LibSQL / Turso Hrana HTTP SQLite pipeline endpoint backed by `nexus-db`.
#[cfg(feature = "sqlite-hrana")]
#[derive(Clone)]
pub struct SqliteHranaHandler {
    pub db: Arc<Database>,
}

#[cfg(feature = "sqlite-hrana")]
#[async_trait]
impl Handler for SqliteHranaHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let (ns, database) = extract_ns_db(req);
        if let Err(msg) = resolve_http_auth(req, &self.db, &ns, &database) {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(json!({ "code": 401, "details": msg })));
            return;
        }
        let body: JsonValue = match req.parse_json().await {
            Ok(v) => v,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(json!({ "error": e.to_string() })));
                return;
            }
        };
        let session = self.db.inner.sqlite_session(&ns, &database);
        res.render(Json(session.handle_hrana_pipeline(&body)));
    }
}

/// Networked multi-node WAL replication endpoints (`GET /_nexus/wal/entries` & `POST /_nexus/wal/apply`).
static NODE_WAL: Lazy<nexus_db::replication::ReplicationLog> =
    Lazy::new(|| nexus_db::replication::ReplicationLog::new(1));

#[derive(Clone)]
pub struct WalReplicationHandler {
    pub db: Arc<Database>,
    pub is_apply: bool,
}

#[async_trait]
impl Handler for WalReplicationHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let (ns, database) = extract_ns_db(req);
        match resolve_http_auth(req, &self.db, &ns, &database) {
            Ok(Some(ctx)) if !ctx.can_admin_iam(&ns, &database) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(json!({ "code": 403, "details": "OWNER role required for WAL replication" })));
                return;
            }
            Ok(_) => {}
            Err(msg) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(json!({ "code": 401, "details": msg })));
                return;
            }
        }
        if self.is_apply {
            let entries: Vec<nexus_db::replication::WalEntry> = match req.parse_json().await {
                Ok(v) => v,
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(json!({ "error": e.to_string() })));
                    return;
                }
            };
            match NODE_WAL.apply_to_follower(&self.db.inner, &entries) {
                Ok(commit_idx) => res.render(Json(json!({ "status": "OK", "commit_index": commit_idx }))),
                Err(e) => {
                    res.status_code(StatusCode::CONFLICT);
                    res.render(Json(json!({ "status": "ERR", "error": e.to_string() })));
                }
            }
        } else {
            let since = req.query::<u64>("since").unwrap_or(0);
            let entries = NODE_WAL.entries_since(since);
            res.render(Json(json!({
                "term": NODE_WAL.current_term(),
                "commit_index": NODE_WAL.commit_index(),
                "entries": entries
            })));
        }
    }
}
