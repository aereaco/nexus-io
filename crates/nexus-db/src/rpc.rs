use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;

use crate::value::Value;
use crate::NexusDb;

/// SurrealDB-compatible JSON-RPC 2.0 request frame (HTTP/WebSocket wire protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub id: Option<JsonValue>,
    pub method: String,
    #[serde(default)]
    pub params: Vec<JsonValue>,
}

/// SurrealDB-compatible JSON-RPC 2.0 response frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// Stateful per-connection RPC session compatible with SurrealDB JS/Rust/Python/Go SDKs & Nexus-UX `$sql()`.
pub struct RpcSession {
    db: NexusDb,
    pub ns: String,
    pub database: String,
    pub vars: HashMap<String, Value>,
    #[cfg(feature = "auth")]
    pub auth: Option<crate::auth::AuthContext>,
    live_subs: HashMap<String, std::sync::mpsc::Receiver<crate::live::LiveNotification>>,
}

impl RpcSession {
    pub fn new(db: NexusDb, ns: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
            vars: HashMap::new(),
            #[cfg(feature = "auth")]
            auth: None,
            live_subs: HashMap::new(),
        }
    }

    /// Drain pending `LIVE SELECT` notifications into SurrealDB-compatible JSON-RPC push frames.
    pub fn drain_live_notifications(&mut self) -> Vec<String> {
        let mut frames = Vec::new();
        for (live_id, rx) in &self.live_subs {
            while let Ok(notif) = rx.try_recv() {
                let frame = json!({
                    "result": {
                        "id": live_id,
                        "action": format!("{:?}", notif.action).to_ascii_uppercase(),
                        "result": notif.result.to_json(),
                    }
                });
                if let Ok(s) = serde_json::to_string(&frame) {
                    frames.push(s);
                }
            }
        }
        frames
    }

    fn exec_query(&self, sql: &str, bindings: Vec<(String, Value)>) -> anyhow::Result<Vec<Value>> {
        #[cfg(feature = "auth")]
        if let Some(ref auth) = self.auth {
            return self
                .db
                .query_scoped_with_auth(&self.ns, &self.database, sql, bindings, auth.clone());
        }
        self.db.query_scoped(&self.ns, &self.database, sql, bindings)
    }

    fn exec_query_multi(
        &self,
        sql: &str,
        bindings: Vec<(String, Value)>,
    ) -> anyhow::Result<Vec<crate::StatementOutcome>> {
        #[cfg(feature = "auth")]
        if let Some(ref auth) = self.auth {
            return self.db.query_scoped_multi_with_auth(
                &self.ns,
                &self.database,
                sql,
                bindings,
                auth.clone(),
            );
        }
        self.db
            .query_scoped_multi(&self.ns, &self.database, sql, bindings)
    }

    pub fn handle_json(&mut self, raw: &str) -> String {
        let req: RpcRequest = match serde_json::from_str(raw) {
            Ok(r) => r,
            Err(e) => {
                let err = RpcResponse {
                    id: None,
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: format!("Invalid JSON-RPC payload: {}", e),
                    }),
                };
                return serde_json::to_string(&err).unwrap_or_default();
            }
        };
        let resp = self.handle(req);
        serde_json::to_string(&resp).unwrap_or_default()
    }

    /// Binary CBOR wire framing (`feature = "cbor"`): decodes RFC 8949 CBOR request frame,
    /// executes via `RpcSession::handle`, and encodes the `RpcResponse` back to CBOR.
    #[cfg(feature = "cbor")]
    pub fn handle_cbor(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut cursor = 0usize;
        let json_val = match cbor_decode(bytes, &mut cursor) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "id": null,
                    "error": { "code": -32700, "message": format!("Invalid CBOR frame: {}", e) }
                });
                let mut out = Vec::new();
                cbor_encode(&err, &mut out);
                return out;
            }
        };
        let req: RpcRequest = match serde_json::from_value(json_val) {
            Ok(r) => r,
            Err(e) => {
                let err = json!({
                    "id": null,
                    "error": { "code": -32600, "message": format!("Invalid RPC request: {}", e) }
                });
                let mut out = Vec::new();
                cbor_encode(&err, &mut out);
                return out;
            }
        };
        let resp = self.handle(req);
        let resp_val = serde_json::to_value(&resp).unwrap_or(JsonValue::Null);
        let mut out = Vec::new();
        cbor_encode(&resp_val, &mut out);
        out
    }

    pub fn handle(&mut self, req: RpcRequest) -> RpcResponse {
        let id = req.id.clone();
        match self.dispatch(&req.method, &req.params) {
            Ok(result) => RpcResponse {
                id,
                result: Some(result),
                error: None,
            },
            Err(e) => RpcResponse {
                id,
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: e.to_string(),
                }),
            },
        }
    }

    fn dispatch(&mut self, method: &str, params: &[JsonValue]) -> anyhow::Result<JsonValue> {
        match method {
            "ping" | "health" => Ok(JsonValue::Null),
            "version" => Ok(json!("nexus-db 0.1.0 (surrealdb-wire-compatible)")),
            "use" => {
                if let Some(ns) = params.first().and_then(|v| v.as_str()) {
                    self.ns = ns.to_string();
                }
                if let Some(db) = params.get(1).and_then(|v| v.as_str()) {
                    self.database = db.to_string();
                }
                Ok(JsonValue::Null)
            }
            "signin" => {
                #[cfg(feature = "auth")]
                {
                    let cred = params
                        .first()
                        .and_then(|v| v.as_object())
                        .ok_or_else(|| anyhow::anyhow!("signin requires credentials object"))?;
                    if let Some(ns) = cred.get("NS").or_else(|| cred.get("ns")).and_then(|v| v.as_str()) {
                        self.ns = ns.to_string();
                    }
                    if let Some(db) = cred.get("DB").or_else(|| cred.get("db")).and_then(|v| v.as_str()) {
                        self.database = db.to_string();
                    }
                    let user = cred
                        .get("user")
                        .or_else(|| cred.get("username"))
                        .and_then(|v| v.as_str());
                    let pass = cred
                        .get("pass")
                        .or_else(|| cred.get("password"))
                        .and_then(|v| v.as_str());
                    if let (Some(u), Some(p)) = (user, pass) {
                        let (token, ctx) = self.db.signin_user(&self.ns, &self.database, u, p)?;
                        self.auth = Some(ctx);
                        return Ok(json!(token));
                    }
                    // Record access (`AC` / `ac`) signin flow
                    if let Some(ac) = cred.get("AC").or_else(|| cred.get("ac")).and_then(|v| v.as_str()) {
                        let access = crate::auth::load_access(
                            self.db.storage.as_ref(),
                            &self.ns,
                            &self.database,
                            ac,
                        )?
                        .ok_or_else(|| anyhow::anyhow!("Access '{}' not found", ac))?;
                        let sql = access
                            .signin_sql
                            .ok_or_else(|| anyhow::anyhow!("Access '{}' has no SIGNIN clause", ac))?;
                        let bindings: Vec<(String, Value)> = cred
                            .iter()
                            .map(|(k, v)| (k.clone(), Value::from_json(v)))
                            .collect();
                        let rows = self.db.query_scoped(&self.ns, &self.database, &sql, bindings)?;
                        let rec = rows
                            .first()
                            .ok_or_else(|| anyhow::anyhow!("Record signin returned no matching record"))?;
                        let rec_id = match rec {
                            Value::Object(m) => m
                                .get("id")
                                .map(|v| v.display_compact())
                                .unwrap_or_else(|| "record:unknown".into()),
                            other => other.display_compact(),
                        };
                        let now = chrono::Utc::now().timestamp();
                        let claims = crate::auth::JwtClaims {
                            iss: Some("nexus-db".into()),
                            iat: Some(now),
                            exp: Some(now + 3600),
                            ns: Some(self.ns.clone()),
                            db: Some(self.database.clone()),
                            ac: Some(ac.to_string()),
                            id: Some(rec_id),
                            ..Default::default()
                        };
                        let secret = access
                            .jwt_key
                            .as_deref()
                            .unwrap_or(crate::auth::DEFAULT_JWT_SECRET);
                        let token = crate::auth::issue_jwt(&claims, secret)?;
                        self.auth = Some(crate::auth::AuthContext::from_jwt_claims(&claims));
                        return Ok(json!(token));
                    }
                    Err(anyhow::anyhow!("signin requires user/pass or AC credentials"))
                }
                #[cfg(not(feature = "auth"))]
                Ok(json!("nexus-session-ok"))
            }
            "signup" => {
                #[cfg(feature = "auth")]
                {
                    let cred = params
                        .first()
                        .and_then(|v| v.as_object())
                        .ok_or_else(|| anyhow::anyhow!("signup requires credentials object"))?;
                    if let Some(ns) = cred.get("NS").or_else(|| cred.get("ns")).and_then(|v| v.as_str()) {
                        self.ns = ns.to_string();
                    }
                    if let Some(db) = cred.get("DB").or_else(|| cred.get("db")).and_then(|v| v.as_str()) {
                        self.database = db.to_string();
                    }
                    let ac = cred
                        .get("AC")
                        .or_else(|| cred.get("ac"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("signup requires AC (access name)"))?;
                    let access = crate::auth::load_access(
                        self.db.storage.as_ref(),
                        &self.ns,
                        &self.database,
                        ac,
                    )?
                    .ok_or_else(|| anyhow::anyhow!("Access '{}' not found", ac))?;
                    let sql = access
                        .signup_sql
                        .ok_or_else(|| anyhow::anyhow!("Access '{}' has no SIGNUP clause", ac))?;
                    let bindings: Vec<(String, Value)> = cred
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::from_json(v)))
                        .collect();
                    let rows = self.db.query_scoped(&self.ns, &self.database, &sql, bindings)?;
                    let rec = rows
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("Record signup returned no record"))?;
                    let rec_id = match rec {
                        Value::Object(m) => m
                            .get("id")
                            .map(|v| v.display_compact())
                            .unwrap_or_else(|| "record:unknown".into()),
                        other => other.display_compact(),
                    };
                    let now = chrono::Utc::now().timestamp();
                    let claims = crate::auth::JwtClaims {
                        iss: Some("nexus-db".into()),
                        iat: Some(now),
                        exp: Some(now + 3600),
                        ns: Some(self.ns.clone()),
                        db: Some(self.database.clone()),
                        ac: Some(ac.to_string()),
                        id: Some(rec_id),
                        ..Default::default()
                    };
                    let secret = access
                        .jwt_key
                        .as_deref()
                        .unwrap_or(crate::auth::DEFAULT_JWT_SECRET);
                    let token = crate::auth::issue_jwt(&claims, secret)?;
                    self.auth = Some(crate::auth::AuthContext::from_jwt_claims(&claims));
                    Ok(json!(token))
                }
                #[cfg(not(feature = "auth"))]
                Ok(json!("nexus-session-ok"))
            }
            "authenticate" => {
                #[cfg(feature = "auth")]
                {
                    let token = params
                        .first()
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("authenticate requires token string"))?;
                    let ctx = self.db.authenticate_token(&self.ns, &self.database, token)?;
                    self.auth = Some(ctx);
                    Ok(JsonValue::Null)
                }
                #[cfg(not(feature = "auth"))]
                Ok(JsonValue::Null)
            }
            "invalidate" => {
                #[cfg(feature = "auth")]
                {
                    self.auth = Some(crate::auth::AuthContext::anonymous());
                }
                Ok(JsonValue::Null)
            }
            "info" => {
                #[cfg(feature = "auth")]
                {
                    return Ok(serde_json::to_value(&self.auth).unwrap_or(JsonValue::Null));
                }
                #[cfg(not(feature = "auth"))]
                Ok(json!({ "ns": self.ns, "db": self.database }))
            }
            "let" => {
                let key = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("let requires variable name"))?;
                let val = params
                    .get(1)
                    .map(Value::from_json)
                    .unwrap_or(Value::Null);
                self.vars.insert(key.to_string(), val);
                Ok(JsonValue::Null)
            }
            "unset" => {
                if let Some(key) = params.first().and_then(|v| v.as_str()) {
                    self.vars.remove(key);
                }
                Ok(JsonValue::Null)
            }
            "query" => {
                let sql = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("query requires SurrealQL string"))?;
                let mut bindings: Vec<(String, Value)> = self
                    .vars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if let Some(JsonValue::Object(map)) = params.get(1) {
                    for (k, v) in map {
                        bindings.push((k.clone(), Value::from_json(v)));
                    }
                }
                let outcomes = self.exec_query_multi(sql, bindings)?;
                let frames: Vec<JsonValue> = outcomes
                    .into_iter()
                    .map(|o| {
                        let json_rows: Vec<JsonValue> =
                            o.result.iter().map(Value::to_json).collect();
                        json!({
                            "time": format!("{}µs", o.time_us),
                            "status": o.status,
                            "result": json_rows
                        })
                    })
                    .collect();
                Ok(JsonValue::Array(frames))
            }
            "select" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("select requires table or record id"))?;
                let rows = self.exec_query(&format!("SELECT * FROM {};", thing), vec![])?;
                Ok(JsonValue::Array(rows.iter().map(Value::to_json).collect()))
            }
            "create" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("create requires table or record id"))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!({}));
                let rows = self.exec_query(
                    &format!("CREATE {} CONTENT $data;", thing),
                    vec![("data".into(), Value::from_json(&data))],
                )?;
                Ok(rows.first().map(Value::to_json).unwrap_or(JsonValue::Null))
            }
            "insert" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("insert requires table name"))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!([]));
                let items = match data {
                    JsonValue::Array(arr) => arr,
                    other => vec![other],
                };
                let mut inserted = Vec::new();
                for item in items {
                    let rows = self.exec_query(
                        &format!("CREATE {} CONTENT $data;", thing),
                        vec![("data".into(), Value::from_json(&item))],
                    )?;
                    inserted.extend(rows.iter().map(Value::to_json));
                }
                Ok(JsonValue::Array(inserted))
            }
            "insert_relation" => {
                let table = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("insert_relation requires edge table"))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!({}));
                let from = data
                    .get("in")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("insert_relation requires 'in' record id"))?;
                let to = data
                    .get("out")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("insert_relation requires 'out' record id"))?;
                let rows = self.exec_query(
                    &format!("RELATE {}->{}->{} CONTENT $data;", from, table, to),
                    vec![("data".into(), Value::from_json(&data))],
                )?;
                Ok(JsonValue::Array(rows.iter().map(Value::to_json).collect()))
            }
            "relate" => {
                let from = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("relate requires 'in' record id"))?;
                let edge = params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("relate requires edge table"))?;
                let to = params
                    .get(2)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("relate requires 'out' record id"))?;
                let sql = if let Some(data) = params.get(3) {
                    let rows = self.exec_query(
                        &format!("RELATE {}->{}->{} CONTENT $data;", from, edge, to),
                        vec![("data".into(), Value::from_json(data))],
                    )?;
                    return Ok(rows.first().map(Value::to_json).unwrap_or(JsonValue::Null));
                } else {
                    format!("RELATE {}->{}->{};", from, edge, to)
                };
                let rows = self.exec_query(&sql, vec![])?;
                Ok(rows.first().map(Value::to_json).unwrap_or(JsonValue::Null))
            }
            "update" | "upsert" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("{} requires table or record id", method))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!({}));
                let kw = method.to_ascii_uppercase();
                let rows = self.exec_query(
                    &format!("{} {} CONTENT $data;", kw, thing),
                    vec![("data".into(), Value::from_json(&data))],
                )?;
                Ok(JsonValue::Array(rows.iter().map(Value::to_json).collect()))
            }
            "merge" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("merge requires table or record id"))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!({}));
                let rows = self.exec_query(
                    &format!("UPDATE {} MERGE $data;", thing),
                    vec![("data".into(), Value::from_json(&data))],
                )?;
                Ok(JsonValue::Array(rows.iter().map(Value::to_json).collect()))
            }
            "patch" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("patch requires table or record id"))?;
                let ops = params
                    .get(1)
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow::anyhow!("patch requires JSON Patch array"))?;
                let mut set_clauses = Vec::new();
                let mut unset_fields = Vec::new();
                let mut bindings = Vec::new();
                for (i, op) in ops.iter().enumerate() {
                    let kind = op.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    let path = op
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim_start_matches('/')
                        .replace('/', ".");
                    if path.is_empty() {
                        continue;
                    }
                    match kind {
                        "add" | "replace" => {
                            let val = op.get("value").cloned().unwrap_or(JsonValue::Null);
                            let pname = format!("p{}", i);
                            set_clauses.push(format!("{} = ${}", path, pname));
                            bindings.push((pname, Value::from_json(&val)));
                        }
                        "remove" => unset_fields.push(path),
                        _ => {}
                    }
                }
                let mut last = Vec::new();
                if !set_clauses.is_empty() {
                    last = self.exec_query(
                        &format!("UPDATE {} SET {};", thing, set_clauses.join(", ")),
                        bindings,
                    )?;
                }
                if !unset_fields.is_empty() {
                    last = self.exec_query(
                        &format!("UPDATE {} UNSET {};", thing, unset_fields.join(", ")),
                        vec![],
                    )?;
                }
                Ok(JsonValue::Array(last.iter().map(Value::to_json).collect()))
            }
            "delete" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("delete requires table or record id"))?;
                let _ = self.exec_query(&format!("DELETE {};", thing), vec![])?;
                Ok(JsonValue::Null)
            }
            "run" => {
                let fn_name = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("run requires function name (e.g. fn::foo)"))?;
                let args = params
                    .get(2)
                    .or_else(|| params.get(1))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut arg_names = Vec::new();
                let mut bindings = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    let pname = format!("a{}", i);
                    arg_names.push(format!("${}", pname));
                    bindings.push((pname, Value::from_json(a)));
                }
                let rows = self.exec_query(
                    &format!("RETURN {}({});", fn_name, arg_names.join(", ")),
                    bindings,
                )?;
                Ok(rows.first().map(Value::to_json).unwrap_or(JsonValue::Null))
            }
            "graphql" => {
                #[cfg(feature = "graphql")]
                {
                    let q = params
                        .first()
                        .and_then(|v| v.get("query").and_then(|s| s.as_str()).or_else(|| v.as_str()))
                        .ok_or_else(|| anyhow::anyhow!("graphql requires query string"))?;
                    return self.db.graphql(&self.ns, &self.database, q);
                }
                #[cfg(not(feature = "graphql"))]
                Err(anyhow::anyhow!("Enable feature 'graphql' to use RPC graphql"))
            }
            "export" => {
                let dump = self.db.export_surql(&self.ns, &self.database)?;
                Ok(json!(dump))
            }
            "import" => {
                let dump = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("import requires SurrealQL string"))?;
                let count = self.db.import_surql(&self.ns, &self.database, dump)?;
                Ok(json!({ "imported_statements": count }))
            }
            "live" => {
                let table = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("live requires table name"))?;
                let (live_id, rx) = self.db.subscribe_live(&self.ns, &self.database, table);
                self.live_subs.insert(live_id.clone(), rx);
                Ok(json!(live_id))
            }
            "kill" => {
                let live_id = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("kill requires live query uuid"))?;
                self.live_subs.remove(live_id);
                self.db.kill_live(live_id);
                Ok(JsonValue::Null)
            }
            other => Err(anyhow::anyhow!("Unsupported SurrealDB RPC method '{}'", other)),
        }
    }
}

#[cfg(feature = "cbor")]
fn cbor_write_head(major: u8, val: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if val < 24 {
        out.push(m | (val as u8));
    } else if val <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(val as u8);
    } else if val <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

#[cfg(feature = "cbor")]
pub fn cbor_encode(v: &JsonValue, out: &mut Vec<u8>) {
    match v {
        JsonValue::Null => out.push(0xF6),
        JsonValue::Bool(false) => out.push(0xF4),
        JsonValue::Bool(true) => out.push(0xF5),
        JsonValue::Number(n) => {
            if let Some(u) = n.as_u64() {
                cbor_write_head(0, u, out);
            } else if let Some(i) = n.as_i64() {
                cbor_write_head(1, (-1 - i) as u64, out);
            } else if let Some(f) = n.as_f64() {
                out.push(0xFB);
                out.extend_from_slice(&f.to_be_bytes());
            }
        }
        JsonValue::String(s) => {
            cbor_write_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        JsonValue::Array(arr) => {
            cbor_write_head(4, arr.len() as u64, out);
            for item in arr {
                cbor_encode(item, out);
            }
        }
        JsonValue::Object(map) => {
            cbor_write_head(5, map.len() as u64, out);
            for (k, val) in map {
                cbor_write_head(3, k.len() as u64, out);
                out.extend_from_slice(k.as_bytes());
                cbor_encode(val, out);
            }
        }
    }
}

#[cfg(feature = "cbor")]
fn cbor_read_len(ai: u8, data: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            let b = *data.get(*pos).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
            *pos += 1;
            Ok(b as u64)
        }
        25 => {
            let s = data.get(*pos..*pos + 2).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
            *pos += 2;
            Ok(u16::from_be_bytes([s[0], s[1]]) as u64)
        }
        26 => {
            let s = data.get(*pos..*pos + 4).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
            *pos += 4;
            Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64)
        }
        27 => {
            let s = data.get(*pos..*pos + 8).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
            *pos += 8;
            Ok(u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        }
        _ => Err(anyhow::anyhow!("Unsupported CBOR additional info {}", ai)),
    }
}

/// SurrealDB RFC 8949 CBOR Semantic Tags (SDK wire compatibility):
/// - Tag 6: NONE
/// - Tag 7: Table name
/// - Tag 8: RecordId (`[tb, id]`)
/// - Tag 12: Datetime (`[secs, nanos]` or ISO-8601 string)
/// - Tag 14: Duration (`[secs, nanos]` or duration string)
/// - Tag 37: UUID (16-byte binary or string)
/// - Tags 88..=94: GeoJSON Geometry
#[cfg(feature = "cbor")]
pub const CBOR_TAG_NONE: u64 = 6;
#[cfg(feature = "cbor")]
pub const CBOR_TAG_TABLE: u64 = 7;
#[cfg(feature = "cbor")]
pub const CBOR_TAG_RECORD_ID: u64 = 8;
#[cfg(feature = "cbor")]
pub const CBOR_TAG_DATETIME: u64 = 12;
#[cfg(feature = "cbor")]
pub const CBOR_TAG_DURATION: u64 = 14;
#[cfg(feature = "cbor")]
pub const CBOR_TAG_UUID: u64 = 37;

/// Encode a `Value` with SurrealDB-compatible RFC 8949 CBOR semantic tags.
#[cfg(feature = "cbor")]
pub fn cbor_encode_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::None => {
            cbor_write_head(6, CBOR_TAG_NONE, out);
            out.push(0xF6);
        }
        Value::Null => out.push(0xF6),
        Value::Bool(false) => out.push(0xF4),
        Value::Bool(true) => out.push(0xF5),
        Value::Int(i) => {
            if *i >= 0 {
                cbor_write_head(0, *i as u64, out);
            } else {
                cbor_write_head(1, (-1 - *i) as u64, out);
            }
        }
        Value::Float(f) => {
            out.push(0xFB);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Value::String(s) => {
            cbor_write_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::DateTime(dt) => {
            cbor_write_head(6, CBOR_TAG_DATETIME, out);
            cbor_write_head(3, dt.len() as u64, out);
            out.extend_from_slice(dt.as_bytes());
        }
        Value::Duration(secs) => {
            cbor_write_head(6, CBOR_TAG_DURATION, out);
            cbor_write_head(4, 2, out);
            cbor_write_head(0, (*secs).max(0) as u64, out);
            cbor_write_head(0, 0, out);
        }
        Value::Bytes(b) => {
            cbor_write_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Decimal(d) => {
            cbor_write_head(3, d.len() as u64, out);
            out.extend_from_slice(d.as_bytes());
        }
        Value::RecordId { tb, id } => {
            cbor_write_head(6, CBOR_TAG_RECORD_ID, out);
            cbor_write_head(4, 2, out);
            cbor_write_head(3, tb.len() as u64, out);
            out.extend_from_slice(tb.as_bytes());
            cbor_write_head(3, id.len() as u64, out);
            out.extend_from_slice(id.as_bytes());
        }
        Value::Array(arr) => {
            cbor_write_head(4, arr.len() as u64, out);
            for item in arr {
                cbor_encode_value(item, out);
            }
        }
        Value::Object(map) => {
            cbor_write_head(5, map.len() as u64, out);
            for (k, val) in map {
                cbor_write_head(3, k.len() as u64, out);
                out.extend_from_slice(k.as_bytes());
                cbor_encode_value(val, out);
            }
        }
    }
}

#[cfg(feature = "cbor")]
pub fn cbor_decode(data: &[u8], pos: &mut usize) -> anyhow::Result<JsonValue> {
    let head = *data.get(*pos).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
    *pos += 1;
    let major = head >> 5;
    let ai = head & 0x1F;
    match major {
        0 => Ok(json!(cbor_read_len(ai, data, pos)?)),
        1 => Ok(json!(-1i64 - (cbor_read_len(ai, data, pos)? as i64))),
        2 => {
            let len = cbor_read_len(ai, data, pos)? as usize;
            let b = data.get(*pos..*pos + len).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
            *pos += len;
            Ok(JsonValue::Array(b.iter().map(|&x| json!(x)).collect()))
        }
        3 => {
            let len = cbor_read_len(ai, data, pos)? as usize;
            let s = data.get(*pos..*pos + len).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
            *pos += len;
            Ok(JsonValue::String(String::from_utf8_lossy(s).to_string()))
        }
        4 => {
            let len = cbor_read_len(ai, data, pos)? as usize;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(cbor_decode(data, pos)?);
            }
            Ok(JsonValue::Array(arr))
        }
        5 => {
            let len = cbor_read_len(ai, data, pos)? as usize;
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let k = match cbor_decode(data, pos)? {
                    JsonValue::String(s) => s,
                    other => other.to_string(),
                };
                let v = cbor_decode(data, pos)?;
                map.insert(k, v);
            }
            Ok(JsonValue::Object(map))
        }
        6 => {
            // SurrealDB RFC 8949 semantic tags (6=NONE, 7=Table, 8=RecordId, 12=Datetime, 14=Duration, 37=UUID, 88..=94=Geo)
            let tag = cbor_read_len(ai, data, pos)?;
            let inner = cbor_decode(data, pos)?;
            match tag {
                CBOR_TAG_NONE => Ok(JsonValue::Null),
                CBOR_TAG_TABLE | CBOR_TAG_DATETIME | CBOR_TAG_DURATION => Ok(inner),
                CBOR_TAG_RECORD_ID => {
                    if let JsonValue::Array(ref arr) = inner {
                        if arr.len() == 2 {
                            let tb = arr[0].as_str().unwrap_or_default();
                            let id = match &arr[1] {
                                JsonValue::String(s) => s.clone(),
                                other => other.to_string(),
                            };
                            return Ok(JsonValue::String(format!("{}:{}", tb, id)));
                        }
                    }
                    Ok(inner)
                }
                CBOR_TAG_UUID => {
                    if let JsonValue::Array(ref bytes) = inner {
                        if bytes.len() == 16 {
                            let mut raw = [0u8; 16];
                            for (i, b) in bytes.iter().enumerate() {
                                raw[i] = b.as_u64().unwrap_or(0) as u8;
                            }
                            return Ok(JsonValue::String(uuid::Uuid::from_bytes(raw).to_string()));
                        }
                    }
                    Ok(inner)
                }
                88..=94 => Ok(json!({ "type": format!("GeoTag({})", tag), "coordinates": inner })),
                _ => Ok(inner),
            }
        }
        7 => match ai {
            20 => Ok(JsonValue::Bool(false)),
            21 => Ok(JsonValue::Bool(true)),
            22 | 23 => Ok(JsonValue::Null),
            27 => {
                let s = data.get(*pos..*pos + 8).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
                *pos += 8;
                let f = f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
                Ok(json!(f))
            }
            _ => Err(anyhow::anyhow!("Unsupported CBOR simple value {}", ai)),
        },
        _ => Err(anyhow::anyhow!("Unsupported CBOR major type {}", major)),
    }
}
