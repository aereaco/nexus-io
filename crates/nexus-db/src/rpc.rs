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

/// Stateful per-connection RPC session compatible with SurrealDB JS/Rust SDKs & Nexus-UX `$sql()`.
pub struct RpcSession {
    db: NexusDb,
    pub ns: String,
    pub database: String,
    pub vars: HashMap<String, Value>,
}

impl RpcSession {
    pub fn new(db: NexusDb, ns: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
            vars: HashMap::new(),
        }
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
            "ping" => Ok(JsonValue::Null),
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
            "signin" | "signup" | "authenticate" => {
                // Local embedded session auth hook (delegated to Nexus-IO SecurityKernel at gateway)
                Ok(json!("nexus-session-ok"))
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
                let rows = self
                    .db
                    .query_scoped(&self.ns, &self.database, sql, bindings)?;
                let json_rows: Vec<JsonValue> = rows.iter().map(Value::to_json).collect();
                Ok(json!([{ "status": "OK", "result": json_rows }]))
            }
            "select" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("select requires table or record id"))?;
                let rows = self.db.query_scoped(
                    &self.ns,
                    &self.database,
                    &format!("SELECT * FROM {};", thing),
                    vec![],
                )?;
                Ok(JsonValue::Array(rows.iter().map(Value::to_json).collect()))
            }
            "create" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("create requires table or record id"))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!({}));
                let rows = self.db.query_scoped(
                    &self.ns,
                    &self.database,
                    &format!("CREATE {} CONTENT $data;", thing),
                    vec![("data".into(), Value::from_json(&data))],
                )?;
                Ok(rows.first().map(Value::to_json).unwrap_or(JsonValue::Null))
            }
            "update" | "upsert" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("{} requires table or record id", method))?;
                let data = params.get(1).cloned().unwrap_or_else(|| json!({}));
                let kw = method.to_ascii_uppercase();
                let rows = self.db.query_scoped(
                    &self.ns,
                    &self.database,
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
                let rows = self.db.query_scoped(
                    &self.ns,
                    &self.database,
                    &format!("UPDATE {} MERGE $data;", thing),
                    vec![("data".into(), Value::from_json(&data))],
                )?;
                Ok(JsonValue::Array(rows.iter().map(Value::to_json).collect()))
            }
            "delete" => {
                let thing = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("delete requires table or record id"))?;
                let _ = self.db.query_scoped(
                    &self.ns,
                    &self.database,
                    &format!("DELETE {};", thing),
                    vec![],
                )?;
                Ok(JsonValue::Null)
            }
            "live" => {
                let table = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("live requires table name"))?;
                let (live_id, _rx) = self.db.subscribe_live(&self.ns, &self.database, table);
                Ok(json!(live_id))
            }
            "kill" => {
                let live_id = params
                    .first()
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("kill requires live query uuid"))?;
                self.db.kill_live(live_id);
                Ok(JsonValue::Null)
            }
            other => Err(anyhow::anyhow!("Unsupported SurrealDB RPC method '{}'", other)),
        }
    }
}
