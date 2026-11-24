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

#[cfg(feature = "cbor")]
pub fn cbor_decode(data: &[u8], pos: &mut usize) -> anyhow::Result<JsonValue> {
    let head = *data.get(*pos).ok_or_else(|| anyhow::anyhow!("CBOR EOF"))?;
    *pos += 1;
    let major = head >> 5;
    let ai = head & 0x1F;
    match major {
        0 => Ok(json!(cbor_read_len(ai, data, pos)?)),
        1 => Ok(json!(-1i64 - (cbor_read_len(ai, data, pos)? as i64))),
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
