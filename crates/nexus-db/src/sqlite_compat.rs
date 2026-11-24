//! Pure-Rust SQLite & LibSQL/Turso Hrana HTTP (`/v2/pipeline`) compatibility layer on `nexus-db`.
//!
//! Zero C `libsqlite3` dependency: translates SQLite DML/DDL/PRAGMA and LibSQL Hrana JSON pipelines
//! directly onto `NexusDb`, unified alongside `pgwire.rs` (PostgreSQL v3) and `rpc.rs` (SurrealDB).

use anyhow::Result;
use serde_json::{json, Value as JsonValue};

use crate::value::Value;
use crate::NexusDb;

/// Stateful SQLite-compatible session backed by `NexusDb`.
pub struct SqliteSession {
    db: NexusDb,
    pub ns: String,
    pub database: String,
}

impl SqliteSession {
    pub fn new(db: NexusDb, ns: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
        }
    }

    /// Execute a SQLite / SurrealQL statement with positional `?` bindings.
    pub fn execute(&self, sql: &str, args: Vec<Value>) -> Result<Vec<Value>> {
        let surql = translate_sqlite_basic(sql);
        let mut bindings = Vec::with_capacity(args.len());
        let mut rewritten = String::with_capacity(surql.len() + 16);
        let mut idx = 0usize;
        let mut in_str = false;
        for ch in surql.chars() {
            if ch == '\'' {
                in_str = !in_str;
                rewritten.push(ch);
            } else if ch == '?' && !in_str && idx < args.len() {
                let pname = format!("p{}", idx);
                rewritten.push('$');
                rewritten.push_str(&pname);
                bindings.push((pname, args[idx].clone()));
                idx += 1;
            } else {
                rewritten.push(ch);
            }
        }
        self.db.query_scoped(&self.ns, &self.database, &rewritten, bindings)
    }

    /// Handle a LibSQL / Turso Hrana v2 HTTP pipeline request (`POST /v2/pipeline`).
    pub fn handle_hrana_pipeline(&self, body: &JsonValue) -> JsonValue {
        let requests = body
            .get("requests")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut results = Vec::with_capacity(requests.len());
        for req in requests {
            let rtype = req.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if rtype == "close" {
                results.push(json!({ "type": "ok", "response": { "type": "close" } }));
                continue;
            }
            if rtype != "execute" {
                results.push(json!({ "type": "ok", "response": { "type": rtype } }));
                continue;
            }
            let stmt = req.get("stmt").unwrap_or(&JsonValue::Null);
            let sql = stmt.get("sql").and_then(|v| v.as_str()).unwrap_or("");
            let args: Vec<Value> = stmt
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|a| {
                            if let Some(val) = a.get("value") {
                                Value::from_json(val)
                            } else {
                                Value::from_json(a)
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            match self.execute(sql, args) {
                Ok(rows) => {
                    let mut cols: Vec<String> = Vec::new();
                    let mut out_rows: Vec<JsonValue> = Vec::new();
                    for row in &rows {
                        if let Value::Object(map) = row {
                            if cols.is_empty() {
                                cols = map.keys().cloned().collect();
                            }
                            let cells: Vec<JsonValue> = cols
                                .iter()
                                .map(|c| hrana_cell(map.get(c).unwrap_or(&Value::Null)))
                                .collect();
                            out_rows.push(JsonValue::Array(cells));
                        } else {
                            if cols.is_empty() {
                                cols.push("value".into());
                            }
                            out_rows.push(JsonValue::Array(vec![hrana_cell(row)]));
                        }
                    }
                    let col_meta: Vec<JsonValue> = cols
                        .into_iter()
                        .map(|name| json!({ "name": name, "decltype": null }))
                        .collect();
                    results.push(json!({
                        "type": "ok",
                        "response": {
                            "type": "execute",
                            "result": {
                                "cols": col_meta,
                                "rows": out_rows,
                                "affected_row_count": rows.len(),
                                "last_insert_rowid": null
                            }
                        }
                    }));
                }
                Err(e) => {
                    results.push(json!({
                        "type": "error",
                        "error": { "message": e.to_string(), "code": "SQL_ERROR" }
                    }));
                }
            }
        }
        json!({ "baton": null, "base_url": null, "results": results })
    }
}

fn hrana_cell(v: &Value) -> JsonValue {
    match v {
        Value::Null | Value::None => json!({ "type": "null" }),
        Value::Int(i) => json!({ "type": "integer", "value": i.to_string() }),
        Value::Float(f) => json!({ "type": "float", "value": f }),
        Value::Bool(b) => json!({ "type": "integer", "value": if *b { "1" } else { "0" } }),
        other => json!({ "type": "text", "value": other.display_compact() }),
    }
}

/// Lightweight SQLite DDL/PRAGMA normalization into SurrealQL for `SqliteSession`.
fn translate_sqlite_basic(sql: &str) -> String {
    let trimmed = sql.trim();
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("PRAGMA TABLE_INFO(") {
        if let Some(tbl) = trimmed[18..].trim_end_matches(';').strip_suffix(')') {
            let clean = tbl.trim().trim_matches(|c| c == '\'' || c == '"' || c == '`');
            return format!("INFO FOR TABLE {};", clean);
        }
    }
    if upper.starts_with("CREATE TABLE") {
        // Extract table name after CREATE TABLE [IF NOT EXISTS] <name>
        let after = trimmed[12..].trim();
        let after_if = if after.to_ascii_uppercase().starts_with("IF NOT EXISTS") {
            after[13..].trim()
        } else {
            after
        };
        let tbl = after_if
            .split(|c: char| c.is_whitespace() || c == '(')
            .next()
            .unwrap_or("tbl")
            .trim_matches(|c| c == '`' || c == '"');
        return format!("DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;", tbl);
    }
    if upper.starts_with("ROLLBACK") {
        return "CANCEL TRANSACTION;".to_string();
    }
    trimmed.to_string()
}
