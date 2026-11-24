use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use surrealdb::types::Value as SurValue;

use super::Database;

/// Internal `StateEngine` abstraction isolating `surrealdb::*` behind scoped `(ns, db)` sessions.
/// Enables `celld` cells (`pinned` and `elastic`) to operate without race conditions and preserves
/// a clean future swap path to a custom Apache-2.0 KV-backed multi-model engine.
#[salvo::prelude::async_trait]
pub trait StateEngine: Send + Sync + 'static {
    /// Execute a SurrealQL query scoped to `(ns, db)` with named parameter bindings.
    async fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, SurValue)>,
    ) -> Result<Vec<SurValue>>;

    /// Cell KV `get(key)` against reserved `_cell_kv` table in `(ns, db)`.
    async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<SurValue>>;

    /// Cell KV `put(key, value)` against reserved `_cell_kv` table in `(ns, db)`.
    async fn kv_put(&self, ns: &str, db: &str, key: &str, value: SurValue) -> Result<()>;

    /// Cell KV `delete(key)` against reserved `_cell_kv` table in `(ns, db)`.
    async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()>;

    /// Cell KV `list(prefix)` returning `(key, value)` pairs in `(ns, db)`.
    async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, SurValue)>>;

    /// Export a JSON snapshot of `_cell_kv` and user tables in `(ns, db)` for `elastic` hibernation.
    async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes>;

    /// Import a previously exported snapshot into `(ns, db)` on `elastic` cell wake.
    async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()>;
}

fn sanitize_ident(ident: &str) -> String {
    ident
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

#[salvo::prelude::async_trait]
impl StateEngine for Database {
    async fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, SurValue)>,
    ) -> Result<Vec<SurValue>> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);

        self.client.use_ns(&ns_clean).use_db(&db_clean).await?;
        let mut q = self.client.query(surql.to_string());
        for (k, v) in bindings {
            q = q.bind((k, v));
        }

        let mut response = q.await?;
        let mut last_rows: Vec<SurValue> = Vec::new();
        let num_stmts = response.num_statements();
        for idx in 0..num_stmts {
            if let Ok(rows) = response.take::<Vec<SurValue>>(idx) {
                last_rows = rows;
            }
        }
        Ok(last_rows)
    }

    async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<SurValue>> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);
        self.client.use_ns(&ns_clean).use_db(&db_clean).await?;

        let _ = self
            .client
            .query("DEFINE TABLE IF NOT EXISTS _cell_kv SCHEMALESS;")
            .await;

        let mut resp = self
            .client
            .query("SELECT VALUE val FROM type::record('_cell_kv', $k)")
            .bind(("k", key.to_string()))
            .await?;
        let rows: Vec<SurValue> = resp.take(0)?;
        Ok(rows.into_iter().next().filter(|v| !matches!(v, SurValue::None | SurValue::Null)))
    }

    async fn kv_put(&self, ns: &str, db: &str, key: &str, value: SurValue) -> Result<()> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);
        self.client.use_ns(&ns_clean).use_db(&db_clean).await?;

        let resp = self
            .client
            .query(
                "DEFINE TABLE IF NOT EXISTS _cell_kv SCHEMALESS;
                 UPSERT type::record('_cell_kv', $k) SET key = $k, val = $v, updated_at = time::now();",
            )
            .bind(("k", key.to_string()))
            .bind(("v", value))
            .await?;
        resp.check()?;
        Ok(())
    }

    async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);
        self.client.use_ns(&ns_clean).use_db(&db_clean).await?;

        let _ = self
            .client
            .query("DELETE type::record('_cell_kv', $k)")
            .bind(("k", key.to_string()))
            .await?;
        Ok(())
    }

    async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, SurValue)>> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);
        self.client.use_ns(&ns_clean).use_db(&db_clean).await?;

        let _ = self
            .client
            .query("DEFINE TABLE IF NOT EXISTS _cell_kv SCHEMALESS;")
            .await;

        let mut resp = self
            .client
            .query("SELECT key, val FROM _cell_kv")
            .await?;
        let rows: Vec<SurValue> = resp.take(0)?;

        let mut out = Vec::new();
        for row in rows {
            if let SurValue::Object(mut obj) = row {
                let k = match obj.remove("key") {
                    Some(SurValue::String(s)) => s,
                    _ => continue,
                };
                if let Some(pfx) = prefix {
                    if !k.starts_with(pfx) {
                        continue;
                    }
                }
                let v = obj.remove("val").unwrap_or(SurValue::Null);
                out.push((k, v));
            }
        }
        Ok(out)
    }

    async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes> {
        let kv_entries = self.kv_list(ns, db, None).await?;
        let mut kv_map: HashMap<String, serde_json::Value> = HashMap::new();
        for (k, v) in kv_entries {
            kv_map.insert(k, sur_to_json(&v));
        }

        let payload = serde_json::json!({
            "ns": sanitize_ident(ns),
            "db": sanitize_ident(db),
            "kv": kv_map,
        });
        Ok(Bytes::from(serde_json::to_vec(&payload)?))
    }

    async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()> {
        let parsed: serde_json::Value = serde_json::from_slice(&snapshot)?;
        if let Some(kv) = parsed.get("kv").and_then(|v| v.as_object()) {
            for (k, v) in kv {
                self.kv_put(ns, db, k, json_to_sur(v)).await?;
            }
        }
        Ok(())
    }
}

fn sur_to_json(val: &SurValue) -> serde_json::Value {
    match val {
        SurValue::None | SurValue::Null => serde_json::Value::Null,
        SurValue::Bool(b) => serde_json::Value::Bool(*b),
        SurValue::Number(n) => match n {
            surrealdb::types::Number::Int(i) => serde_json::json!(*i),
            surrealdb::types::Number::Float(f) => serde_json::json!(*f),
            other => serde_json::Value::String(other.to_string()),
        },
        SurValue::String(s) => serde_json::Value::String(s.clone()),
        SurValue::Array(arr) => serde_json::Value::Array(arr.iter().map(sur_to_json).collect()),
        SurValue::Object(map) => {
            let mut m = serde_json::Map::new();
            for (k, v) in map.iter() {
                m.insert(k.clone(), sur_to_json(v));
            }
            serde_json::Value::Object(m)
        }
        other => serde_json::Value::String(format!("{:?}", other)),
    }
}

fn json_to_sur(val: &serde_json::Value) -> SurValue {
    match val {
        serde_json::Value::Null => SurValue::Null,
        serde_json::Value::Bool(b) => SurValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SurValue::Number(surrealdb::types::Number::Int(i))
            } else if let Some(f) = n.as_f64() {
                SurValue::Number(surrealdb::types::Number::Float(f))
            } else {
                SurValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => SurValue::String(s.clone()),
        serde_json::Value::Array(arr) => {
            SurValue::Array(arr.iter().map(json_to_sur).collect::<Vec<_>>().into())
        }
        serde_json::Value::Object(map) => {
            let mut obj = surrealdb::types::Object::new();
            for (k, v) in map {
                obj.insert(k.clone(), json_to_sur(v));
            }
            SurValue::Object(obj)
        }
    }
}
