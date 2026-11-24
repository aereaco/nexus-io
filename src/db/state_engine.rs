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

        let mut response = q.await?.check()?;
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

fn nexus_to_sur(val: &nexus_db::Value) -> SurValue {
    json_to_sur(&val.to_json())
}

fn sur_to_nexus(val: &SurValue) -> nexus_db::Value {
    nexus_db::Value::from_json(&sur_to_json(val))
}

#[salvo::prelude::async_trait]
impl StateEngine for nexus_db::NexusDb {
    async fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, SurValue)>,
    ) -> Result<Vec<SurValue>> {
        let converted: Vec<(String, nexus_db::Value)> = bindings
            .into_iter()
            .map(|(k, v)| (k, sur_to_nexus(&v)))
            .collect();
        let rows = nexus_db::NexusDb::query_scoped(self, ns, db, surql, converted)?;
        // Match SurrealDB's `response.take::<Vec<Value>>` unwrapping of a top-level Array return
        if rows.len() == 1 {
            if let nexus_db::Value::Array(items) = &rows[0] {
                return Ok(items.iter().map(nexus_to_sur).collect());
            }
        }
        Ok(rows.iter().map(nexus_to_sur).collect())
    }

    async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<SurValue>> {
        Ok(nexus_db::NexusDb::kv_get(self, ns, db, key)?
            .as_ref()
            .map(nexus_to_sur))
    }

    async fn kv_put(&self, ns: &str, db: &str, key: &str, value: SurValue) -> Result<()> {
        nexus_db::NexusDb::kv_put(self, ns, db, key, sur_to_nexus(&value))
    }

    async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()> {
        nexus_db::NexusDb::kv_delete(self, ns, db, key)
    }

    async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, SurValue)>> {
        let entries = nexus_db::NexusDb::kv_list(self, ns, db, prefix)?;
        Ok(entries
            .into_iter()
            .map(|(k, v)| (k, nexus_to_sur(&v)))
            .collect())
    }

    async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes> {
        Ok(Bytes::from(nexus_db::NexusDb::export_snapshot(self, ns, db)?))
    }

    async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()> {
        nexus_db::NexusDb::import_snapshot(self, ns, db, &snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sql_compiler::compile_sqlite_to_surql;
    use surrealdb::engine::local::Mem;
    use surrealdb::Surreal;

    /// Differential test harness: runs identical SurrealQL, SQLite-compiled SQL, KV, and snapshot
    /// operations against both SurrealDB 4.0 and `nexus-db` and asserts identical outputs.
    #[test]
    fn differential_nexus_db_matches_surrealdb_4() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_stack_size(16 * 1024 * 1024)
                    .build()
                    .unwrap();
                rt.block_on(Box::pin(async {
                    let client = Surreal::new::<Mem>(()).await.unwrap();
                    client.use_ns("nexus").use_db("system").await.unwrap();
                    let surreal_engine = Database { client };
                    let nexus_engine = nexus_db::NexusDb::open_mem();

                    let engines: [&dyn StateEngine; 2] = [&surreal_engine, &nexus_engine];
                    let mut results = Vec::new();

                    for eng in engines {
                        // 1. SQLite AST-compiled CREATE TABLE + INSERT + SELECT
                        let ddl = compile_sqlite_to_surql(
                            "CREATE TABLE IF NOT EXISTS tasks (title TEXT, score INT)",
                            vec![],
                        )
                        .unwrap();
                        eng.query_scoped("diff_app", "room_1", &ddl.surql, ddl.bindings)
                            .await
                            .unwrap();

                        let ins1 = compile_sqlite_to_surql(
                            "INSERT INTO tasks (title, score) VALUES (?, ?)",
                            vec![
                                SurValue::String("alpha".into()),
                                SurValue::Number(surrealdb::types::Number::Int(10)),
                            ],
                        )
                        .unwrap();
                        eng.query_scoped("diff_app", "room_1", &ins1.surql, ins1.bindings)
                            .await
                            .unwrap();

                        let ins2 = compile_sqlite_to_surql(
                            "INSERT INTO tasks (title, score) VALUES (?, ?)",
                            vec![
                                SurValue::String("beta".into()),
                                SurValue::Number(surrealdb::types::Number::Int(25)),
                            ],
                        )
                        .unwrap();
                        eng.query_scoped("diff_app", "room_1", &ins2.surql, ins2.bindings)
                            .await
                            .unwrap();

                        let rows = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "SELECT VALUE title FROM tasks WHERE score >= 10 ORDER BY score DESC;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 2. Graph RELATE + traversal + UPDATE/MERGE/UNSET/+= + UNIQUE + expressions
                        eng.query_scoped(
                            "diff_app",
                            "room_1",
                            "CREATE person:alice SET name = 'alice';
                             CREATE person:bob SET name = 'bob';
                             RELATE person:alice->knows->person:bob;
                             UPDATE person:bob MERGE { role: 'eng' };
                             CREATE counter:1 SET val = 5, tmp = 'dropme';
                             UPDATE counter:1 SET val += 7;
                             UPDATE counter:1 UNSET tmp;",
                            vec![],
                        )
                        .await
                        .unwrap();

                        let graph_rows = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "SELECT VALUE string::uppercase(name) FROM person:bob;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        let counter_rows = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "SELECT VALUE val FROM counter:1;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 2b. UNIQUE constraint enforcement (both engines must reject duplicate!)
                        eng.query_scoped(
                            "diff_app",
                            "room_1",
                            "DEFINE TABLE uniq_u SCHEMALESS;
                             DEFINE INDEX idx_u_email ON uniq_u FIELDS email UNIQUE;
                             CREATE uniq_u:1 SET email = 'dup@nexus.io';",
                            vec![],
                        )
                        .await
                        .unwrap();
                        let dup_rejected = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "CREATE uniq_u:2 SET email = 'dup@nexus.io';",
                                vec![],
                            )
                            .await
                            .is_err();

                        // 2c. Expressions: `??`, inline IF, string::lowercase, math::abs
                        let expr_rows = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "RETURN [NONE ?? 'ok', IF 3 > 1 THEN 'yes' ELSE 'no' END, string::lowercase('NEXUS'), math::abs(-9)];",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 3. Cell KV + snapshot round-trip
                        eng.kv_put("diff_app", "room_1", "k1", SurValue::String("v1".into()))
                            .await
                            .unwrap();
                        let kv_val = eng.kv_get("diff_app", "room_1", "k1").await.unwrap();
                        let snap = eng.export_snapshot("diff_app", "room_1").await.unwrap();
                        eng.kv_delete("diff_app", "room_1", "k1").await.unwrap();
                        eng.import_snapshot("diff_app", "room_1", snap).await.unwrap();
                        let kv_after = eng.kv_get("diff_app", "room_1", "k1").await.unwrap();

                        results.push((
                            rows.iter().map(sur_to_json).collect::<Vec<_>>(),
                            graph_rows.iter().map(sur_to_json).collect::<Vec<_>>(),
                            counter_rows.iter().map(sur_to_json).collect::<Vec<_>>(),
                            dup_rejected,
                            expr_rows.iter().map(sur_to_json).collect::<Vec<_>>(),
                            kv_val.as_ref().map(sur_to_json),
                            kv_after.as_ref().map(sur_to_json),
                        ));
                    }

                    assert_eq!(results[0], results[1], "nexus-db diverged from SurrealDB 4.0!");
                }));
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
