use anyhow::Result;
use bytes::Bytes;
use nexus_db::{NexusDb, Value as DbValue};

use super::Database;

/// Unified `StateEngine` abstraction isolating storage behind scoped `(ns, db)` sessions.
/// Backed by MIT-licensed `nexus-db` (`redb` / `BTreeMap`) by default, with optional
/// `surrealdb-ref` adapter strictly for automated differential conformance testing.
#[salvo::prelude::async_trait]
pub trait StateEngine: Send + Sync + 'static {
    async fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, DbValue)>,
    ) -> Result<Vec<DbValue>>;

    async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<DbValue>>;
    async fn kv_put(&self, ns: &str, db: &str, key: &str, value: DbValue) -> Result<()>;
    async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()>;
    async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, DbValue)>>;
    async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes>;
    async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()>;
}

#[salvo::prelude::async_trait]
impl StateEngine for NexusDb {
    async fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, DbValue)>,
    ) -> Result<Vec<DbValue>> {
        let rows = NexusDb::query_scoped(self, ns, db, surql, bindings)?;
        if rows.len() == 1 {
            if let DbValue::Array(items) = &rows[0] {
                return Ok(items.clone());
            }
        }
        Ok(rows)
    }

    async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<DbValue>> {
        NexusDb::kv_get(self, ns, db, key)
    }

    async fn kv_put(&self, ns: &str, db: &str, key: &str, value: DbValue) -> Result<()> {
        NexusDb::kv_put(self, ns, db, key, value)
    }

    async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()> {
        NexusDb::kv_delete(self, ns, db, key)
    }

    async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, DbValue)>> {
        NexusDb::kv_list(self, ns, db, prefix)
    }

    async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes> {
        Ok(Bytes::from(NexusDb::export_snapshot(self, ns, db)?))
    }

    async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()> {
        NexusDb::import_snapshot(self, ns, db, &snapshot)
    }
}

#[salvo::prelude::async_trait]
impl StateEngine for Database {
    async fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, DbValue)>,
    ) -> Result<Vec<DbValue>> {
        StateEngine::query_scoped(&self.inner, ns, db, surql, bindings).await
    }

    async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<DbValue>> {
        StateEngine::kv_get(&self.inner, ns, db, key).await
    }

    async fn kv_put(&self, ns: &str, db: &str, key: &str, value: DbValue) -> Result<()> {
        StateEngine::kv_put(&self.inner, ns, db, key, value).await
    }

    async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()> {
        StateEngine::kv_delete(&self.inner, ns, db, key).await
    }

    async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, DbValue)>> {
        StateEngine::kv_list(&self.inner, ns, db, prefix).await
    }

    async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes> {
        StateEngine::export_snapshot(&self.inner, ns, db).await
    }

    async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()> {
        StateEngine::import_snapshot(&self.inner, ns, db, snapshot).await
    }
}

/// Optional SurrealDB 4.0 reference adapter (`--features surrealdb-ref`) used strictly
/// for automated differential conformance testing against `nexus-db`.
#[cfg(feature = "surrealdb-ref")]
pub mod surreal_ref {
    use super::*;
    use std::collections::HashMap;
    use surrealdb::types::Value as SurValue;
    use surrealdb::Surreal;

    pub struct SurrealRefEngine {
        pub client: Surreal<surrealdb::engine::local::Db>,
    }

    fn sanitize(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
            .collect()
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

    #[salvo::prelude::async_trait]
    impl StateEngine for SurrealRefEngine {
        async fn query_scoped(
            &self,
            ns: &str,
            db: &str,
            surql: &str,
            bindings: Vec<(String, DbValue)>,
        ) -> Result<Vec<DbValue>> {
            self.client.use_ns(&sanitize(ns)).use_db(&sanitize(db)).await?;
            let mut q = self.client.query(surql.to_string());
            for (k, v) in bindings {
                q = q.bind((k, json_to_sur(&v.to_json())));
            }
            let mut response = q.await?.check()?;
            let mut last_rows: Vec<SurValue> = Vec::new();
            for idx in 0..response.num_statements() {
                if let Ok(rows) = response.take::<Vec<SurValue>>(idx) {
                    last_rows = rows;
                }
            }
            Ok(last_rows
                .iter()
                .map(|v| DbValue::from_json(&sur_to_json(v)))
                .collect())
        }

        async fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<DbValue>> {
            self.client.use_ns(&sanitize(ns)).use_db(&sanitize(db)).await?;
            let _ = self.client.query("DEFINE TABLE IF NOT EXISTS _cell_kv SCHEMALESS;").await;
            let mut resp = self
                .client
                .query("SELECT VALUE val FROM type::record('_cell_kv', $k)")
                .bind(("k", key.to_string()))
                .await?;
            let rows: Vec<SurValue> = resp.take(0)?;
            Ok(rows
                .into_iter()
                .next()
                .filter(|v| !matches!(v, SurValue::None | SurValue::Null))
                .map(|v| DbValue::from_json(&sur_to_json(&v))))
        }

        async fn kv_put(&self, ns: &str, db: &str, key: &str, value: DbValue) -> Result<()> {
            self.client.use_ns(&sanitize(ns)).use_db(&sanitize(db)).await?;
            self.client
                .query("DEFINE TABLE IF NOT EXISTS _cell_kv SCHEMALESS; UPSERT type::record('_cell_kv', $k) SET key = $k, val = $v;")
                .bind(("k", key.to_string()))
                .bind(("v", json_to_sur(&value.to_json())))
                .await?
                .check()?;
            Ok(())
        }

        async fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()> {
            self.client.use_ns(&sanitize(ns)).use_db(&sanitize(db)).await?;
            let _ = self
                .client
                .query("DELETE type::record('_cell_kv', $k)")
                .bind(("k", key.to_string()))
                .await?;
            Ok(())
        }

        async fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, DbValue)>> {
            self.client.use_ns(&sanitize(ns)).use_db(&sanitize(db)).await?;
            let _ = self.client.query("DEFINE TABLE IF NOT EXISTS _cell_kv SCHEMALESS;").await;
            let mut resp = self.client.query("SELECT key, val FROM _cell_kv").await?;
            let rows: Vec<SurValue> = resp.take(0)?;
            let mut out = Vec::new();
            for row in rows {
                if let SurValue::Object(mut obj) = row {
                    let k = match obj.remove("key") {
                        Some(SurValue::String(s)) => s,
                        _ => continue,
                    };
                    if let Some(p) = prefix {
                        if !k.starts_with(p) {
                            continue;
                        }
                    }
                    let v = obj.remove("val").unwrap_or(SurValue::Null);
                    out.push((k, DbValue::from_json(&sur_to_json(&v))));
                }
            }
            Ok(out)
        }

        async fn export_snapshot(&self, ns: &str, db: &str) -> Result<Bytes> {
            let mut kv_map = HashMap::new();
            for (k, v) in self.kv_list(ns, db, None).await? {
                kv_map.insert(k, v.to_json());
            }
            let payload = serde_json::json!({ "ns": sanitize(ns), "db": sanitize(db), "kv": kv_map });
            Ok(Bytes::from(serde_json::to_vec(&payload)?))
        }

        async fn import_snapshot(&self, ns: &str, db: &str, snapshot: Bytes) -> Result<()> {
            let parsed: serde_json::Value = serde_json::from_slice(&snapshot)?;
            if let Some(kv) = parsed.get("kv").and_then(|v| v.as_object()) {
                for (k, v) in kv {
                    self.kv_put(ns, db, k, DbValue::from_json(v)).await?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "surrealdb-ref"))]
mod differential_tests {
    use super::surreal_ref::SurrealRefEngine;
    use super::*;
    use crate::db::sql_compiler::compile_sqlite_to_surql;
    use surrealdb::engine::local::Mem;
    use surrealdb::Surreal;

    /// Expanded automated differential conformance test suite (`--features surrealdb-ref`):
    /// Executes identical SQLite-compiled DDL/DML, SurrealQL CRUD, Graph RELATE, `SET +=` / `UNSET` /
    /// `MERGE`, `UNIQUE` enforcement, `DEFAULT` / `ASSERT`, `DEFINE FUNCTION`, `BEGIN ... COMMIT`
    /// atomic rollback, expressions (`??`, inline `IF`, stdlib), and KV snapshots against BOTH
    /// SurrealDB 4.0 and `nexus-db` and asserts identical outputs.
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
                    let surreal_engine = SurrealRefEngine { client };
                    let nexus_engine = NexusDb::open_mem();

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

                        for (t, s) in [("alpha", 10), ("beta", 25)] {
                            let ins = compile_sqlite_to_surql(
                                "INSERT INTO tasks (title, score) VALUES (?, ?)",
                                vec![DbValue::String(t.into()), DbValue::Int(s)],
                            )
                            .unwrap();
                            eng.query_scoped("diff_app", "room_1", &ins.surql, ins.bindings)
                                .await
                                .unwrap();
                        }

                        let rows = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "SELECT VALUE title FROM tasks WHERE score >= 10 ORDER BY score DESC;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 2. Graph RELATE + UPDATE/MERGE/UNSET/+=
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

                        // 3. UNIQUE constraint enforcement + atomic transaction rollback
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
                                "BEGIN TRANSACTION;
                                 CREATE uniq_u:2 SET email = 'ok@nexus.io';
                                 CREATE uniq_u:3 SET email = 'dup@nexus.io';
                                 COMMIT TRANSACTION;",
                                vec![],
                            )
                            .await
                            .is_err();
                        let remaining_u = eng
                            .query_scoped("diff_app", "room_1", "SELECT VALUE email FROM uniq_u;", vec![])
                            .await
                            .unwrap();

                        // 4. Schema DEFAULT + ASSERT enforcement
                        eng.query_scoped(
                            "diff_app",
                            "room_1",
                            "DEFINE TABLE prod SCHEMALESS;
                             DEFINE FIELD status ON prod TYPE string DEFAULT 'active';
                             DEFINE FIELD price ON prod TYPE int ASSERT $value > 0;
                             CREATE prod:1 SET price = 50;",
                            vec![],
                        )
                        .await
                        .unwrap();
                        let bad_assert = eng
                            .query_scoped("diff_app", "room_1", "CREATE prod:2 SET price = -1;", vec![])
                            .await
                            .is_err();
                        let prod_status = eng
                            .query_scoped("diff_app", "room_1", "SELECT VALUE status FROM prod:1;", vec![])
                            .await
                            .unwrap();

                        // 5. Expressions: `??`, inline IF, string::lowercase, math::abs
                        let expr_rows = eng
                            .query_scoped(
                                "diff_app",
                                "room_1",
                                "RETURN [NONE ?? 'ok', IF 3 > 1 THEN 'yes' ELSE 'no' END, string::lowercase('NEXUS'), math::abs(-9)];",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 6. Cell KV + snapshot round-trip
                        eng.kv_put("diff_app", "room_1", "k1", DbValue::String("v1".into()))
                            .await
                            .unwrap();
                        let kv_val = eng.kv_get("diff_app", "room_1", "k1").await.unwrap();
                        let snap = eng.export_snapshot("diff_app", "room_1").await.unwrap();
                        eng.kv_delete("diff_app", "room_1", "k1").await.unwrap();
                        eng.import_snapshot("diff_app", "room_1", snap).await.unwrap();
                        let kv_after = eng.kv_get("diff_app", "room_1", "k1").await.unwrap();

                        results.push((
                            rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            graph_rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            counter_rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            dup_rejected,
                            remaining_u.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            bad_assert,
                            prod_status.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            expr_rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            kv_val.as_ref().map(DbValue::to_json),
                            kv_after.as_ref().map(DbValue::to_json),
                        ));
                    }

                    assert_eq!(results[0], results[1], "nexus-db diverged from SurrealDB 4.0!");
                }));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Second differential suite covering GROUP BY aggregates, DEFINE FUNCTION,
    /// UPSERT/DELETE/LIMIT/START/OMIT/SPLIT, and array/string stdlib parity.
    #[test]
    fn differential_aggregates_functions_dml_and_stdlib() {
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
                    let surreal_engine = SurrealRefEngine { client };
                    let nexus_engine = NexusDb::open_mem();

                    let engines: [&dyn StateEngine; 2] = [&surreal_engine, &nexus_engine];
                    let mut results = Vec::new();

                    for eng in engines {
                        // 1. Seed sales data & test GROUP BY + count/sum/min/max
                        eng.query_scoped(
                            "diff_agg",
                            "room_2",
                            "CREATE sale:1 SET region = 'east', amount = 10;
                             CREATE sale:2 SET region = 'east', amount = 30;
                             CREATE sale:3 SET region = 'west', amount = 50;",
                            vec![],
                        )
                        .await
                        .unwrap();

                        let agg_rows = eng
                            .query_scoped(
                                "diff_agg",
                                "room_2",
                                "SELECT region, count() AS n, math::sum(amount) AS total, math::min(amount) AS lo, math::max(amount) AS hi FROM sale GROUP BY region ORDER BY region ASC;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 2. UPSERT + DELETE + LIMIT/START + OMIT
                        eng.query_scoped(
                            "diff_agg",
                            "room_2",
                            "UPSERT item:a SET name = 'a', rank = 1, secret = 'x';
                             UPSERT item:b SET name = 'b', rank = 2, secret = 'y';
                             UPSERT item:c SET name = 'c', rank = 3, secret = 'z';
                             UPSERT item:b SET name = 'b2', rank = 2, secret = 'y2';
                             DELETE item:c;",
                            vec![],
                        )
                        .await
                        .unwrap();

                        let page_rows = eng
                            .query_scoped(
                                "diff_agg",
                                "room_2",
                                "SELECT * OMIT id, secret FROM item ORDER BY rank ASC LIMIT 1 START 1;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 3. SPLIT on array field
                        eng.query_scoped(
                            "diff_agg",
                            "room_2",
                            "CREATE post:1 SET title = 'hi', tags = ['rust', 'db'];",
                            vec![],
                        )
                        .await
                        .unwrap();

                        let split_rows = eng
                            .query_scoped(
                                "diff_agg",
                                "room_2",
                                "SELECT VALUE tags FROM post:1 SPLIT tags ORDER BY tags ASC;",
                                vec![],
                            )
                            .await
                            .unwrap();

                        // 4. DEFINE FUNCTION + array/string stdlib
                        eng.query_scoped(
                            "diff_agg",
                            "room_2",
                            "DEFINE FUNCTION fn::double($x: int) { RETURN $x * 2; };",
                            vec![],
                        )
                        .await
                        .unwrap();

                        let fn_and_stdlib = eng
                            .query_scoped(
                                "diff_agg",
                                "room_2",
                                "RETURN [fn::double(21), array::len([1, 2, 3]), array::distinct([3, 1, 3, 2]), string::concat('nexus', '-', 'io')];",
                                vec![],
                            )
                            .await
                            .unwrap();

                        results.push((
                            agg_rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            page_rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            split_rows.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                            fn_and_stdlib.iter().map(DbValue::to_json).collect::<Vec<_>>(),
                        ));
                    }

                    assert_eq!(
                        results[0], results[1],
                        "nexus-db diverged from SurrealDB 4.0 on aggregates/functions/DML/stdlib!"
                    );
                }));
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
