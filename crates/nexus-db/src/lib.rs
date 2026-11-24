pub mod engine;
pub mod live;
pub mod parser;
pub mod rpc;
pub mod stdlib;
pub mod storage;
pub mod value;

#[cfg(feature = "fts")]
pub mod search;
#[cfg(feature = "vector")]
pub mod vector_hnsw;
#[cfg(feature = "geo")]
pub mod geo;
#[cfg(feature = "crypto")]
pub mod crypto_ext;

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{mpsc, Arc};

use crate::engine::ExecContext;
use crate::live::{LiveBroker, LiveNotification};
use crate::parser::parse_surql;
use crate::rpc::RpcSession;
use crate::storage::{encode_key, MemStorage, RedbStorage, StorageBackend, PREFIX_CELL_KV};
pub use crate::value::Value;

/// Clean-room, MIT-licensed, ultra-low-footprint SurrealQL-compatible embedded multi-model database.
#[derive(Clone)]
pub struct NexusDb {
    storage: Arc<dyn StorageBackend>,
    live: Arc<LiveBroker>,
}

impl NexusDb {
    /// Open an in-memory `BTreeMap`-backed database (instant startup for tests & ephemeral cells).
    pub fn open_mem() -> Self {
        Self {
            storage: Arc::new(MemStorage::new()),
            live: Arc::new(LiveBroker::new()),
        }
    }

    /// Open a persistent ACID MVCC `redb` database on disk.
    pub fn open_disk<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            storage: Arc::new(RedbStorage::open(path)?),
            live: Arc::new(LiveBroker::new()),
        })
    }

    /// Subscribe to real-time `LIVE SELECT` notifications on `(ns, db, table)`.
    pub fn subscribe_live(
        &self,
        ns: &str,
        db: &str,
        table: &str,
    ) -> (String, mpsc::Receiver<LiveNotification>) {
        self.live
            .subscribe(&sanitize_ident(ns), &sanitize_ident(db), table)
    }

    /// Cancel an active `LIVE SELECT` subscription (`KILL <uuid>`).
    pub fn kill_live(&self, live_id: &str) -> bool {
        self.live.kill(live_id)
    }

    /// Create a SurrealDB-compatible JSON-RPC 2.0 session (for WebSocket / HTTP wire protocol).
    pub fn rpc_session(&self, ns: &str, db: &str) -> RpcSession {
        RpcSession::new(self.clone(), sanitize_ident(ns), sanitize_ident(db))
    }

    /// Execute one or more SurrealQL statements scoped to `(ns, db)` with named `$param` bindings.
    pub fn query_scoped(
        &self,
        ns: &str,
        db: &str,
        surql: &str,
        bindings: Vec<(String, Value)>,
    ) -> Result<Vec<Value>> {
        let stmts = parse_surql(surql)?;
        let params: HashMap<String, Value> = bindings.into_iter().collect();
        let mut ctx = ExecContext::new(
            self.storage.as_ref(),
            self.live.as_ref(),
            sanitize_ident(ns),
            sanitize_ident(db),
            params,
        );
        ctx.execute_all(&stmts)
    }

    /// Fast-path KV `get(key)` in `(ns, db)`.
    pub fn kv_get(&self, ns: &str, db: &str, key: &str) -> Result<Option<Value>> {
        let raw_key = encode_key(PREFIX_CELL_KV, &[&sanitize_ident(ns), &sanitize_ident(db), key]);
        match self.storage.get(&raw_key)? {
            Some(bytes) => {
                let val: Value = serde_json::from_slice(&bytes)?;
                Ok(if matches!(val, Value::None | Value::Null) {
                    None
                } else {
                    Some(val)
                })
            }
            None => Ok(None),
        }
    }

    /// Fast-path KV `put(key, value)` in `(ns, db)`.
    pub fn kv_put(&self, ns: &str, db: &str, key: &str, value: Value) -> Result<()> {
        let raw_key = encode_key(PREFIX_CELL_KV, &[&sanitize_ident(ns), &sanitize_ident(db), key]);
        let bytes = serde_json::to_vec(&value)?;
        self.storage.put(&raw_key, &bytes)
    }

    /// Fast-path KV `delete(key)` in `(ns, db)`.
    pub fn kv_delete(&self, ns: &str, db: &str, key: &str) -> Result<()> {
        let raw_key = encode_key(PREFIX_CELL_KV, &[&sanitize_ident(ns), &sanitize_ident(db), key]);
        let _ = self.storage.delete(&raw_key)?;
        Ok(())
    }

    /// Fast-path KV `list(prefix)` in `(ns, db)`.
    pub fn kv_list(&self, ns: &str, db: &str, prefix: Option<&str>) -> Result<Vec<(String, Value)>> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);
        let scan_pfx = encode_key(PREFIX_CELL_KV, &[&ns_clean, &db_clean]);
        let entries = self.storage.scan_prefix(&scan_pfx)?;
        let mut out = Vec::new();
        for (k_bytes, v_bytes) in entries {
            let tail = &k_bytes[scan_pfx.len()..];
            let k_str =
                String::from_utf8_lossy(tail.strip_suffix(&[0x00]).unwrap_or(tail)).to_string();
            if let Some(p) = prefix {
                if !k_str.starts_with(p) {
                    continue;
                }
            }
            let val: Value = serde_json::from_slice(&v_bytes)?;
            out.push((k_str, val));
        }
        Ok(out)
    }

    /// Export a JSON snapshot of KV state for `(ns, db)` (compatible with `BlobBridge` cell hibernation).
    pub fn export_snapshot(&self, ns: &str, db: &str) -> Result<Vec<u8>> {
        let entries = self.kv_list(ns, db, None)?;
        let mut kv_map = serde_json::Map::new();
        for (k, v) in entries {
            kv_map.insert(k, v.to_json());
        }
        let payload = serde_json::json!({
            "ns": sanitize_ident(ns),
            "db": sanitize_ident(db),
            "kv": kv_map,
        });
        Ok(serde_json::to_vec(&payload)?)
    }

    /// Import a previously exported JSON snapshot into `(ns, db)`.
    pub fn import_snapshot(&self, ns: &str, db: &str, snapshot: &[u8]) -> Result<()> {
        let parsed: serde_json::Value = serde_json::from_slice(snapshot)?;
        if let Some(kv) = parsed.get("kv").and_then(|v| v.as_object()) {
            for (k, v) in kv {
                self.kv_put(ns, db, k, Value::from_json(v))?;
            }
        }
        Ok(())
    }
}

fn sanitize_ident(ident: &str) -> String {
    ident
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::LiveAction;

    #[test]
    fn crud_query_kv_and_redb_persistence() {
        let tmp = std::env::temp_dir().join(format!("nexus_db_test_{}.redb", uuid::Uuid::new_v4()));
        {
            let db = NexusDb::open_disk(&tmp).unwrap();
            db.query_scoped("app1", "cell1", "DEFINE TABLE IF NOT EXISTS items SCHEMALESS;", vec![])
                .unwrap();

            db.query_scoped(
                "app1",
                "cell1",
                "INSERT INTO items (name, qty) VALUES ($n1, $q1), ($n2, $q2);",
                vec![
                    ("n1".into(), Value::String("apple".into())),
                    ("q1".into(), Value::Int(5)),
                    ("n2".into(), Value::String("banana".into())),
                    ("q2".into(), Value::Int(12)),
                ],
            )
            .unwrap();

            let rows = db
                .query_scoped(
                    "app1",
                    "cell1",
                    "SELECT VALUE name FROM items WHERE qty > 6 ORDER BY qty DESC LIMIT 1;",
                    vec![],
                )
                .unwrap();
            assert_eq!(rows, vec![Value::String("banana".into())]);

            db.kv_put("app1", "cell1", "theme", Value::String("dark".into()))
                .unwrap();
        }

        // Reopen from disk and verify ACID persistence
        {
            let db = NexusDb::open_disk(&tmp).unwrap();
            assert_eq!(
                db.kv_get("app1", "cell1", "theme").unwrap(),
                Some(Value::String("dark".into()))
            );
            let rows = db
                .query_scoped("app1", "cell1", "SELECT name, qty FROM items ORDER BY qty ASC;", vec![])
                .unwrap();
            assert_eq!(rows.len(), 2);

            let snap = db.export_snapshot("app1", "cell1").unwrap();
            let mem = NexusDb::open_mem();
            mem.import_snapshot("app1", "cell1", &snap).unwrap();
            assert_eq!(
                mem.kv_get("app1", "cell1", "theme").unwrap(),
                Some(Value::String("dark".into()))
            );
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn graph_relate_schema_unique_live_fts_vector_and_rpc() {
        let db = NexusDb::open_mem();

        // 1. Schema + UNIQUE index enforcement
        db.query_scoped(
            "social",
            "main",
            "DEFINE TABLE person SCHEMAFULL;
             DEFINE FIELD name ON person TYPE string;
             DEFINE FIELD email ON person TYPE string;
             DEFINE FIELD bio ON person TYPE string;
             DEFINE FIELD embedding ON person TYPE array;
             DEFINE INDEX idx_email ON person FIELDS email UNIQUE;
             DEFINE INDEX idx_bio ON person FIELDS bio SEARCH ANALYZER ascii BM25;
             DEFINE INDEX idx_vec ON person FIELDS embedding HNSW DIMENSION 3 DIST COSINE;",
            vec![],
        )
        .unwrap();

        // Live subscription before mutations
        let (live_id, rx) = db.subscribe_live("social", "main", "person");

        db.query_scoped(
            "social",
            "main",
            "CREATE person:alice SET name = 'Alice', email = 'a@x.io', bio = 'rust distributed systems', embedding = [1.0, 0.0, 0.0];
             CREATE person:bob SET name = 'Bob', email = 'b@x.io', bio = 'web frontend design', embedding = [0.0, 1.0, 0.0];
             CREATE person:carol SET name = 'Carol', email = 'c@x.io', bio = 'rust database kernel', embedding = [0.9, 0.1, 0.0];",
            vec![],
        )
        .unwrap();

        // Verify LIVE SELECT emitted 3 CREATE events
        let ev1 = rx.try_recv().unwrap();
        assert_eq!(ev1.action, LiveAction::Create);
        assert!(db.kill_live(&live_id));

        // Verify UNIQUE constraint rejects duplicate email
        let dup = db.query_scoped(
            "social",
            "main",
            "CREATE person:dave SET name = 'Dave', email = 'a@x.io', bio = 'dup', embedding = [0.0, 0.0, 1.0];",
            vec![],
        );
        assert!(dup.is_err(), "Duplicate UNIQUE email must fail");

        // 2. Graph RELATE + outbound & inbound traversal
        db.query_scoped(
            "social",
            "main",
            "RELATE person:alice->knows->person:bob SET since = 2024;
             RELATE person:alice->knows->person:carol SET since = 2025;",
            vec![],
        )
        .unwrap();

        let friends = db
            .query_scoped(
                "social",
                "main",
                "SELECT ->knows->person.name AS friends FROM person:alice;",
                vec![],
            )
            .unwrap();
        let friends_json = friends[0].to_json();
        let arr = friends_json["friends"].as_array().unwrap();
        assert_eq!(arr.len(), 2);

        // 3. Full-Text `@@` search
        let fts = db
            .query_scoped(
                "social",
                "main",
                "SELECT VALUE name FROM person WHERE bio @@ 'rust' ORDER BY name ASC;",
                vec![],
            )
            .unwrap();
        assert_eq!(
            fts,
            vec![Value::String("Alice".into()), Value::String("Carol".into())]
        );

        // 4. Vector KNN `<|2,COSINE|>` search (closest to [1, 0, 0] -> Alice, Carol)
        let knn = db
            .query_scoped(
                "social",
                "main",
                "SELECT VALUE name FROM person WHERE embedding <|2,COSINE|> [1.0, 0.0, 0.0];",
                vec![],
            )
            .unwrap();
        assert_eq!(
            knn,
            vec![Value::String("Alice".into()), Value::String("Carol".into())]
        );

        // 5. SurrealDB JSON-RPC 2.0 wire session
        let mut rpc = db.rpc_session("social", "main");
        let resp_str = rpc.handle_json(
            r#"{"id":1,"method":"query","params":["SELECT VALUE string::uppercase(name) FROM person:alice;"]}"#,
        );
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp["result"][0]["status"], "OK");
        assert_eq!(resp["result"][0]["result"][0], "ALICE");
    }

    #[test]
    fn full_parity_events_assert_default_functions_patch_return_split_omit_info_subqueries() {
        let db = NexusDb::open_mem();

        // 1. DEFAULT + ASSERT + DEFINE EVENT + DEFINE FUNCTION
        db.query_scoped(
            "shop",
            "main",
            "DEFINE TABLE product SCHEMALESS;
             DEFINE FIELD status ON product TYPE string DEFAULT 'active';
             DEFINE FIELD price ON product TYPE int ASSERT $value > 0;
             DEFINE EVENT on_product ON product WHEN $event == 'CREATE' THEN {
                 CREATE audit SET msg = $after.name
             };
             DEFINE FUNCTION fn::discount($p, $pct) {
                 RETURN $p - ($p * $pct / 100)
             };",
            vec![],
        )
        .unwrap();

        // Negative price must fail ASSERT
        let bad = db.query_scoped(
            "shop",
            "main",
            "CREATE product:bad SET name = 'Broken', price = -5;",
            vec![],
        );
        assert!(bad.is_err(), "ASSERT $value > 0 must reject negative price");

        // Valid create applies DEFAULT status='active' AND triggers EVENT creating audit row
        let created = db
            .query_scoped(
                "shop",
                "main",
                "CREATE product:p1 SET name = 'Widget', price = 100, secret = 'hide', tags = ['a', 'b'];",
                vec![],
            )
            .unwrap();
        assert_eq!(created[0].to_json()["status"], "active");

        let audits = db
            .query_scoped("shop", "main", "SELECT VALUE msg FROM audit;", vec![])
            .unwrap();
        assert_eq!(audits, vec![Value::String("Widget".into())]);

        // Custom fn::discount call
        let disc = db
            .query_scoped("shop", "main", "RETURN fn::discount(200, 15);", vec![])
            .unwrap();
        assert_eq!(disc, vec![Value::Float(170.0)]);

        // PATCH + RETURN DIFF
        let diff = db
            .query_scoped(
                "shop",
                "main",
                "UPDATE product:p1 PATCH [{ op: 'replace', path: '/price', value: 120 }] RETURN DIFF;",
                vec![],
            )
            .unwrap();
        assert!(diff[0].to_json().to_string().contains("/price"));

        // OMIT + SPLIT ON
        let split_rows = db
            .query_scoped(
                "shop",
                "main",
                "SELECT * OMIT secret FROM product:p1 SPLIT ON tags;",
                vec![],
            )
            .unwrap();
        assert_eq!(split_rows.len(), 2);
        assert!(split_rows[0].to_json().get("secret").is_none());

        // Subquery inside LET + INFO FOR DB / TABLE
        let sub = db
            .query_scoped(
                "shop",
                "main",
                "LET $ids = (SELECT VALUE name FROM product); RETURN count($ids);",
                vec![],
            )
            .unwrap();
        assert_eq!(sub, vec![Value::Int(1)]);

        let info_db = db
            .query_scoped("shop", "main", "INFO FOR DB;", vec![])
            .unwrap();
        assert!(info_db[0].to_json()["tables"]["product"].is_string());
        assert!(info_db[0].to_json()["functions"]["fn::discount"].is_string());
    }

    #[cfg(feature = "full")]
    #[test]
    fn full_feature_flags_geo_crypto_cbor_fts_highlight() {
        let db = NexusDb::open_mem();

        // Geo: NYC -> LA distance + Geohash + point-in-polygon
        let dist = db
            .query_scoped(
                "ext",
                "main",
                "RETURN geo::distance([-74.006, 40.7128], [-118.2437, 34.0522]);",
                vec![],
            )
            .unwrap();
        let meters = dist[0].as_f64().unwrap();
        assert!(meters > 3_900_000.0 && meters < 4_000_000.0);

        let gh = db
            .query_scoped("ext", "main", "RETURN geo::hash::encode([-74.006, 40.7128], 5);", vec![])
            .unwrap();
        assert_eq!(gh, vec![Value::String("dr5re".into())]);

        // Crypto: pure-Rust SHA-256 + BLAKE3
        let sha = db
            .query_scoped("ext", "main", "RETURN crypto::sha256('abc');", vec![])
            .unwrap();
        assert_eq!(
            sha,
            vec![Value::String(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into()
            )]
        );

        // FTS highlight
        let hl = db
            .query_scoped(
                "ext",
                "main",
                "RETURN search::highlight('<b>', '</b>', 'fast rust database', 'rust');",
                vec![],
            )
            .unwrap();
        assert_eq!(hl, vec![Value::String("fast <b>rust</b> database".into())]);

        // CBOR wire framing round-trip
        let mut rpc = db.rpc_session("ext", "main");
        let mut req_cbor = Vec::new();
        crate::rpc::cbor_encode(
            &serde_json::json!({"id": 7, "method": "version", "params": []}),
            &mut req_cbor,
        );
        let resp_cbor = rpc.handle_cbor(&req_cbor);
        let mut pos = 0usize;
        let decoded = crate::rpc::cbor_decode(&resp_cbor, &mut pos).unwrap();
        assert_eq!(decoded["id"], 7);
        assert!(decoded["result"].as_str().unwrap().contains("nexus-db"));
    }
}
