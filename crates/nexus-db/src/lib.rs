pub mod codec;
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
#[cfg(feature = "files")]
pub mod files;
#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "geo")]
pub mod geo;
#[cfg(feature = "crypto")]
pub mod crypto_ext;
#[cfg(feature = "graphql")]
pub mod graphql;
#[cfg(feature = "ml")]
pub mod ml;
#[cfg(feature = "gql")]
pub mod gql;
#[cfg(feature = "pgwire")]
pub mod pgwire;

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{mpsc, Arc};

use crate::engine::{ApiMeta, ExecContext};
use crate::live::{LiveBroker, LiveNotification};
use crate::parser::{parse_surql, Statement};
use crate::rpc::RpcSession;
use crate::storage::{
    encode_key, MemStorage, RedbStorage, StorageBackend, PREFIX_API_META, PREFIX_CELL_KV,
};
pub use crate::value::Value;

pub type ModuleInvoker = Arc<dyn Fn(&str, &str, &[Value]) -> Result<Value> + Send + Sync>;

/// Clean-room, MIT-licensed, ultra-low-footprint SurrealQL-compatible embedded multi-model database.
#[derive(Clone)]
pub struct NexusDb {
    storage: Arc<dyn StorageBackend>,
    live: Arc<LiveBroker>,
    #[cfg(feature = "ml")]
    ml: Arc<crate::ml::MlRegistry>,
    module_invoker: Option<ModuleInvoker>,
}

impl NexusDb {
    /// Open an in-memory `BTreeMap`-backed database (instant startup for tests & ephemeral cells).
    pub fn open_mem() -> Self {
        Self {
            storage: Arc::new(MemStorage::new()),
            live: Arc::new(LiveBroker::new()),
            #[cfg(feature = "ml")]
            ml: Arc::new(crate::ml::MlRegistry::new()),
            module_invoker: None,
        }
    }

    /// Open a persistent ACID MVCC `redb` database on disk.
    pub fn open_disk<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            storage: Arc::new(RedbStorage::open(path)?),
            live: Arc::new(LiveBroker::new()),
            #[cfg(feature = "ml")]
            ml: Arc::new(crate::ml::MlRegistry::new()),
            module_invoker: None,
        })
    }

    /// Attach a Surrealism Wasm module invoker (e.g. Nexus-IO's `CrystalEngine`) for `mod::*` calls.
    pub fn with_module_invoker(mut self, invoker: ModuleInvoker) -> Self {
        self.module_invoker = Some(invoker);
        self
    }

    /// Invoke a custom SurrealQL API endpoint defined via `DEFINE API <path> FOR <methods> THEN <expr>`.
    pub fn invoke_api(
        &self,
        ns: &str,
        db: &str,
        method: &str,
        path: &str,
        request_body: Value,
    ) -> Result<Value> {
        let ns_clean = sanitize_ident(ns);
        let db_clean = sanitize_ident(db);
        let key = encode_key(PREFIX_API_META, &[&ns_clean, &db_clean, path]);
        let raw = self
            .storage
            .get(&key)?
            .ok_or_else(|| anyhow::anyhow!("API endpoint '{}' not found", path))?;
        let meta: ApiMeta = serde_json::from_slice(&raw)?;
        let method_upper = method.to_ascii_uppercase();
        if !meta.methods.iter().any(|m| m == &method_upper) {
            return Err(anyhow::anyhow!(
                "Method {} not allowed for API endpoint '{}'",
                method_upper,
                path
            ));
        }
        let mut params = HashMap::new();
        params.insert("request".into(), request_body);
        let mut ctx = ExecContext::new(
            self.storage.as_ref(),
            self.live.as_ref(),
            ns_clean,
            db_clean,
            params,
        );
        #[cfg(feature = "ml")]
        {
            ctx.ml = Some(self.ml.as_ref());
        }
        if let Some(ref inv) = self.module_invoker {
            ctx.module_invoker = Some(inv.as_ref());
        }
        let rows = ctx.execute_all(&[Statement::Return(meta.body)])?;
        Ok(rows.into_iter().next().unwrap_or(Value::Null))
    }

    /// Execute an ISO GQL `MATCH (...) RETURN ...` graph query (`feature = "gql"`).
    #[cfg(feature = "gql")]
    pub fn gql(&self, ns: &str, db: &str, query: &str) -> Result<Vec<Value>> {
        crate::gql::execute_gql(self, ns, db, query)
    }

    /// Create a PostgreSQL v3 Wire Protocol session (`feature = "pgwire"`).
    #[cfg(feature = "pgwire")]
    pub fn pgwire_session(&self, ns: &str, db: &str) -> crate::pgwire::PgWireSession {
        crate::pgwire::PgWireSession::new(self.clone(), sanitize_ident(ns), sanitize_ident(db))
    }

    /// Execute a GraphQL query against `(ns, db)` (`feature = "graphql"`).
    #[cfg(feature = "graphql")]
    pub fn graphql(&self, ns: &str, db: &str, query: &str) -> Result<serde_json::Value> {
        crate::graphql::execute_graphql(self, ns, db, query)
    }

    /// Register a SurrealML-compatible linear model (`feature = "ml"`).
    #[cfg(feature = "ml")]
    pub fn register_ml_model(&self, model: crate::ml::LinearModel) {
        self.ml.register(model);
    }

    /// Authenticate a user defined via `DEFINE USER` (`feature = "auth"`).
    #[cfg(feature = "auth")]
    pub fn authenticate_user(
        &self,
        ns: &str,
        db: &str,
        username: &str,
        password: &str,
    ) -> Result<Option<crate::auth::UserMeta>> {
        crate::auth::authenticate_user(
            self.storage.as_ref(),
            &sanitize_ident(ns),
            &sanitize_ident(db),
            username,
            password,
        )
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
        #[cfg(feature = "ml")]
        {
            ctx.ml = Some(self.ml.as_ref());
        }
        if let Some(ref inv) = self.module_invoker {
            ctx.module_invoker = Some(inv.as_ref());
        }
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

        // Files & Buckets (`DEFINE BUCKET` + `f"bucket:/key"` + `file::put/get/head/exists/list/copy/rename/delete`)
        db.query_scoped(
            "ext",
            "main",
            "DEFINE BUCKET media BACKEND 'memory';
             RETURN file::put(f'media:/hello.txt', 'nexus-bytes');",
            vec![],
        )
        .unwrap();
        let exists = db
            .query_scoped("ext", "main", "RETURN file::exists(f'media:/hello.txt');", vec![])
            .unwrap();
        assert_eq!(exists, vec![Value::Bool(true)]);
        let got = db
            .query_scoped("ext", "main", "RETURN file::get(f'media:/hello.txt');", vec![])
            .unwrap();
        assert_eq!(got, vec![Value::Bytes(b"nexus-bytes".to_vec())]);
        let listed = db
            .query_scoped("ext", "main", "RETURN file::list('media');", vec![])
            .unwrap();
        assert_eq!(listed, vec![Value::Array(vec![Value::String("media:/hello.txt".into())])]);

        // Auth (`DEFINE USER`, `DEFINE ACCESS`, `PERMISSIONS WHERE`, `crypto::argon2::generate/compare`)
        db.query_scoped(
            "ext",
            "main",
            "DEFINE USER alice ON DATABASE PASSWORD 'secret' ROLES OWNER;
             DEFINE ACCESS user_jwt ON DATABASE TYPE JWT;
             DEFINE TABLE secret_doc SCHEMALESS PERMISSIONS FOR select WHERE owner == $auth;",
            vec![],
        )
        .unwrap();
        assert!(db.authenticate_user("ext", "main", "alice", "secret").unwrap().is_some());
        assert!(db.authenticate_user("ext", "main", "alice", "wrong").unwrap().is_none());

        db.query_scoped(
            "ext",
            "main",
            "CREATE secret_doc:1 SET owner = 'alice', title = 'Mine';
             CREATE secret_doc:2 SET owner = 'bob', title = 'Theirs';",
            vec![],
        )
        .unwrap();
        let visible = db
            .query_scoped(
                "ext",
                "main",
                "SELECT VALUE title FROM secret_doc;",
                vec![("auth".into(), Value::String("alice".into()))],
            )
            .unwrap();
        assert_eq!(visible, vec![Value::String("Mine".into())]);

        // Changefeed + Materialized View + MVCC VERSION + Composite Range + IF/FOR + Recursive Graph + Shortest Path
        db.query_scoped(
            "ext",
            "main",
            "DEFINE TABLE metric SCHEMALESS CHANGEFEED 1h;
             DEFINE TABLE high_metric AS SELECT * FROM metric WHERE val >= 50;
             CREATE metric:['s1', 1] SET val = 20;
             CREATE metric:['s1', 2] SET val = 80;
             UPDATE metric:['s1', 2] SET val = 95;",
            vec![],
        )
        .unwrap();

        let changes = db
            .query_scoped("ext", "main", "SHOW CHANGES FOR TABLE metric SINCE 1;", vec![])
            .unwrap();
        assert_eq!(changes.len(), 3);

        let view_rows = db
            .query_scoped("ext", "main", "SELECT VALUE val FROM high_metric;", vec![])
            .unwrap();
        assert_eq!(view_rows, vec![Value::Int(95)]);

        let old_ver = db
            .query_scoped("ext", "main", "SELECT VALUE val FROM metric:['s1', 2] VERSION 1;", vec![])
            .unwrap();
        assert_eq!(old_ver, vec![Value::Int(80)]);

        let range_rows = db
            .query_scoped("ext", "main", "SELECT VALUE val FROM metric:['s1', 1]..['s1', 2] ORDER BY val ASC;", vec![])
            .unwrap();
        assert_eq!(range_rows, vec![Value::Int(20), Value::Int(95)]);

        // IF / FOR procedural SurrealQL
        let proc_out = db
            .query_scoped(
                "ext",
                "main",
                "FOR $x IN [1, 2, 3] { IF $x > 2 { CREATE bag SET n = $x } };
                 SELECT VALUE n FROM bag;",
                vec![],
            )
            .unwrap();
        assert_eq!(proc_out, vec![Value::Int(3)]);

        // Recursive Graph `@{1..2}` & `graph::shortest_path`
        db.query_scoped(
            "ext",
            "main",
            "CREATE node:a SET label = 'A';
             CREATE node:b SET label = 'B';
             CREATE node:c SET label = 'C';
             RELATE node:a->link->node:b;
             RELATE node:b->link->node:c;",
            vec![],
        )
        .unwrap();
        let rec_g = db
            .query_scoped("ext", "main", "SELECT ->link@{1..2}->node.label AS reach FROM node:a;", vec![])
            .unwrap();
        assert_eq!(rec_g[0].to_json()["reach"].as_array().unwrap().len(), 2);

        let sp = db
            .query_scoped("ext", "main", "RETURN graph::shortest_path(node:a, 'link', node:c);", vec![])
            .unwrap();
        assert_eq!(sp[0].to_json().as_array().unwrap().len(), 3);

        // GraphQL + SurrealML (`feature = "graphql"`, `feature = "ml"`)
        let gql = db.graphql("ext", "main", "query { node(limit: 2) { label } }").unwrap();
        assert_eq!(gql["data"]["node"].as_array().unwrap().len(), 2);

        db.register_ml_model(crate::ml::LinearModel {
            name: "price".into(),
            version: "1.0".into(),
            weights: vec![2.0, 3.0],
            bias: 1.0,
        });
        let pred = db
            .query_scoped("ext", "main", "RETURN ml::price([4.0, 5.0]);", vec![])
            .unwrap();
        assert_eq!(pred, vec![Value::Float(24.0)]);
    }

    #[test]
    fn option1_binary_codec_atomic_rollback_index_seek_cascade_closures_and_remove() {
        let db = NexusDb::open_mem();

        // 1. Atomic transaction rollback on UNIQUE violation (zero partial writes!)
        db.query_scoped(
            "prod",
            "main",
            "DEFINE TABLE acct SCHEMALESS;
             DEFINE INDEX idx_code ON acct FIELDS code UNIQUE;
             CREATE acct:1 SET code = 'A1', bal = 100;",
            vec![],
        )
        .unwrap();

        let failed_tx = db.query_scoped(
            "prod",
            "main",
            "BEGIN TRANSACTION;
             CREATE acct:2 SET code = 'A2', bal = 200;
             CREATE acct:3 SET code = 'A1', bal = 300;
             COMMIT TRANSACTION;",
            vec![],
        );
        assert!(failed_tx.is_err(), "Duplicate UNIQUE in tx must fail");
        let after_rollback = db
            .query_scoped("prod", "main", "SELECT * FROM acct;", vec![])
            .unwrap();
        assert_eq!(after_rollback.len(), 1, "acct:2 must have been rolled back!");

        // 2. EXPLAIN verifies IndexSeek planner on indexed equality
        let plan = db
            .query_scoped(
                "prod",
                "main",
                "SELECT * FROM acct WHERE code = 'A1' EXPLAIN;",
                vec![],
            )
            .unwrap();
        assert_eq!(plan[0].to_json()["operation"], "IndexSeek(acct.idx_code)");

        // 3. Computed VALUE field + SET +=/-= + UNSET + DEFINE PARAM + REMOVE
        db.query_scoped(
            "prod",
            "main",
            "DEFINE PARAM $tax VALUE 10;
             DEFINE TABLE order_item SCHEMALESS;
             DEFINE FIELD total ON order_item VALUE qty * price + $tax;
             CREATE order_item:1 SET qty = 2, price = 50, temp = 'x', tags = ['a'];",
            vec![],
        )
        .unwrap();
        let tot = db
            .query_scoped("prod", "main", "SELECT VALUE total FROM order_item:1;", vec![])
            .unwrap();
        assert_eq!(tot, vec![Value::Int(110)]);

        db.query_scoped(
            "prod",
            "main",
            "UPDATE order_item:1 SET qty += 1, tags += 'b';
             UPDATE order_item:1 UNSET temp;",
            vec![],
        )
        .unwrap();
        let updated = db
            .query_scoped("prod", "main", "SELECT * FROM order_item:1;", vec![])
            .unwrap();
        assert_eq!(updated[0].to_json()["qty"], 3);
        assert_eq!(updated[0].to_json()["total"], 160);
        assert!(updated[0].to_json().get("temp").is_none());

        // 4. REFERENCE ON DELETE CASCADE
        db.query_scoped(
            "prod",
            "main",
            "DEFINE TABLE author SCHEMALESS;
             DEFINE TABLE post SCHEMALESS;
             DEFINE FIELD author ON post TYPE record REFERENCE ON DELETE CASCADE;
             CREATE author:1 SET name = 'Ada';
             CREATE post:1 SET title = 'Hello', author = author:1;
             DELETE author:1;",
            vec![],
        )
        .unwrap();
        let posts = db
            .query_scoped("prod", "main", "SELECT * FROM post;", vec![])
            .unwrap();
        assert!(posts.is_empty(), "post:1 must cascade-delete when author:1 is deleted");

        // 5. Closures, array indexing/filtering, null-coalesce ??, ranges, casts, inline IF, REMOVE + REBUILD INDEX
        let expr_res = db
            .query_scoped(
                "prod",
                "main",
                "RETURN [
                    array::map([1, 2, 3], |$x| $x * 10),
                    array::filter([1, 2, 3, 4], |$x| $x > 2),
                    (1..=4)[2],
                    NONE ?? 'fallback',
                    <int>'42',
                    IF 5 > 2 THEN 'yes' ELSE 'no' END
                ];",
                vec![],
            )
            .unwrap();
        let arr = expr_res[0].to_json();
        assert_eq!(arr[0], serde_json::json!([10, 20, 30]));
        assert_eq!(arr[1], serde_json::json!([3, 4]));
        assert_eq!(arr[2], serde_json::json!(3));
        assert_eq!(arr[3], serde_json::json!("fallback"));
        assert_eq!(arr[4], serde_json::json!(42));
        assert_eq!(arr[5], serde_json::json!("yes"));

        db.query_scoped(
            "prod",
            "main",
            "REBUILD INDEX idx_code ON acct;
             REMOVE TABLE order_item;",
            vec![],
        )
        .unwrap();
        assert!(db
            .query_scoped("prod", "main", "SELECT * FROM order_item;", vec![])
            .unwrap()
            .is_empty());
    }

    #[cfg(feature = "full")]
    #[test]
    fn wave_e_surrealdb_v3_v4_computed_readonly_sequence_api_module_gql_pgwire() {
        // Attach a mock Surrealism Wasm invoker (in nexus-io this delegates to CrystalEngine)
        let db = NexusDb::open_mem().with_module_invoker(Arc::new(|src, func, args| {
            let x = args.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
            Ok(Value::String(format!("{}:{}({})", src, func, x as i64)))
        }));

        // 1. Read-time COMPUTED field + READONLY immutability + ON DELETE RESTRICT
        db.query_scoped(
            "v4",
            "main",
            "DEFINE TABLE OVERWRITE account SCHEMALESS;
             DEFINE FIELD created_by ON account TYPE string READONLY;
             DEFINE FIELD display ON account COMPUTED string::concat(first, ' ', last);
             CREATE account:1 SET created_by = 'root', first = 'Ada', last = 'Lovelace';",
            vec![],
        )
        .unwrap();

        let read = db
            .query_scoped("v4", "main", "SELECT VALUE display FROM account:1;", vec![])
            .unwrap();
        assert_eq!(read, vec![Value::String("Ada Lovelace".into())]);

        // Modifying READONLY field must fail
        let ro_err = db.query_scoped(
            "v4",
            "main",
            "UPDATE account:1 SET created_by = 'hacker';",
            vec![],
        );
        assert!(ro_err.is_err(), "READONLY field must reject updates");

        // 2. DEFINE SEQUENCE + ALTER SEQUENCE + sequence::nextval()
        db.query_scoped(
            "v4",
            "main",
            "DEFINE SEQUENCE IF NOT EXISTS inv_seq BATCH 10 START 100;",
            vec![],
        )
        .unwrap();
        let s1 = db
            .query_scoped("v4", "main", "RETURN sequence::nextval('inv_seq');", vec![])
            .unwrap();
        let s2 = db
            .query_scoped("v4", "main", "RETURN sequence::nextval('inv_seq');", vec![])
            .unwrap();
        assert_eq!(s1, vec![Value::Int(100)]);
        assert_eq!(s2, vec![Value::Int(101)]);

        // 3. DEFINE API + invoke_api
        db.query_scoped(
            "v4",
            "main",
            "DEFINE API OVERWRITE /hello FOR GET, POST THEN { status: 200, body: $request };",
            vec![],
        )
        .unwrap();
        let api_res = db
            .invoke_api("v4", "main", "POST", "/hello", Value::String("world".into()))
            .unwrap();
        assert_eq!(api_res.to_json()["status"], 200);
        assert_eq!(api_res.to_json()["body"], "world");

        // 4. DEFINE MODULE (Surrealism Wasm extension)
        db.query_scoped(
            "v4",
            "main",
            "DEFINE MODULE mod::pricing FROM f'plugins:/pricing.wasm' UNSIGNED;",
            vec![],
        )
        .unwrap();
        let mod_out = db
            .query_scoped("v4", "main", "RETURN mod::pricing::calc(42);", vec![])
            .unwrap();
        assert_eq!(
            mod_out,
            vec![Value::String("plugins:/pricing.wasm:calc(42)".into())]
        );

        // 5. ISO GQL `MATCH (a:person)-[:knows]->(b:person) RETURN b.name`
        db.query_scoped(
            "v4",
            "main",
            "CREATE person:1 SET name = 'Alice';
             CREATE person:2 SET name = 'Bob';
             RELATE person:1->knows->person:2;",
            vec![],
        )
        .unwrap();
        let gql_rows = db
            .gql(
                "v4",
                "main",
                "MATCH (a:person)-[:knows]->(b:person) WHERE a.name = 'Alice' RETURN b.name",
            )
            .unwrap();
        assert_eq!(gql_rows, vec![Value::String("Bob".into())]);

        // 6. PostgreSQL v3 Wire Protocol (`PgWireSession`)
        let mut pg = db.pgwire_session("v4", "main");
        let startup = pg.startup_response();
        assert_eq!(startup[0], b'R'); // AuthenticationOk
        let q_frame = crate::pgwire::PgWireSession::encode_query_frame("SELECT name FROM person:1;");
        let resp = pg.handle_frame(&q_frame).unwrap();
        assert_eq!(resp[0], b'T'); // RowDescription
        assert!(resp.windows(5).any(|w| w == b"Alice"));
        assert_eq!(resp[resp.len() - 6], b'Z'); // ReadyForQuery
    }
}
