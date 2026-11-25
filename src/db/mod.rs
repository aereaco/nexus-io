use anyhow::Result;
use chrono::{DateTime, Utc};
use nexus_db::{NexusDb, Value as DbValue};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::{Arc, RwLock};

#[cfg(feature = "shell")]
pub mod command;
pub mod sql_compiler;
pub mod state_engine;

pub use state_engine::StateEngine;

/// Ergonomic async-compatible client facade over `nexus_db::NexusDb` so existing
/// `db.client.query(...).bind(...).await` call sites work seamlessly without SurrealDB.
#[derive(Clone)]
pub struct DbClient {
    inner: NexusDb,
    ns: Arc<RwLock<String>>,
    db: Arc<RwLock<String>>,
}

impl DbClient {
    pub fn new(inner: NexusDb) -> Self {
        Self {
            inner,
            ns: Arc::new(RwLock::new("nexus".to_string())),
            db: Arc::new(RwLock::new("system".to_string())),
        }
    }

    pub fn use_ns(&self, ns: &str) -> UseScope<'_> {
        UseScope {
            client: self,
            ns: ns.to_string(),
            db: None,
        }
    }

    pub fn query(&self, sql: impl Into<String>) -> QueryBuilder {
        let ns = self.ns.read().unwrap().clone();
        let db = self.db.read().unwrap().clone();
        QueryBuilder {
            inner: self.inner.clone(),
            ns,
            db,
            sql: sql.into(),
            bindings: Vec::new(),
        }
    }
}

pub struct UseScope<'a> {
    client: &'a DbClient,
    ns: String,
    db: Option<String>,
}

impl<'a> UseScope<'a> {
    pub fn use_db(mut self, db: &str) -> Self {
        self.db = Some(db.to_string());
        self
    }
}

impl<'a> std::future::IntoFuture for UseScope<'a> {
    type Output = Result<()>;
    type IntoFuture = std::future::Ready<Result<()>>;

    fn into_future(self) -> Self::IntoFuture {
        *self.client.ns.write().unwrap() = self.ns;
        if let Some(d) = self.db {
            *self.client.db.write().unwrap() = d;
        }
        std::future::ready(Ok(()))
    }
}

pub struct QueryBuilder {
    inner: NexusDb,
    ns: String,
    db: String,
    sql: String,
    bindings: Vec<(String, DbValue)>,
}

impl QueryBuilder {
    pub fn bind<K: Into<String>, V: Serialize>(mut self, pair: (K, V)) -> Self {
        let (k, v) = pair;
        let jv = serde_json::to_value(v).unwrap_or(serde_json::Value::Null);
        self.bindings.push((k.into(), DbValue::from_json(&jv)));
        self
    }
}

impl std::future::IntoFuture for QueryBuilder {
    type Output = Result<QueryResponse>;
    type IntoFuture = std::future::Ready<Result<QueryResponse>>;

    fn into_future(self) -> Self::IntoFuture {
        let res = self
            .inner
            .query_scoped(&self.ns, &self.db, &self.sql, self.bindings)
            .map(|rows| QueryResponse { rows });
        std::future::ready(res)
    }
}

pub struct QueryResponse {
    pub rows: Vec<DbValue>,
}

impl QueryResponse {
    pub fn check(self) -> Result<Self> {
        Ok(self)
    }

    pub fn num_statements(&self) -> usize {
        1
    }

    pub fn take<T: DeserializeOwned>(&mut self, _idx: usize) -> Result<T> {
        let jv = serde_json::Value::Array(self.rows.iter().map(DbValue::to_json).collect());
        if let Ok(parsed) = serde_json::from_value::<T>(jv.clone()) {
            return Ok(parsed);
        }
        if let Some(first) = self.rows.first() {
            if let Ok(parsed) = serde_json::from_value::<T>(first.to_json()) {
                return Ok(parsed);
            }
        }
        serde_json::from_value::<T>(jv).map_err(|e| anyhow::anyhow!("Deserialization error: {}", e))
    }

    pub fn take_values(&self) -> Vec<DbValue> {
        self.rows.clone()
    }
}

pub struct Database {
    pub inner: NexusDb,
    pub client: DbClient,
}

impl Database {
    /// Open an in-memory `nexus-db` instance (instant startup for tests & ephemeral cells).
    pub fn open_mem() -> Self {
        let inner = NexusDb::open_mem();
        let client = DbClient::new(inner.clone());
        Self { inner, client }
    }

    pub async fn init() -> Self {
        Self::init_in(".").await
    }

    /// Initialize `nexus-db` (`redb` ACID MVCC disk store) inside an explicit writable `data_dir`.
    pub async fn init_in(data_dir: impl AsRef<std::path::Path>) -> Self {
        let db_path = data_dir.as_ref().join("nexus.redb");
        let inner = NexusDb::open_disk(&db_path).expect("Failed to open nexus-db redb store");
        let client = DbClient::new(inner.clone());

        // Load schema definitions (best-effort; table definitions are idempotent)
        let _ = inner.query_scoped(
            "nexus",
            "system",
            "DEFINE TABLE IF NOT EXISTS user SCHEMALESS;
             DEFINE TABLE IF NOT EXISTS sys_storage SCHEMALESS;
             DEFINE TABLE IF NOT EXISTS sys_file SCHEMALESS;",
            vec![],
        );

        // 1. PROJECT SYSTEM IDENTITY (Zero-Seed IAM)
        use sysinfo::Users;
        let users = Users::new_with_refreshed_list();
        for user in &users {
            let username = user.name().to_string();
            let groups: Vec<String> = user.groups().iter().map(|g| g.name().to_string()).collect();
            let is_admin = groups
                .iter()
                .any(|g| ["sudo", "wheel", "admin", "root"].contains(&g.as_str()));
            let active_role = if is_admin { "role:admin" } else { "role:guest" };

            let _ = client
                .query(
                    "UPSERT type::record('user', $id) SET username = $username, password = '', groups = $groups, active_role = $active_role;",
                )
                .bind(("id", username.clone()))
                .bind(("username", username))
                .bind(("groups", groups))
                .bind(("active_role", active_role))
                .await;
        }

        // 2. PROJECT HARDWARE (Storage)
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();
        for disk in &disks {
            let name = disk.name().to_string_lossy().to_string();
            let mount = disk.mount_point().to_string_lossy().to_string();
            let total = disk.total_space();
            let avail = disk.available_space();
            let removable = disk.is_removable();

            let _ = client
                .query(
                    "UPSERT type::record('sys_storage', $id) SET name = $name, mount_point = $mount, total_space = $total, available_space = $avail, removable = $removable;",
                )
                .bind(("id", mount.replace(['/', '\\', ':'], "_")))
                .bind(("name", name))
                .bind(("mount", mount))
                .bind(("total", total))
                .bind(("avail", avail))
                .bind(("removable", removable))
                .await;
        }

        // 3. PROJECT INITIAL VFS (Cross-platform temp dir)
        if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
            for entry in entries.flatten().take(64) {
                if let Ok(meta) = entry.metadata() {
                    let path = entry.path().to_string_lossy().to_string();
                    let modified = DateTime::<Utc>::from(
                        meta.modified().unwrap_or(std::time::SystemTime::now()),
                    )
                    .to_rfc3339();

                    let _ = client
                        .query(
                            "UPSERT type::record('sys_file', $id) SET path = $path, is_dir = $is_dir, size = $size, modified = $modified;",
                        )
                        .bind(("id", path.replace(['/', '\\', ':'], "_")))
                        .bind(("path", path))
                        .bind(("is_dir", meta.is_dir()))
                        .bind(("size", meta.len()))
                        .bind(("modified", modified))
                        .await;
                }
            }
        }

        Self { inner, client }
    }
}
