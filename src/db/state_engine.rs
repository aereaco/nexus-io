use anyhow::Result;
use bytes::Bytes;
use nexus_db::{NexusDb, Value as DbValue};

use super::Database;

/// Unified `StateEngine` abstraction isolating storage behind scoped `(ns, db)` sessions,
/// backed by 100% MIT-licensed `nexus-db` (`redb` / `BTreeMap`).
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

    fn as_nexus_db(&self) -> Option<&NexusDb> {
        None
    }
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

    fn as_nexus_db(&self) -> Option<&NexusDb> {
        Some(self)
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

    fn as_nexus_db(&self) -> Option<&NexusDb> {
        Some(&self.inner)
    }
}
