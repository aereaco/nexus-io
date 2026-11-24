use anyhow::Result;
use redb::{Database as RedbDatabase, TableDefinition};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::RwLock;

const KV_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nexus_kv");

/// Keyspace prefixes matching the ordered B-tree layout in the `nexus-db` architecture.
pub const PREFIX_TABLE_META: u8 = 0x01;
pub const PREFIX_RECORD: u8 = 0x02;
pub const PREFIX_EDGE_OUT: u8 = 0x03;
pub const PREFIX_EDGE_IN: u8 = 0x04;
pub const PREFIX_INDEX: u8 = 0x05;
pub const PREFIX_FTS: u8 = 0x06;
pub const PREFIX_VEC: u8 = 0x07;
pub const PREFIX_CELL_KV: u8 = 0x08;
pub const PREFIX_FIELD_META: u8 = 0x09;
pub const PREFIX_INDEX_META: u8 = 0x0A;
pub const PREFIX_EVENT_META: u8 = 0x0B;
pub const PREFIX_FUNCTION_META: u8 = 0x0C;
pub const PREFIX_CHANGEFEED: u8 = 0x0D;
pub const PREFIX_VERSION: u8 = 0x0E;
pub const PREFIX_BUCKET_META: u8 = 0x0F;
pub const PREFIX_FILE_BLOB: u8 = 0x10;
pub const PREFIX_USER_META: u8 = 0x11;
pub const PREFIX_ACCESS_META: u8 = 0x12;
pub const PREFIX_ANALYZER_META: u8 = 0x13;
pub const PREFIX_PARAM_META: u8 = 0x14;
pub const PREFIX_SEQUENCE_META: u8 = 0x15;
pub const PREFIX_API_META: u8 = 0x16;
pub const PREFIX_MODULE_META: u8 = 0x17;
pub const PREFIX_BEARER_GRANT: u8 = 0x18;
pub const PREFIX_VEC_GRAPH: u8 = 0x19;

/// Build a `\x00`-delimited ordered binary key for prefix scans.
pub fn encode_key(prefix: u8, parts: &[&str]) -> Vec<u8> {
    let cap: usize = 1 + parts.iter().map(|p| p.len() + 1).sum::<usize>();
    let mut buf = Vec::with_capacity(cap);
    buf.push(prefix);
    for p in parts {
        buf.extend_from_slice(p.as_bytes());
        buf.push(0x00);
    }
    buf
}

/// Synchronous ordered KV storage backend (implemented by `MemStorage` and `RedbStorage`).
pub trait StorageBackend: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<bool>;
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
    fn apply_batch(&self, ops: Vec<BatchOp>) -> Result<()>;
}

#[derive(Debug, Clone)]
pub enum BatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// In-memory ordered `BTreeMap` backend (instant startup for tests and ephemeral elastic cells).
pub struct MemStorage {
    map: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemStorage {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Default for MemStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let guard = self.map.read().unwrap();
        Ok(guard.get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut guard = self.map.write().unwrap();
        guard.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<bool> {
        let mut guard = self.map.write().unwrap();
        Ok(guard.remove(key).is_some())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let guard = self.map.read().unwrap();
        let mut out = Vec::new();
        for (k, v) in guard.range(prefix.to_vec()..) {
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.clone(), v.clone()));
        }
        Ok(out)
    }

    fn apply_batch(&self, ops: Vec<BatchOp>) -> Result<()> {
        let mut guard = self.map.write().unwrap();
        for op in ops {
            match op {
                BatchOp::Put(k, v) => {
                    guard.insert(k, v);
                }
                BatchOp::Delete(k) => {
                    guard.remove(&k);
                }
            }
        }
        Ok(())
    }
}

/// Pure-Rust ACID MVCC B-tree disk backend powered by `redb`.
pub struct RedbStorage {
    db: RedbDatabase,
}

impl RedbStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let db = RedbDatabase::create(path)?;
        // Ensure table exists on first open
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(KV_TABLE)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }
}

impl StorageBackend for RedbStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(KV_TABLE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(KV_TABLE)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(KV_TABLE)?;
            let res = table.remove(key)?.is_some();
            res
        };
        write_txn.commit()?;
        Ok(existed)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(KV_TABLE)?;
        let mut out = Vec::new();
        for item in table.range(prefix..)? {
            let (k, v) = item?;
            let kb = k.value();
            if !kb.starts_with(prefix) {
                break;
            }
            out.push((kb.to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }

    fn apply_batch(&self, ops: Vec<BatchOp>) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(KV_TABLE)?;
            for op in ops {
                match op {
                    BatchOp::Put(k, v) => {
                        table.insert(k.as_slice(), v.as_slice())?;
                    }
                    BatchOp::Delete(k) => {
                        let _ = table.remove(k.as_slice())?;
                    }
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}
