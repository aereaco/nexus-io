//! Raft-style replicated Write-Ahead Log (WAL) & snapshot sync for multi-node `nexus-db` clusters.
//!
//! Leaders append committed SurrealQL mutations with monotonically increasing `(term, index)`
//! coordinates; followers pull `entries_since(last_applied)` (over `iroh` / HTTP / WireGuard)
//! and deterministically replay them into their local `NexusDb` instance.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::NexusDb;

/// A single replicated WAL mutation entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalEntry {
    pub term: u64,
    pub index: u64,
    pub ns: String,
    pub db: String,
    pub surql: String,
}

/// Thread-safe Raft-style append-only replication log.
#[derive(Clone, Default)]
pub struct ReplicationLog {
    inner: Arc<RwLock<ReplicationState>>,
}

#[derive(Default)]
struct ReplicationState {
    current_term: u64,
    commit_index: u64,
    entries: Vec<WalEntry>,
}

impl ReplicationLog {
    pub fn new(initial_term: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ReplicationState {
                current_term: initial_term.max(1),
                commit_index: 0,
                entries: Vec::new(),
            })),
        }
    }

    /// Leader executes `surql` locally on `db` and atomically appends a `(term, index)` WAL entry.
    pub fn replicate_write(
        &self,
        db: &NexusDb,
        ns: &str,
        database: &str,
        surql: &str,
    ) -> Result<WalEntry> {
        let _ = db.query_scoped(ns, database, surql, vec![])?;
        let mut st = self.inner.write().unwrap();
        let next_index = st.entries.len() as u64 + 1;
        let entry = WalEntry {
            term: st.current_term,
            index: next_index,
            ns: ns.to_string(),
            db: database.to_string(),
            surql: surql.to_string(),
        };
        st.entries.push(entry.clone());
        st.commit_index = next_index;
        Ok(entry)
    }

    /// Return all committed WAL entries strictly after `after_index` for follower catch-up.
    pub fn entries_since(&self, after_index: u64) -> Vec<WalEntry> {
        let st = self.inner.read().unwrap();
        st.entries
            .iter()
            .filter(|e| e.index > after_index)
            .cloned()
            .collect()
    }

    pub fn commit_index(&self) -> u64 {
        self.inner.read().unwrap().commit_index
    }

    pub fn current_term(&self) -> u64 {
        self.inner.read().unwrap().current_term
    }

    /// Advance term (e.g., on leader election).
    pub fn advance_term(&self, new_term: u64) {
        let mut st = self.inner.write().unwrap();
        if new_term > st.current_term {
            st.current_term = new_term;
        }
    }

    /// Follower applies a contiguous batch of leader WAL entries to its local `NexusDb`.
    pub fn apply_to_follower(&self, follower_db: &NexusDb, entries: &[WalEntry]) -> Result<u64> {
        let mut st = self.inner.write().unwrap();
        for entry in entries {
            let expected = st.entries.len() as u64 + 1;
            if entry.index < expected {
                continue; // Idempotent replay skip
            }
            if entry.index > expected {
                return Err(anyhow!(
                    "WAL gap detected: expected index {}, got {} (request snapshot sync)",
                    expected,
                    entry.index
                ));
            }
            if entry.term > st.current_term {
                st.current_term = entry.term;
            }
            let _ = follower_db.query_scoped(&entry.ns, &entry.db, &entry.surql, vec![])?;
            st.entries.push(entry.clone());
            st.commit_index = entry.index;
        }
        Ok(st.commit_index)
    }
}
