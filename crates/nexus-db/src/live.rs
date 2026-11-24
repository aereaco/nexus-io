use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::value::Value;

/// Action emitted by a `LIVE SELECT` subscription (SurrealDB wire-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LiveAction {
    Create,
    Update,
    Delete,
}

/// Real-time change notification pushed to active `LIVE SELECT` subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveNotification {
    pub id: String,
    pub action: LiveAction,
    pub result: Value,
}

struct LiveSub {
    ns: String,
    db: String,
    table: String,
    tx: mpsc::Sender<LiveNotification>,
}

/// Zero-dependency in-process pub/sub broker for `LIVE SELECT` and `KILL`.
#[derive(Default)]
pub struct LiveBroker {
    subs: Mutex<HashMap<String, LiveSub>>,
}

impl LiveBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new `LIVE SELECT` subscription on `(ns, db, table)`.
    /// Returns `(live_uuid, receiver)`.
    pub fn subscribe(
        &self,
        ns: &str,
        db: &str,
        table: &str,
    ) -> (String, mpsc::Receiver<LiveNotification>) {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = mpsc::channel();
        let mut guard = self.subs.lock().unwrap();
        guard.insert(
            id.clone(),
            LiveSub {
                ns: ns.to_string(),
                db: db.to_string(),
                table: table.to_string(),
                tx,
            },
        );
        (id, rx)
    }

    /// Cancel an active `LIVE SELECT` subscription (`KILL <uuid>`).
    pub fn kill(&self, live_id: &str) -> bool {
        let mut guard = self.subs.lock().unwrap();
        guard.remove(live_id).is_some()
    }

    /// Broadcast a mutation event to all matching subscribers, pruning closed channels.
    pub fn publish(&self, ns: &str, db: &str, table: &str, action: LiveAction, result: &Value) {
        let mut guard = self.subs.lock().unwrap();
        let mut dead = Vec::new();
        for (id, sub) in guard.iter() {
            if sub.ns == ns && sub.db == db && sub.table == table {
                let notif = LiveNotification {
                    id: id.clone(),
                    action,
                    result: result.clone(),
                };
                if sub.tx.send(notif).is_err() {
                    dead.push(id.clone());
                }
            }
        }
        for id in dead {
            guard.remove(&id);
        }
    }
}
