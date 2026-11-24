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
    diff_mode: bool,
    filter_eq: Option<(String, String)>,
    tx: mpsc::Sender<LiveNotification>,
}

/// Zero-dependency in-process pub/sub broker for `LIVE SELECT [DIFF] ... [WHERE field = val]` and `KILL`.
#[derive(Default)]
pub struct LiveBroker {
    subs: Mutex<HashMap<String, LiveSub>>,
}

impl LiveBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new `LIVE SELECT` subscription on `(ns, db, table)`.
    pub fn subscribe(
        &self,
        ns: &str,
        db: &str,
        table: &str,
    ) -> (String, mpsc::Receiver<LiveNotification>) {
        self.subscribe_filtered(ns, db, table, false, None)
    }

    /// Register a filtered / `DIFF` `LIVE SELECT` subscription.
    pub fn subscribe_filtered(
        &self,
        ns: &str,
        db: &str,
        table: &str,
        diff_mode: bool,
        filter_eq: Option<(String, String)>,
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
                diff_mode,
                filter_eq,
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
        self.publish_with_before(ns, db, table, action, None, result);
    }

    /// Broadcast a mutation event with optional `before` snapshot to emit RFC 6902 diffs for `LIVE SELECT DIFF`.
    pub fn publish_with_before(
        &self,
        ns: &str,
        db: &str,
        table: &str,
        action: LiveAction,
        before: Option<&Value>,
        result: &Value,
    ) {
        let mut guard = self.subs.lock().unwrap();
        let mut dead = Vec::new();
        for (id, sub) in guard.iter() {
            if sub.ns != ns || sub.db != db || sub.table != table {
                continue;
            }
            if let Some((ref f_key, ref f_val)) = sub.filter_eq {
                let matched = match result {
                    Value::Object(m) => m
                        .get(f_key)
                        .map(|v| v.display_compact() == *f_val)
                        .unwrap_or(false),
                    _ => false,
                };
                if !matched {
                    continue;
                }
            }
            let payload = if sub.diff_mode {
                compute_rfc6902_diff(before, result)
            } else {
                result.clone()
            };
            let notif = LiveNotification {
                id: id.clone(),
                action,
                result: payload,
            };
            if sub.tx.send(notif).is_err() {
                dead.push(id.clone());
            }
        }
        for id in dead {
            guard.remove(&id);
        }
    }
}

/// Compute an RFC 6902 JSON Patch `Value::Array` diff between `before` and `after`.
pub fn compute_rfc6902_diff(before: Option<&Value>, after: &Value) -> Value {
    let mut ops = Vec::new();
    if let Value::Object(after_map) = after {
        let empty = std::collections::BTreeMap::new();
        let before_map = match before {
            Some(Value::Object(m)) => m,
            _ => &empty,
        };
        for (k, v) in after_map {
            match before_map.get(k) {
                None => {
                    let mut op = std::collections::BTreeMap::new();
                    op.insert("op".into(), Value::String("add".into()));
                    op.insert("path".into(), Value::String(format!("/{}", k)));
                    op.insert("value".into(), v.clone());
                    ops.push(Value::Object(op));
                }
                Some(old) if old != v => {
                    let mut op = std::collections::BTreeMap::new();
                    op.insert("op".into(), Value::String("replace".into()));
                    op.insert("path".into(), Value::String(format!("/{}", k)));
                    op.insert("value".into(), v.clone());
                    ops.push(Value::Object(op));
                }
                _ => {}
            }
        }
        for k in before_map.keys() {
            if !after_map.contains_key(k) {
                let mut op = std::collections::BTreeMap::new();
                op.insert("op".into(), Value::String("remove".into()));
                op.insert("path".into(), Value::String(format!("/{}", k)));
                ops.push(Value::Object(op));
            }
        }
    }
    Value::Array(ops)
}
