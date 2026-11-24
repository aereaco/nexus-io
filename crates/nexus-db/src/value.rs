use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;

/// Compact, SurrealQL-compatible tagged value model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "$t", content = "$v")]
pub enum Value {
    None,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    RecordId { tb: String, id: String },
    DateTime(String),
    Duration(i64),
    Decimal(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::None | Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0 && !f.is_nan(),
            Value::String(s) | Value::Decimal(s) => !s.is_empty(),
            Value::Bytes(b) => !b.is_empty(),
            Value::RecordId { .. } | Value::DateTime(_) => true,
            Value::Duration(d) => *d != 0,
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Decimal(d) => d.parse::<f64>().ok(),
            Value::Duration(s) => Some(*s as f64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) | Value::DateTime(s) | Value::Decimal(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Convert to plain JSON (SurrealDB HTTP/WS JSON representation).
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::None | Value::Null => serde_json::Value::Null,
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Int(i) => serde_json::json!(*i),
            Value::Float(f) => serde_json::json!(*f),
            Value::String(s) | Value::DateTime(s) | Value::Decimal(s) => {
                serde_json::Value::String(s.clone())
            }
            Value::Duration(s) => serde_json::Value::String(format!("{}s", s)),
            Value::Bytes(b) => serde_json::Value::Array(b.iter().map(|x| serde_json::json!(*x)).collect()),
            Value::RecordId { tb, id } => serde_json::Value::String(format!("{}:{}", tb, id)),
            Value::Array(arr) => serde_json::Value::Array(arr.iter().map(Value::to_json).collect()),
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    out.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(out)
            }
        }
    }

    pub fn from_json(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else if let Some(f) = n.as_f64() {
                    Value::Float(f)
                } else {
                    Value::String(n.to_string())
                }
            }
            serde_json::Value::String(s) => Value::String(s.clone()),
            serde_json::Value::Array(arr) => Value::Array(arr.iter().map(Value::from_json).collect()),
            serde_json::Value::Object(map) => {
                let mut out = BTreeMap::new();
                for (k, val) in map {
                    out.insert(k.clone(), Value::from_json(val));
                }
                Value::Object(out)
            }
        }
    }

    /// Total ordering for `ORDER BY` and range comparisons.
    pub fn cmp_order(&self, other: &Self) -> Ordering {
        use Value::*;
        match (self, other) {
            (None, None) | (Null, Null) => Ordering::Equal,
            (None, _) => Ordering::Less,
            (_, None) => Ordering::Greater,
            (Null, _) => Ordering::Less,
            (_, Null) => Ordering::Greater,
            (Bool(a), Bool(b)) => a.cmp(b),
            (Int(a), Int(b)) => a.cmp(b),
            (Int(a), Float(b)) => (*a as f64).partial_cmp(b).unwrap_or(Ordering::Equal),
            (Float(a), Int(b)) => a.partial_cmp(&(*b as f64)).unwrap_or(Ordering::Equal),
            (Float(a), Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
            (String(a), String(b)) => a.cmp(b),
            (DateTime(a), DateTime(b)) => a.cmp(b),
            (RecordId { tb: t1, id: i1 }, RecordId { tb: t2, id: i2 }) => {
                (t1, i1).cmp(&(t2, i2))
            }
            (a, b) => a.to_json().to_string().cmp(&b.to_json().to_string()),
        }
    }

    pub fn display_compact(&self) -> String {
        match self {
            Value::None => "NONE".to_string(),
            Value::Null => "NULL".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::String(s) | Value::DateTime(s) | Value::Decimal(s) => s.clone(),
            Value::Duration(s) => format!("{}s", s),
            Value::RecordId { tb, id } => format!("{}:{}", tb, id),
            _ => self.to_json().to_string(),
        }
    }
}
