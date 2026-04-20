/// Conversion utilities for SurrealDB types

use nu_protocol::{Value, Span};

/// Placeholder for SurrealDB to Nu conversions
pub fn surreal_to_nu(val: serde_json::Value, span: Span) -> Value {
    match val {
        serde_json::Value::Null => Value::nothing(span),
        serde_json::Value::Bool(b) => Value::bool(b, span),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::int(i, span)
            } else if let Some(f) = n.as_f64() {
                Value::float(f, span)
            } else {
                Value::nothing(span)
            }
        }
        serde_json::Value::String(s) => Value::string(s, span),
        serde_json::Value::Array(arr) => {
            let vals: Vec<Value> = arr.into_iter()
                .map(|v| surreal_to_nu(v, span))
                .collect();
            Value::list(vals, span)
        }
        serde_json::Value::Object(obj) => {
            let mut record = nu_protocol::Record::new();
            for (k, v) in obj {
                record.push(k, surreal_to_nu(v, span));
            }
            Value::record(record, span)
        }
    }
}
