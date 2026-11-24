use anyhow::{anyhow, Result};
use chrono::{Datelike, Utc};
use uuid::Uuid;

use crate::value::Value;

/// Tokenize text for BM25 full-text indexing and `@@` search matching.
pub fn tokenize_fts(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Extract a numeric `Vec<f64>` vector from a `Value::Array`.
pub fn value_to_vec(v: &Value) -> Option<Vec<f64>> {
    match v {
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(item.as_f64()?);
            }
            Some(out)
        }
        _ => None,
    }
}

/// Cosine similarity in `[-1.0, 1.0]` between two equal-length vectors.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

/// Euclidean distance (`L2`) between two equal-length vectors.
pub fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() {
        return f64::INFINITY;
    }
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y) * (x - y))
        .sum::<f64>()
        .sqrt()
}

/// Manhattan distance (`L1`) between two equal-length vectors.
pub fn manhattan_distance(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() {
        return f64::INFINITY;
    }
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).sum()
}

/// Evaluate a built-in SurrealQL standard library function (`string::*`, `math::*`, `array::*`,
/// `object::*`, `time::*`, `type::*`, `vector::*`, `rand::*`, `count`).
pub fn eval_stdlib(name: &str, args: &[Value]) -> Result<Value> {
    match name.to_ascii_lowercase().as_str() {
        // --- type::* ---
        "type::record" | "type::thing" => {
            if args.len() != 2 {
                return Err(anyhow!("type::record expects 2 arguments (table, id)"));
            }
            Ok(Value::RecordId {
                tb: args[0].display_compact(),
                id: args[1].display_compact(),
            })
        }
        "type::string" => Ok(Value::String(
            args.first().map(|v| v.display_compact()).unwrap_or_default(),
        )),
        "type::int" => {
            let n = match args.first() {
                Some(Value::Int(i)) => *i,
                Some(Value::Float(f)) => *f as i64,
                Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(0),
                Some(Value::Bool(b)) => i64::from(*b),
                _ => 0,
            };
            Ok(Value::Int(n))
        }
        "type::float" => {
            let f = match args.first() {
                Some(Value::Float(x)) => *x,
                Some(Value::Int(i)) => *i as f64,
                Some(Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
                _ => 0.0,
            };
            Ok(Value::Float(f))
        }
        "type::bool" => Ok(Value::Bool(args.first().map(|v| v.is_truthy()).unwrap_or(false))),

        // --- additional bytes::* & rand::* helpers ---
        "bytes::len" => {
            let n = args
                .first()
                .map(|v| v.display_compact().len() as i64)
                .unwrap_or(0);
            Ok(Value::Int(n))
        }
        "rand::ulid" => {
            let ms = Utc::now().timestamp_millis() as u64;
            let r = Uuid::new_v4().as_u128();
            Ok(Value::String(format!("{:010X}{:016X}", ms & 0xFF_FFFF_FFFF, (r as u64))))
        }
        "rand::bool" => Ok(Value::Bool((Uuid::new_v4().as_bytes()[0] & 1) == 1)),

        // --- time::* ---
        "time::now" => Ok(Value::DateTime(Utc::now().to_rfc3339())),
        "time::unix" => Ok(Value::Int(Utc::now().timestamp())),
        "time::year" => Ok(Value::Int(Utc::now().year() as i64)),
        "time::month" => Ok(Value::Int(Utc::now().month() as i64)),
        "time::day" => Ok(Value::Int(Utc::now().day() as i64)),
        "time::floor" | "time::group" => {
            // Bucket ISO-8601 timestamp to 'year' | 'month' | 'day' | 'hour' | 'minute'
            let ts = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let unit = args.get(1).and_then(|v| v.as_str()).unwrap_or("day").to_ascii_lowercase();
            let prefix_len = match unit.as_str() {
                "year" | "1y" => 4,
                "month" | "1mo" => 7,
                "day" | "1d" => 10,
                "hour" | "1h" => 13,
                "minute" | "1m" => 16,
                _ => ts.len(),
            };
            Ok(Value::DateTime(ts.chars().take(prefix_len).collect()))
        }

        // --- duration::* ---
        "duration::secs" => Ok(Value::Int(parse_duration_secs(args.first().map(|v| v.display_compact()).as_deref().unwrap_or("0s")))),
        "duration::mins" => Ok(Value::Int(parse_duration_secs(args.first().map(|v| v.display_compact()).as_deref().unwrap_or("0s")) / 60)),
        "duration::hours" => Ok(Value::Int(parse_duration_secs(args.first().map(|v| v.display_compact()).as_deref().unwrap_or("0s")) / 3600)),
        "duration::days" => Ok(Value::Int(parse_duration_secs(args.first().map(|v| v.display_compact()).as_deref().unwrap_or("0s")) / 86400)),

        // --- bytes::* ---
        "bytes::len" => match args.first() {
            Some(Value::Bytes(b)) => Ok(Value::Int(b.len() as i64)),
            Some(Value::String(s)) => Ok(Value::Int(s.len() as i64)),
            _ => Ok(Value::Int(0)),
        },

        // --- parse::* ---
        "parse::email::host" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            Ok(s.split_once('@')
                .map(|(_, h)| Value::String(h.to_string()))
                .unwrap_or(Value::None))
        }
        "parse::email::user" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            Ok(s.split_once('@')
                .map(|(u, _)| Value::String(u.to_string()))
                .unwrap_or(Value::None))
        }
        "parse::url::host" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let rest = s.split("://").nth(1).unwrap_or(s);
            let host = rest.split('/').next().unwrap_or("").split(':').next().unwrap_or("");
            Ok(Value::String(host.to_string()))
        }
        "parse::url::path" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let rest = s.split("://").nth(1).unwrap_or(s);
            let path = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
            Ok(Value::String(path.split('?').next().unwrap_or(path).to_string()))
        }

        // --- encoding::base64::* ---
        "encoding::base64::encode" => {
            let bytes = match args.first() {
                Some(Value::Bytes(b)) => b.as_slice(),
                Some(Value::String(s)) => s.as_bytes(),
                _ => &[],
            };
            Ok(Value::String(base64_encode_std(bytes)))
        }
        "encoding::base64::decode" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::Bytes(base64_decode_std(s)))
        }

        // --- auth password hashing (`crypto::argon2::generate/compare`) ---
        #[cfg(feature = "auth")]
        "crypto::argon2::generate" | "crypto::bcrypt::generate" | "crypto::scrypt::generate" => {
            let pass = args.first().map(|v| v.display_compact()).unwrap_or_default();
            Ok(Value::String(crate::auth::hash_password(&pass)))
        }
        #[cfg(feature = "auth")]
        "crypto::argon2::compare" | "crypto::bcrypt::compare" | "crypto::scrypt::compare" => {
            let hash = args.first().map(|v| v.display_compact()).unwrap_or_default();
            let pass = args.get(1).map(|v| v.display_compact()).unwrap_or_default();
            Ok(Value::Bool(crate::auth::verify_password(&hash, &pass)))
        }

        // --- rand::* ---
        "rand::uuid" | "rand::uuid::v4" => Ok(Value::String(Uuid::new_v4().to_string())),

        // --- string::* ---
        "string::lowercase" => Ok(Value::String(
            args.first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase(),
        )),
        "string::uppercase" => Ok(Value::String(
            args.first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_uppercase(),
        )),
        "string::trim" => Ok(Value::String(
            args.first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string(),
        )),
        "string::len" => Ok(Value::Int(
            args.first()
                .and_then(|v| v.as_str())
                .map(|s| s.chars().count() as i64)
                .unwrap_or(0),
        )),
        "string::concat" => {
            let mut out = String::new();
            for a in args {
                out.push_str(&a.display_compact());
            }
            Ok(Value::String(out))
        }
        "string::contains" => {
            let hay = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let needle = args.get(1).and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::Bool(hay.contains(needle)))
        }
        "string::starts_with" => {
            let hay = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let pfx = args.get(1).and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::Bool(hay.starts_with(pfx)))
        }
        "string::ends_with" => {
            let hay = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let sfx = args.get(1).and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::Bool(hay.ends_with(sfx)))
        }
        "string::split" => {
            let hay = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let sep = args.get(1).and_then(|v| v.as_str()).unwrap_or(" ");
            Ok(Value::Array(
                hay.split(sep).map(|s| Value::String(s.to_string())).collect(),
            ))
        }
        "string::replace" => {
            let hay = args.first().and_then(|v| v.as_str()).unwrap_or("");
            let from = args.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let to = args.get(2).and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::String(hay.replace(from, to)))
        }

        // --- math::* & aggregates ---
        "count" => match args.first() {
            Some(Value::Array(a)) => Ok(Value::Int(a.len() as i64)),
            Some(Value::String(s)) => Ok(Value::Int(s.len() as i64)),
            Some(Value::None) | Some(Value::Null) | None => Ok(Value::Int(0)),
            _ => Ok(Value::Int(1)),
        },
        "math::abs" => match args.first() {
            Some(Value::Int(i)) => Ok(Value::Int(i.abs())),
            Some(Value::Float(f)) => Ok(Value::Float(f.abs())),
            _ => Ok(Value::Int(0)),
        },
        "math::ceil" => Ok(Value::Float(
            args.first().and_then(|v| v.as_f64()).unwrap_or(0.0).ceil(),
        )),
        "math::floor" => Ok(Value::Float(
            args.first().and_then(|v| v.as_f64()).unwrap_or(0.0).floor(),
        )),
        "math::round" => Ok(Value::Float(
            args.first().and_then(|v| v.as_f64()).unwrap_or(0.0).round(),
        )),
        "math::sqrt" => Ok(Value::Float(
            args.first().and_then(|v| v.as_f64()).unwrap_or(0.0).sqrt(),
        )),
        "math::pow" => {
            let a = args.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b = args.get(1).and_then(|v| v.as_f64()).unwrap_or(1.0);
            Ok(Value::Float(a.powf(b)))
        }
        "math::sum" => match args.first() {
            Some(Value::Array(a)) => {
                if a.iter().all(|v| matches!(v, Value::Int(_))) {
                    let s: i64 = a
                        .iter()
                        .filter_map(|v| match v {
                            Value::Int(i) => Some(*i),
                            _ => None,
                        })
                        .sum();
                    Ok(Value::Int(s))
                } else {
                    let s: f64 = a.iter().filter_map(|v| v.as_f64()).sum();
                    Ok(Value::Float(s))
                }
            }
            _ => Ok(Value::Int(0)),
        },
        "math::mean" => match args.first() {
            Some(Value::Array(a)) if !a.is_empty() => {
                let vals: Vec<f64> = a.iter().filter_map(|v| v.as_f64()).collect();
                if vals.is_empty() {
                    Ok(Value::Float(0.0))
                } else {
                    Ok(Value::Float(vals.iter().sum::<f64>() / vals.len() as f64))
                }
            }
            _ => Ok(Value::Float(0.0)),
        },
        "math::min" => match args.first() {
            Some(Value::Array(a)) => Ok(a
                .iter()
                .min_by(|x, y| x.cmp_order(y))
                .cloned()
                .unwrap_or(Value::None)),
            _ => Ok(Value::None),
        },
        "math::max" => match args.first() {
            Some(Value::Array(a)) => Ok(a
                .iter()
                .max_by(|x, y| x.cmp_order(y))
                .cloned()
                .unwrap_or(Value::None)),
            _ => Ok(Value::None),
        },

        // --- array::* ---
        "array::len" => match args.first() {
            Some(Value::Array(a)) => Ok(Value::Int(a.len() as i64)),
            _ => Ok(Value::Int(0)),
        },
        "array::distinct" => match args.first() {
            Some(Value::Array(a)) => {
                let mut out = Vec::new();
                for item in a {
                    if !out.contains(item) {
                        out.push(item.clone());
                    }
                }
                Ok(Value::Array(out))
            }
            _ => Ok(Value::Array(Vec::new())),
        },
        "array::flatten" => match args.first() {
            Some(Value::Array(a)) => {
                let mut out = Vec::new();
                for item in a {
                    match item {
                        Value::Array(inner) => out.extend(inner.iter().cloned()),
                        other => out.push(other.clone()),
                    }
                }
                Ok(Value::Array(out))
            }
            _ => Ok(Value::Array(Vec::new())),
        },
        "array::reverse" => match args.first() {
            Some(Value::Array(a)) => {
                let mut out = a.clone();
                out.reverse();
                Ok(Value::Array(out))
            }
            _ => Ok(Value::Array(Vec::new())),
        },
        "array::sort" => match args.first() {
            Some(Value::Array(a)) => {
                let mut out = a.clone();
                out.sort_by(|x, y| x.cmp_order(y));
                Ok(Value::Array(out))
            }
            _ => Ok(Value::Array(Vec::new())),
        },
        "array::concat" => {
            let mut out = Vec::new();
            for arg in args {
                if let Value::Array(a) = arg {
                    out.extend(a.iter().cloned());
                }
            }
            Ok(Value::Array(out))
        }
        "array::first" => match args.first() {
            Some(Value::Array(a)) => Ok(a.first().cloned().unwrap_or(Value::None)),
            _ => Ok(Value::None),
        },
        "array::last" => match args.first() {
            Some(Value::Array(a)) => Ok(a.last().cloned().unwrap_or(Value::None)),
            _ => Ok(Value::None),
        },
        "array::includes" => match (args.first(), args.get(1)) {
            (Some(Value::Array(a)), Some(item)) => Ok(Value::Bool(a.contains(item))),
            _ => Ok(Value::Bool(false)),
        },
        "array::slice" => match args.first() {
            Some(Value::Array(a)) => {
                let start = args.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0).max(0.0) as usize;
                let len = args.get(2).and_then(|v| v.as_f64()).map(|n| n.max(0.0) as usize);
                let slice = if start >= a.len() {
                    Vec::new()
                } else if let Some(l) = len {
                    a[start..(start + l).min(a.len())].to_vec()
                } else {
                    a[start..].to_vec()
                };
                Ok(Value::Array(slice))
            }
            _ => Ok(Value::Array(Vec::new())),
        },
        "array::union" => {
            let mut out = Vec::new();
            for arg in args {
                if let Value::Array(a) = arg {
                    for item in a {
                        if !out.contains(item) {
                            out.push(item.clone());
                        }
                    }
                }
            }
            Ok(Value::Array(out))
        }
        "array::intersect" => match (args.first(), args.get(1)) {
            (Some(Value::Array(a)), Some(Value::Array(b))) => {
                let mut out = Vec::new();
                for item in a {
                    if b.contains(item) && !out.contains(item) {
                        out.push(item.clone());
                    }
                }
                Ok(Value::Array(out))
            }
            _ => Ok(Value::Array(Vec::new())),
        },

        // --- object::* ---
        "object::keys" => match args.first() {
            Some(Value::Object(m)) => Ok(Value::Array(
                m.keys().map(|k| Value::String(k.clone())).collect(),
            )),
            _ => Ok(Value::Array(Vec::new())),
        },
        "object::values" => match args.first() {
            Some(Value::Object(m)) => Ok(Value::Array(m.values().cloned().collect())),
            _ => Ok(Value::Array(Vec::new())),
        },
        "object::len" => match args.first() {
            Some(Value::Object(m)) => Ok(Value::Int(m.len() as i64)),
            _ => Ok(Value::Int(0)),
        },

        // --- vector::* ---
        "vector::similarity::cosine" => {
            let a = args.first().and_then(value_to_vec).unwrap_or_default();
            let b = args.get(1).and_then(value_to_vec).unwrap_or_default();
            Ok(Value::Float(cosine_similarity(&a, &b)))
        }
        "vector::distance::euclidean" => {
            let a = args.first().and_then(value_to_vec).unwrap_or_default();
            let b = args.get(1).and_then(value_to_vec).unwrap_or_default();
            Ok(Value::Float(euclidean_distance(&a, &b)))
        }
        "vector::distance::manhattan" => {
            let a = args.first().and_then(value_to_vec).unwrap_or_default();
            let b = args.get(1).and_then(value_to_vec).unwrap_or_default();
            Ok(Value::Float(manhattan_distance(&a, &b)))
        }
        "vector::dot" => {
            let a = args.first().and_then(value_to_vec).unwrap_or_default();
            let b = args.get(1).and_then(value_to_vec).unwrap_or_default();
            let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            Ok(Value::Float(dot))
        }

        // --- search::* (feature = "fts") ---
        #[cfg(feature = "fts")]
        "search::highlight" => {
            let prefix = args.first().and_then(|v| v.as_str()).unwrap_or("<b>");
            let suffix = args.get(1).and_then(|v| v.as_str()).unwrap_or("</b>");
            let text = args.get(2).and_then(|v| v.as_str()).unwrap_or("");
            let query = args.get(3).and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::String(crate::search::highlight_terms(
                text, query, prefix, suffix,
            )))
        }

        // --- geo::* (feature = "geo") ---
        #[cfg(feature = "geo")]
        n if n.starts_with("geo::") => crate::geo::eval_geo(n, args),

        // --- crypto::* (feature = "crypto") ---
        #[cfg(feature = "crypto")]
        n if n.starts_with("crypto::") => crate::crypto_ext::eval_crypto(n, args),

        other => Err(anyhow!("Unknown SurrealQL function '{}'", other)),
    }
}

/// Parse SurrealQL duration strings (`30s`, `5m`, `2h`, `7d`, `1w`) into seconds.
pub fn parse_duration_secs(s: &str) -> i64 {
    let trimmed = s.trim();
    if let Some(n) = trimmed.strip_suffix("ms").and_then(|x| x.parse::<i64>().ok()) {
        return n / 1000;
    }
    if let Some(n) = trimmed.strip_suffix('s').and_then(|x| x.parse::<i64>().ok()) {
        return n;
    }
    if let Some(n) = trimmed.strip_suffix('m').and_then(|x| x.parse::<i64>().ok()) {
        return n * 60;
    }
    if let Some(n) = trimmed.strip_suffix('h').and_then(|x| x.parse::<i64>().ok()) {
        return n * 3600;
    }
    if let Some(n) = trimmed.strip_suffix('d').and_then(|x| x.parse::<i64>().ok()) {
        return n * 86400;
    }
    if let Some(n) = trimmed.strip_suffix('w').and_then(|x| x.parse::<i64>().ok()) {
        return n * 604800;
    }
    trimmed.parse::<i64>().unwrap_or(0)
}

fn base64_encode_std(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode_std(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u8;
    for b in s.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    out
}
