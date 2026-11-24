use anyhow::{anyhow, Result};
use std::collections::BTreeMap;

use crate::value::Value;

// Compact 1-byte type tags for zero-loss binary Value encoding.
const TAG_NONE: u8 = 0x00;
const TAG_NULL: u8 = 0x01;
const TAG_FALSE: u8 = 0x02;
const TAG_TRUE: u8 = 0x03;
const TAG_INT: u8 = 0x04;
const TAG_FLOAT: u8 = 0x05;
const TAG_STRING: u8 = 0x06;
const TAG_BYTES: u8 = 0x07;
const TAG_RECORD_ID: u8 = 0x08;
const TAG_DATETIME: u8 = 0x09;
const TAG_DURATION: u8 = 0x0A;
const TAG_DECIMAL: u8 = 0x0B;
const TAG_ARRAY: u8 = 0x0C;
const TAG_OBJECT: u8 = 0x0D;

/// Encode a `Value` into a compact, exact, zero-loss binary byte vector.
/// Preserves exact SurrealQL types (`None` vs `Null`, `Int` vs `Float` vs `Decimal`,
/// `DateTime`, `Duration`, `Bytes`, `RecordId`) without JSON lossiness.
pub fn encode_value(val: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    write_val(val, &mut out);
    out
}

/// Decode a `Value` from binary bytes produced by `encode_value` (with JSON fallback for legacy blobs).
pub fn decode_value(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() {
        return Ok(Value::None);
    }
    // Transparent fallback if reading an older JSON-encoded record (`{` = 0x7B)
    if bytes[0] == b'{' {
        return Ok(serde_json::from_slice(bytes)?);
    }
    let mut pos = 0usize;
    read_val(bytes, &mut pos)
}

fn write_u32(n: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}

fn write_str(s: &str, out: &mut Vec<u8>) {
    write_u32(s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

fn write_val(val: &Value, out: &mut Vec<u8>) {
    match val {
        Value::None => out.push(TAG_NONE),
        Value::Null => out.push(TAG_NULL),
        Value::Bool(false) => out.push(TAG_FALSE),
        Value::Bool(true) => out.push(TAG_TRUE),
        Value::Int(i) => {
            out.push(TAG_INT);
            out.extend_from_slice(&i.to_le_bytes());
        }
        Value::Float(f) => {
            out.push(TAG_FLOAT);
            out.extend_from_slice(&f.to_le_bytes());
        }
        Value::String(s) => {
            out.push(TAG_STRING);
            write_str(s, out);
        }
        Value::Bytes(b) => {
            out.push(TAG_BYTES);
            write_u32(b.len(), out);
            out.extend_from_slice(b);
        }
        Value::RecordId { tb, id } => {
            out.push(TAG_RECORD_ID);
            write_str(tb, out);
            write_str(id, out);
        }
        Value::DateTime(dt) => {
            out.push(TAG_DATETIME);
            write_str(dt, out);
        }
        Value::Duration(secs) => {
            out.push(TAG_DURATION);
            out.extend_from_slice(&secs.to_le_bytes());
        }
        Value::Decimal(d) => {
            out.push(TAG_DECIMAL);
            write_str(d, out);
        }
        Value::Array(arr) => {
            out.push(TAG_ARRAY);
            write_u32(arr.len(), out);
            for item in arr {
                write_val(item, out);
            }
        }
        Value::Object(map) => {
            out.push(TAG_OBJECT);
            write_u32(map.len(), out);
            for (k, v) in map {
                write_str(k, out);
                write_val(v, out);
            }
        }
    }
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<usize> {
    let slice = data
        .get(*pos..*pos + 4)
        .ok_or_else(|| anyhow!("Binary codec EOF reading u32"))?;
    *pos += 4;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize)
}

fn read_i64(data: &[u8], pos: &mut usize) -> Result<i64> {
    let slice = data
        .get(*pos..*pos + 8)
        .ok_or_else(|| anyhow!("Binary codec EOF reading i64"))?;
    *pos += 8;
    Ok(i64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_str(data: &[u8], pos: &mut usize) -> Result<String> {
    let len = read_u32(data, pos)?;
    let slice = data
        .get(*pos..*pos + len)
        .ok_or_else(|| anyhow!("Binary codec EOF reading string"))?;
    *pos += len;
    Ok(String::from_utf8_lossy(slice).to_string())
}

fn read_val(data: &[u8], pos: &mut usize) -> Result<Value> {
    let tag = *data
        .get(*pos)
        .ok_or_else(|| anyhow!("Binary codec EOF reading tag"))?;
    *pos += 1;
    match tag {
        TAG_NONE => Ok(Value::None),
        TAG_NULL => Ok(Value::Null),
        TAG_FALSE => Ok(Value::Bool(false)),
        TAG_TRUE => Ok(Value::Bool(true)),
        TAG_INT => Ok(Value::Int(read_i64(data, pos)?)),
        TAG_FLOAT => {
            let slice = data
                .get(*pos..*pos + 8)
                .ok_or_else(|| anyhow!("Binary codec EOF reading f64"))?;
            *pos += 8;
            Ok(Value::Float(f64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])))
        }
        TAG_STRING => Ok(Value::String(read_str(data, pos)?)),
        TAG_BYTES => {
            let len = read_u32(data, pos)?;
            let slice = data
                .get(*pos..*pos + len)
                .ok_or_else(|| anyhow!("Binary codec EOF reading bytes"))?;
            *pos += len;
            Ok(Value::Bytes(slice.to_vec()))
        }
        TAG_RECORD_ID => {
            let tb = read_str(data, pos)?;
            let id = read_str(data, pos)?;
            Ok(Value::RecordId { tb, id })
        }
        TAG_DATETIME => Ok(Value::DateTime(read_str(data, pos)?)),
        TAG_DURATION => Ok(Value::Duration(read_i64(data, pos)?)),
        TAG_DECIMAL => Ok(Value::Decimal(read_str(data, pos)?)),
        TAG_ARRAY => {
            let len = read_u32(data, pos)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(read_val(data, pos)?);
            }
            Ok(Value::Array(arr))
        }
        TAG_OBJECT => {
            let len = read_u32(data, pos)?;
            let mut map = BTreeMap::new();
            for _ in 0..len {
                let k = read_str(data, pos)?;
                let v = read_val(data, pos)?;
                map.insert(k, v);
            }
            Ok(Value::Object(map))
        }
        other => Err(anyhow!("Unknown binary value tag 0x{:02x}", other)),
    }
}
