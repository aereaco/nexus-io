use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::storage::{encode_key, StorageBackend, PREFIX_BUCKET_META, PREFIX_FILE_BLOB};
use crate::value::Value;

/// Bucket backend definition (`DEFINE BUCKET <name> BACKEND "memory" | "file://<dir>"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketMeta {
    pub name: String,
    pub backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHead {
    pub bucket: String,
    pub key: String,
    pub size: usize,
    pub updated_at: String,
}

/// Parse a SurrealDB file pointer (`"bucket:/path/to/file"` or `"bucket:path"`).
pub fn parse_file_pointer(ptr: &str) -> Result<(String, String)> {
    let clean = ptr.trim();
    let (bucket, key) = clean
        .split_once(':')
        .ok_or_else(|| anyhow!("Invalid file pointer '{}': expected 'bucket:/key'", ptr))?;
    let norm_key = key.trim_start_matches('/').to_string();
    if bucket.is_empty() || norm_key.is_empty() {
        return Err(anyhow!("Invalid file pointer '{}': empty bucket or key", ptr));
    }
    Ok((bucket.to_string(), norm_key))
}

fn load_bucket(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    bucket: &str,
) -> Result<BucketMeta> {
    let key = encode_key(PREFIX_BUCKET_META, &[ns, db, bucket]);
    if let Some(raw) = storage.get(&key)? {
        return Ok(serde_json::from_slice(&raw)?);
    }
    // Allow implicit memory bucket if not explicitly defined
    Ok(BucketMeta {
        name: bucket.to_string(),
        backend: "memory".to_string(),
    })
}

fn disk_path(backend: &str, key: &str) -> Option<PathBuf> {
    backend
        .strip_prefix("file://")
        .map(|dir| PathBuf::from(dir).join(key))
}

pub fn define_bucket(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
    backend: &str,
) -> Result<()> {
    let meta = BucketMeta {
        name: name.to_string(),
        backend: backend.to_string(),
    };
    let key = encode_key(PREFIX_BUCKET_META, &[ns, db, name]);
    storage.put(&key, &serde_json::to_vec(&meta)?)?;
    if let Some(dir) = backend.strip_prefix("file://") {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

pub fn file_put(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    pointer: &str,
    data: Vec<u8>,
) -> Result<Value> {
    let (bucket, key) = parse_file_pointer(pointer)?;
    let meta = load_bucket(storage, ns, db, &bucket)?;
    let size = data.len();

    if let Some(path) = disk_path(&meta.backend, &key) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &data)?;
    } else {
        let blob_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &bucket, &key]);
        storage.put(&blob_key, &data)?;
    }

    let head = FileHead {
        bucket: bucket.clone(),
        key: key.clone(),
        size,
        updated_at: Utc::now().to_rfc3339(),
    };
    let head_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &format!("{}:__head", bucket), &key]);
    storage.put(&head_key, &serde_json::to_vec(&head)?)?;

    Ok(Value::String(format!("{}:/{}", bucket, key)))
}

pub fn file_get(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    pointer: &str,
) -> Result<Value> {
    let (bucket, key) = parse_file_pointer(pointer)?;
    let meta = load_bucket(storage, ns, db, &bucket)?;
    if let Some(path) = disk_path(&meta.backend, &key) {
        let bytes = std::fs::read(&path)?;
        return Ok(Value::Bytes(bytes));
    }
    let blob_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &bucket, &key]);
    match storage.get(&blob_key)? {
        Some(bytes) => Ok(Value::Bytes(bytes)),
        None => Ok(Value::None),
    }
}

pub fn file_exists(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    pointer: &str,
) -> Result<Value> {
    let (bucket, key) = parse_file_pointer(pointer)?;
    let meta = load_bucket(storage, ns, db, &bucket)?;
    if let Some(path) = disk_path(&meta.backend, &key) {
        return Ok(Value::Bool(path.exists()));
    }
    let blob_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &bucket, &key]);
    Ok(Value::Bool(storage.get(&blob_key)?.is_some()))
}

pub fn file_head(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    pointer: &str,
) -> Result<Value> {
    let (bucket, key) = parse_file_pointer(pointer)?;
    let head_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &format!("{}:__head", bucket), &key]);
    if let Some(raw) = storage.get(&head_key)? {
        let head: FileHead = serde_json::from_slice(&raw)?;
        let mut obj = BTreeMap::new();
        obj.insert("bucket".into(), Value::String(head.bucket));
        obj.insert("key".into(), Value::String(head.key));
        obj.insert("size".into(), Value::Int(head.size as i64));
        obj.insert("updated".into(), Value::DateTime(head.updated_at));
        return Ok(Value::Object(obj));
    }
    Ok(Value::None)
}

pub fn file_delete(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    pointer: &str,
) -> Result<Value> {
    let (bucket, key) = parse_file_pointer(pointer)?;
    let meta = load_bucket(storage, ns, db, &bucket)?;
    if let Some(path) = disk_path(&meta.backend, &key) {
        let _ = std::fs::remove_file(path);
    } else {
        let blob_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &bucket, &key]);
        let _ = storage.delete(&blob_key)?;
    }
    let head_key = encode_key(PREFIX_FILE_BLOB, &[ns, db, &format!("{}:__head", bucket), &key]);
    let _ = storage.delete(&head_key)?;
    Ok(Value::None)
}

pub fn file_list(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    bucket: &str,
    prefix: Option<&str>,
) -> Result<Value> {
    let pfx = encode_key(PREFIX_FILE_BLOB, &[ns, db, &format!("{}:__head", bucket)]);
    let mut out = Vec::new();
    for (_, raw) in storage.scan_prefix(&pfx)? {
        if let Ok(head) = serde_json::from_slice::<FileHead>(&raw) {
            if let Some(p) = prefix {
                if !head.key.starts_with(p.trim_start_matches('/')) {
                    continue;
                }
            }
            out.push(Value::String(format!("{}:/{}", head.bucket, head.key)));
        }
    }
    Ok(Value::Array(out))
}

pub fn eval_file_fn(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
    args: &[Value],
) -> Result<Value> {
    match name {
        "file::put" => {
            let ptr = args
                .first()
                .ok_or_else(|| anyhow!("file::put requires (pointer, data)"))?
                .display_compact();
            let bytes = match args.get(1) {
                Some(Value::Bytes(b)) => b.clone(),
                Some(v) => v.display_compact().into_bytes(),
                None => Vec::new(),
            };
            file_put(storage, ns, db, &ptr, bytes)
        }
        "file::get" => {
            let ptr = args
                .first()
                .ok_or_else(|| anyhow!("file::get requires (pointer)"))?
                .display_compact();
            file_get(storage, ns, db, &ptr)
        }
        "file::exists" => {
            let ptr = args
                .first()
                .ok_or_else(|| anyhow!("file::exists requires (pointer)"))?
                .display_compact();
            file_exists(storage, ns, db, &ptr)
        }
        "file::head" => {
            let ptr = args
                .first()
                .ok_or_else(|| anyhow!("file::head requires (pointer)"))?
                .display_compact();
            file_head(storage, ns, db, &ptr)
        }
        "file::delete" => {
            let ptr = args
                .first()
                .ok_or_else(|| anyhow!("file::delete requires (pointer)"))?
                .display_compact();
            file_delete(storage, ns, db, &ptr)
        }
        "file::list" => {
            let bucket = args
                .first()
                .ok_or_else(|| anyhow!("file::list requires (bucket[, prefix])"))?
                .display_compact();
            let pfx = args.get(1).and_then(|v| v.as_str());
            file_list(storage, ns, db, &bucket, pfx)
        }
        "file::copy" => {
            let src = args
                .first()
                .ok_or_else(|| anyhow!("file::copy requires (src, dst)"))?
                .display_compact();
            let dst = args
                .get(1)
                .ok_or_else(|| anyhow!("file::copy requires (src, dst)"))?
                .display_compact();
            if let Value::Bytes(data) = file_get(storage, ns, db, &src)? {
                return file_put(storage, ns, db, &dst, data);
            }
            Err(anyhow!("Source file '{}' not found", src))
        }
        "file::rename" => {
            let src = args
                .first()
                .ok_or_else(|| anyhow!("file::rename requires (src, dst)"))?
                .display_compact();
            let dst = args
                .get(1)
                .ok_or_else(|| anyhow!("file::rename requires (src, dst)"))?
                .display_compact();
            if let Value::Bytes(data) = file_get(storage, ns, db, &src)? {
                let res = file_put(storage, ns, db, &dst, data)?;
                let _ = file_delete(storage, ns, db, &src)?;
                return Ok(res);
            }
            Err(anyhow!("Source file '{}' not found", src))
        }
        "file::bucket" => {
            let ptr = args.first().map(|v| v.display_compact()).unwrap_or_default();
            let (b, _) = parse_file_pointer(&ptr)?;
            Ok(Value::String(b))
        }
        "file::key" => {
            let ptr = args.first().map(|v| v.display_compact()).unwrap_or_default();
            let (_, k) = parse_file_pointer(&ptr)?;
            Ok(Value::String(k))
        }
        other => Err(anyhow!("Unknown file function '{}'", other)),
    }
}
