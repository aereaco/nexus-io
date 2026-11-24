use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::parser::Expr;
use crate::storage::{encode_key, StorageBackend, PREFIX_ACCESS_META, PREFIX_USER_META};

/// Table-level / row-level permission rules (`PERMISSIONS FOR select, create, update, delete WHERE ...`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TablePermissions {
    pub select: Option<PermRule>,
    pub create: Option<PermRule>,
    pub update: Option<PermRule>,
    pub delete: Option<PermRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermRule {
    Full,
    None,
    Where(Expr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMeta {
    pub name: String,
    pub level: String, // ROOT | NAMESPACE | DATABASE
    pub password_hash: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessMeta {
    pub name: String,
    pub access_type: String, // RECORD | JWT | BEARER
    pub duration_session: Option<String>,
}

/// Pure-Rust salted password hashing (`$nxh$<salt>$<iterated_hash>`) for `DEFINE USER` and
/// `crypto::argon2::generate/compare` parity without C dependencies.
pub fn hash_password(password: &str) -> String {
    let salt = Uuid::new_v4().simple().to_string();
    let digest = stretch_hash(&salt, password);
    format!("$nxh${}${}", salt, digest)
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let Some(rest) = hash.strip_prefix("$nxh$") else {
        return hash == password;
    };
    let Some((salt, expected)) = rest.split_once('$') else {
        return false;
    };
    stretch_hash(salt, password) == expected
}

fn stretch_hash(salt: &str, password: &str) -> String {
    // 1024-round FNV/SHA-style pure-Rust key stretching (fast in debug, zero extra crates)
    let mut state: [u64; 4] = [
        0xcbf29ce484222325,
        0x100000001b3,
        0x9e3779b97f4a7c15,
        0xbf58476d1ce4e5b9,
    ];
    for round in 0..1024u64 {
        for b in salt.bytes().chain(password.bytes()) {
            state[0] = state[0].wrapping_mul(0x100000001b3) ^ (b as u64) ^ round;
            state[1] = state[1].rotate_left(13) ^ state[0];
            state[2] = state[2].wrapping_add(state[1]).rotate_right(7);
            state[3] = state[3] ^ state[2].wrapping_mul(0x9e3779b97f4a7c15);
        }
    }
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        state[0], state[1], state[2], state[3]
    )
}

pub fn save_user(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
    level: &str,
    password: &str,
    roles: Vec<String>,
) -> Result<()> {
    let meta = UserMeta {
        name: name.to_string(),
        level: level.to_string(),
        password_hash: hash_password(password),
        roles,
    };
    let key = encode_key(PREFIX_USER_META, &[ns, db, name]);
    storage.put(&key, &serde_json::to_vec(&meta)?)
}

pub fn authenticate_user(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
    password: &str,
) -> Result<Option<UserMeta>> {
    let key = encode_key(PREFIX_USER_META, &[ns, db, name]);
    if let Some(raw) = storage.get(&key)? {
        let meta: UserMeta = serde_json::from_slice(&raw)?;
        if verify_password(&meta.password_hash, password) {
            return Ok(Some(meta));
        }
    }
    Ok(None)
}

pub fn save_access(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
    access_type: &str,
    duration_session: Option<String>,
) -> Result<()> {
    let meta = AccessMeta {
        name: name.to_string(),
        access_type: access_type.to_string(),
        duration_session,
    };
    let key = encode_key(PREFIX_ACCESS_META, &[ns, db, name]);
    storage.put(&key, &serde_json::to_vec(&meta)?)
}
