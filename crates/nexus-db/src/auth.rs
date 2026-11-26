use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::parser::Expr;
use crate::storage::{
    encode_key, StorageBackend, PREFIX_ACCESS_META, PREFIX_BEARER_GRANT, PREFIX_USER_META,
};

type HmacSha256 = Hmac<Sha256>;

/// Default signing secret for local embedded JWTs when no explicit `DEFINE ACCESS ... KEY` is set.
pub const DEFAULT_JWT_SECRET: &str = "nexus-db-sovereign-default-hs256-key";

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

/// SurrealDB-compatible RBAC roles for system users and JWT `rl` claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Role {
    Owner,
    Editor,
    Viewer,
    Record,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "OWNER" | "ADMIN" => Some(Self::Owner),
            "EDITOR" => Some(Self::Editor),
            "VIEWER" => Some(Self::Viewer),
            "RECORD" => Some(Self::Record),
            _ => None,
        }
    }
}

/// Authorization scope level matching SurrealDB's `ROOT` / `NAMESPACE` / `DATABASE` / `RECORD` hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthLevel {
    System,
    Root,
    Namespace(String),
    Database(String, String),
    Record {
        ns: String,
        db: String,
        access: String,
        id: String,
    },
    Anonymous,
}

/// Active authentication & RBAC context attached to a query or RPC session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub level: AuthLevel,
    pub roles: Vec<Role>,
    pub actor: Option<String>,
    pub access_name: Option<String>,
    pub token_claims: Option<serde_json::Value>,
}

impl AuthContext {
    /// Trusted internal/embedded execution context (full privileges).
    pub fn system() -> Self {
        Self {
            level: AuthLevel::System,
            roles: vec![Role::Owner],
            actor: Some("system".to_string()),
            access_name: None,
            token_claims: None,
        }
    }

    /// Unauthenticated anonymous session.
    pub fn anonymous() -> Self {
        Self {
            level: AuthLevel::Anonymous,
            roles: Vec::new(),
            actor: None,
            access_name: None,
            token_claims: None,
        }
    }

    pub fn from_user(meta: &UserMeta, ns: &str, db: &str) -> Self {
        let level = match meta.level.to_ascii_uppercase().as_str() {
            "ROOT" => AuthLevel::Root,
            "NAMESPACE" | "NS" => AuthLevel::Namespace(ns.to_string()),
            _ => AuthLevel::Database(ns.to_string(), db.to_string()),
        };
        let mut roles: Vec<Role> = meta.roles.iter().filter_map(|r| Role::parse(r)).collect();
        if roles.is_empty() {
            roles.push(Role::Viewer);
        }
        Self {
            level,
            roles,
            actor: Some(meta.name.clone()),
            access_name: None,
            token_claims: None,
        }
    }

    pub fn from_jwt_claims(claims: &JwtClaims) -> Self {
        let claims_json = serde_json::to_value(claims).ok();
        if let Some(ref rec_id) = claims.id {
            return Self {
                level: AuthLevel::Record {
                    ns: claims.ns.clone().unwrap_or_default(),
                    db: claims.db.clone().unwrap_or_default(),
                    access: claims.ac.clone().unwrap_or_default(),
                    id: rec_id.clone(),
                },
                roles: vec![Role::Record],
                actor: Some(rec_id.clone()),
                access_name: claims.ac.clone(),
                token_claims: claims_json,
            };
        }

        let level = match (&claims.ns, &claims.db) {
            (Some(ns), Some(db)) => AuthLevel::Database(ns.clone(), db.clone()),
            (Some(ns), None) => AuthLevel::Namespace(ns.clone()),
            _ => AuthLevel::Root,
        };
        // Per SurrealDB spec: JWT system tokens read `rl` claim and default strictly to Viewer if omitted.
        let mut roles: Vec<Role> = claims
            .rl
            .as_ref()
            .map(|list| list.iter().filter_map(|r| Role::parse(r)).collect())
            .unwrap_or_default();
        if roles.is_empty() {
            roles.push(Role::Viewer);
        }
        Self {
            level,
            roles,
            actor: claims.sub.clone(),
            access_name: claims.ac.clone(),
            token_claims: claims_json,
        }
    }

    pub fn is_system(&self) -> bool {
        matches!(self.level, AuthLevel::System)
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self.level, AuthLevel::Anonymous)
    }

    pub fn is_record(&self) -> bool {
        matches!(self.level, AuthLevel::Record { .. })
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    pub fn scope_covers(&self, target_ns: &str, target_db: &str) -> bool {
        match &self.level {
            AuthLevel::System | AuthLevel::Root => true,
            AuthLevel::Namespace(ns) => ns == target_ns,
            AuthLevel::Database(ns, db) => ns == target_ns && db == target_db,
            AuthLevel::Record { ns, db, .. } => ns == target_ns && db == target_db,
            AuthLevel::Anonymous => false,
        }
    }

    pub fn can_read(&self, ns: &str, db: &str) -> bool {
        if self.is_system() {
            return true;
        }
        if !self.scope_covers(ns, db) {
            return false;
        }
        self.has_role(Role::Owner)
            || self.has_role(Role::Editor)
            || self.has_role(Role::Viewer)
            || self.is_record()
    }

    pub fn can_write_data(&self, ns: &str, db: &str) -> bool {
        if self.is_system() {
            return true;
        }
        if !self.scope_covers(ns, db) {
            return false;
        }
        self.has_role(Role::Owner) || self.has_role(Role::Editor) || self.is_record()
    }

    pub fn can_define_schema(&self, ns: &str, db: &str) -> bool {
        if self.is_system() {
            return true;
        }
        if !self.scope_covers(ns, db) {
            return false;
        }
        self.has_role(Role::Owner) || self.has_role(Role::Editor)
    }

    pub fn can_admin_iam(&self, ns: &str, db: &str) -> bool {
        if self.is_system() {
            return true;
        }
        if !self.scope_covers(ns, db) {
            return false;
        }
        self.has_role(Role::Owner)
    }
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
    #[serde(default = "default_level_db")]
    pub level: String, // ROOT | NAMESPACE | DATABASE
    pub access_type: String, // RECORD | JWT | BEARER
    #[serde(default)]
    pub jwt_alg: Option<String>,
    #[serde(default)]
    pub jwt_key: Option<String>,
    #[serde(default)]
    pub signup_sql: Option<String>,
    #[serde(default)]
    pub signin_sql: Option<String>,
    #[serde(default)]
    pub duration_session: Option<String>,
}

fn default_level_db() -> String {
    "DATABASE".to_string()
}

/// SurrealDB-compatible JWT claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `ns`, `db`, `ac`, `rl`, `id`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rl: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Persisted `TYPE BEARER` grant record (`ACCESS <name> GRANT ...` / `REVOKE`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BearerGrant {
    pub grant_id: String,
    pub access_name: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub token_hash: String,
    pub revoked: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Cryptographic Argon2id password hashing (`$argon2id$...`) for `DEFINE USER` and
/// `crypto::argon2::generate/compare` parity (100% pure Rust, zero C dependencies).
pub fn hash_password(password: &str) -> String {
    let salt_bytes = Uuid::new_v4();
    let salt = SaltString::encode_b64(salt_bytes.as_bytes()).expect("valid salt");
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2id hash")
        .to_string()
}

/// Constant-time password verification supporting Argon2id PHC strings (and legacy `$nxh$` hashes).
pub fn verify_password(hash: &str, password: &str) -> bool {
    if hash.starts_with("$argon2") {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }
    if let Some(rest) = hash.strip_prefix("$nxh$") {
        if let Some((salt, expected)) = rest.split_once('$') {
            let computed = legacy_stretch_hash(salt, password);
            return bool::from(computed.as_bytes().ct_eq(expected.as_bytes()));
        }
        return false;
    }
    bool::from(hash.as_bytes().ct_eq(password.as_bytes()))
}

fn legacy_stretch_hash(salt: &str, password: &str) -> String {
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

/// Issue a real HS256-signed JWT string (`header.payload.signature`).
pub fn issue_jwt(claims: &JwtClaims, secret: &str) -> Result<String> {
    let header = serde_json::json!({ "alg": "HS256", "typ": "JWT" });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{}.{}", h_b64, p_b64);

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow!("Invalid HMAC key: {}", e))?;
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let s_b64 = URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("{}.{}", signing_input, s_b64))
}

/// Verify an HS256-signed JWT with constant-time signature check and `exp`/`nbf` validation.
pub fn verify_jwt(token: &str, secret: &str) -> Result<JwtClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let provided_sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("Invalid JWT signature encoding"))?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow!("Invalid HMAC key: {}", e))?;
    mac.update(signing_input.as_bytes());
    let expected_sig = mac.finalize().into_bytes();

    if provided_sig.len() != expected_sig.len()
        || !bool::from(provided_sig.as_slice().ct_eq(expected_sig.as_slice()))
    {
        return Err(anyhow!("Invalid JWT signature"));
    }

    decode_and_validate_claims(parts[1])
}

/// Issue an asymmetric EdDSA (Ed25519) JWT (`header.payload.signature`).
pub fn issue_eddsa_jwt(claims: &JwtClaims, signing_key_bytes: &[u8; 32]) -> Result<String> {
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig = signing_key.sign(signing_input.as_bytes());
    let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(format!("{}.{}", signing_input, s_b64))
}

/// Verify an asymmetric EdDSA (Ed25519) JWT against a 32-byte public key.
pub fn verify_eddsa_jwt(token: &str, public_key_bytes: &[u8; 32]) -> Result<JwtClaims> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("Invalid EdDSA signature encoding"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("Invalid EdDSA signature length"))?;
    let vk = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| anyhow!("Invalid Ed25519 public key"))?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| anyhow!("Invalid EdDSA JWT signature"))?;
    decode_and_validate_claims(parts[1])
}

/// JSON Web Key (JWK) entry for OIDC / JWKS verification (`EdDSA` OKP, `ES256` EC P-256, `RS256` RSA, `HS256` oct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    /// Base64url-encoded Ed25519 public key (`OKP`) or EC P-256 X coordinate (`EC`)
    #[serde(default)]
    pub x: Option<String>,
    /// Base64url-encoded EC P-256 Y coordinate (`EC`)
    #[serde(default)]
    pub y: Option<String>,
    /// Base64url-encoded RSA modulus (`RSA`)
    #[serde(default)]
    pub n: Option<String>,
    /// Base64url-encoded RSA exponent (`RSA`)
    #[serde(default)]
    pub e: Option<String>,
    /// Base64url-encoded symmetric key (`oct`)
    #[serde(default)]
    pub k: Option<String>,
}

/// JSON Web Key Set (`{ "keys": [ ... ] }`) compatible with OIDC providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Verify an ES256 (ECDSA P-256 + SHA-256) JWT using raw `(x, y)` 32-byte coordinates.
pub fn verify_es256_jwt(token: &str, x_bytes: &[u8], y_bytes: &[u8]) -> Result<JwtClaims> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("Invalid ES256 signature encoding"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("Invalid ES256 signature"))?;
    let mut sec1 = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    sec1.push(0x04); // Uncompressed SEC1 point
    sec1.extend_from_slice(x_bytes);
    sec1.extend_from_slice(y_bytes);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| anyhow!("Invalid P-256 public key"))?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| anyhow!("Invalid ES256 JWT signature"))?;
    decode_and_validate_claims(parts[1])
}

/// Verify an RS256 (RSA PKCS#1 v1.5 + SHA-256) JWT using raw big-endian `(n, e)` components.
pub fn verify_rs256_jwt(token: &str, n_bytes: &[u8], e_bytes: &[u8]) -> Result<JwtClaims> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{BigUint, RsaPublicKey};
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("Invalid RS256 signature encoding"))?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| anyhow!("Invalid RS256 signature"))?;
    let pub_key = RsaPublicKey::new(
        BigUint::from_bytes_be(n_bytes),
        BigUint::from_bytes_be(e_bytes),
    )
    .map_err(|_| anyhow!("Invalid RSA public key"))?;
    let vk = VerifyingKey::<Sha256>::new(pub_key);
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| anyhow!("Invalid RS256 JWT signature"))?;
    decode_and_validate_claims(parts[1])
}

/// Verify a JWT against any matching key in a `Jwks` keyset (`EdDSA`, `ES256`, `RS256`, or `HS256`).
pub fn verify_jwt_with_jwks(token: &str, jwks: &Jwks) -> Result<JwtClaims> {
    for jwk in &jwks.keys {
        if jwk.kty.eq_ignore_ascii_case("OKP") {
            if let Some(ref x_b64) = jwk.x {
                if let Ok(raw) = URL_SAFE_NO_PAD.decode(x_b64) {
                    if raw.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&raw);
                        if let Ok(claims) = verify_eddsa_jwt(token, &pk) {
                            return Ok(claims);
                        }
                    }
                }
            }
        } else if jwk.kty.eq_ignore_ascii_case("EC") {
            if let (Some(ref x_b64), Some(ref y_b64)) = (&jwk.x, &jwk.y) {
                if let (Ok(x), Ok(y)) = (URL_SAFE_NO_PAD.decode(x_b64), URL_SAFE_NO_PAD.decode(y_b64)) {
                    if let Ok(claims) = verify_es256_jwt(token, &x, &y) {
                        return Ok(claims);
                    }
                }
            }
        } else if jwk.kty.eq_ignore_ascii_case("RSA") {
            if let (Some(ref n_b64), Some(ref e_b64)) = (&jwk.n, &jwk.e) {
                if let (Ok(n), Ok(e)) = (URL_SAFE_NO_PAD.decode(n_b64), URL_SAFE_NO_PAD.decode(e_b64)) {
                    if let Ok(claims) = verify_rs256_jwt(token, &n, &e) {
                        return Ok(claims);
                    }
                }
            }
        } else if jwk.kty.eq_ignore_ascii_case("oct") {
            if let Some(ref k_b64) = jwk.k {
                if let Ok(raw) = URL_SAFE_NO_PAD.decode(k_b64) {
                    if let Ok(secret) = String::from_utf8(raw) {
                        if let Ok(claims) = verify_jwt(token, &secret) {
                            return Ok(claims);
                        }
                    }
                }
            }
        }
    }
    Err(anyhow!("No key in JWKS verified the provided JWT"))
}

fn decode_and_validate_claims(payload_b64: &str) -> Result<JwtClaims> {
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| anyhow!("Invalid JWT payload encoding"))?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)?;

    let now = Utc::now().timestamp();
    if let Some(exp) = claims.exp {
        if now >= exp {
            return Err(anyhow!("JWT token expired"));
        }
    }
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Err(anyhow!("JWT token not yet valid (nbf)"));
        }
    }

    Ok(claims)
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
        level: level.to_ascii_uppercase(),
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
    // Check DB-level, then NS-level, then ROOT-level user definitions
    for (u_ns, u_db) in [(ns, db), (ns, ""), ("", "")] {
        let key = encode_key(PREFIX_USER_META, &[u_ns, u_db, name]);
        if let Some(raw) = storage.get(&key)? {
            let meta: UserMeta = serde_json::from_slice(&raw)?;
            if verify_password(&meta.password_hash, password) {
                return Ok(Some(meta));
            }
        }
    }
    Ok(None)
}

/// Public, sanitized user summary (never exposes Argon2 password hashes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicUserInfo {
    pub name: String,
    pub level: String,
    pub roles: Vec<String>,
}

pub fn list_users(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
) -> Result<Vec<PublicUserInfo>> {
    let mut seen = std::collections::BTreeMap::new();
    for (u_ns, u_db) in [(ns, db), (ns, ""), ("", "")] {
        let prefix = encode_key(PREFIX_USER_META, &[u_ns, u_db]);
        for (_, raw) in storage.scan_prefix(&prefix)? {
            if let Ok(meta) = serde_json::from_slice::<UserMeta>(&raw) {
                seen.entry(meta.name.clone()).or_insert(PublicUserInfo {
                    name: meta.name,
                    level: meta.level,
                    roles: meta.roles,
                });
            }
        }
    }
    Ok(seen.into_values().collect())
}

pub fn has_any_user(storage: &dyn StorageBackend, ns: &str, db: &str) -> Result<bool> {
    Ok(!list_users(storage, ns, db)?.is_empty())
}

fn is_owner_roles(roles: &[String]) -> bool {
    roles
        .iter()
        .any(|r| matches!(r.trim().to_ascii_uppercase().as_str(), "OWNER" | "ADMIN"))
}

fn count_owners(storage: &dyn StorageBackend, ns: &str, db: &str) -> Result<usize> {
    Ok(list_users(storage, ns, db)?
        .into_iter()
        .filter(|u| is_owner_roles(&u.roles))
        .count())
}

/// Update an existing user's roles and optionally reset their password.
/// Enforces last-OWNER protection so the workspace can never be locked out.
pub fn update_user(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
    roles: Vec<String>,
    new_password: Option<&str>,
) -> Result<Option<PublicUserInfo>> {
    let key = encode_key(PREFIX_USER_META, &[ns, db, name]);
    let Some(raw) = storage.get(&key)? else {
        return Ok(None);
    };
    let mut meta: UserMeta = serde_json::from_slice(&raw)?;
    if is_owner_roles(&meta.roles) && !is_owner_roles(&roles) && count_owners(storage, ns, db)? <= 1 {
        return Err(anyhow!("Cannot demote the last remaining OWNER"));
    }
    meta.roles = roles;
    if let Some(pass) = new_password {
        if !pass.is_empty() {
            meta.password_hash = hash_password(pass);
        }
    }
    storage.put(&key, &serde_json::to_vec(&meta)?)?;
    Ok(Some(PublicUserInfo {
        name: meta.name,
        level: meta.level,
        roles: meta.roles,
    }))
}

/// Delete an existing user from `(ns, db)`.
/// Enforces last-OWNER protection so the final OWNER account cannot be removed.
pub fn delete_user(storage: &dyn StorageBackend, ns: &str, db: &str, name: &str) -> Result<bool> {
    let key = encode_key(PREFIX_USER_META, &[ns, db, name]);
    let Some(raw) = storage.get(&key)? else {
        return Ok(false);
    };
    let meta: UserMeta = serde_json::from_slice(&raw)?;
    if is_owner_roles(&meta.roles) && count_owners(storage, ns, db)? <= 1 {
        return Err(anyhow!("Cannot delete the last remaining OWNER"));
    }
    let _ = storage.delete(&key)?;
    Ok(true)
}

pub fn save_access(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    meta: AccessMeta,
) -> Result<()> {
    let key = encode_key(PREFIX_ACCESS_META, &[ns, db, &meta.name]);
    storage.put(&key, &serde_json::to_vec(&meta)?)
}

pub fn load_access(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    name: &str,
) -> Result<Option<AccessMeta>> {
    let key = encode_key(PREFIX_ACCESS_META, &[ns, db, name]);
    if let Some(raw) = storage.get(&key)? {
        return Ok(Some(serde_json::from_slice(&raw)?));
    }
    Ok(None)
}

pub fn list_accesses(storage: &dyn StorageBackend, ns: &str, db: &str) -> Result<Vec<AccessMeta>> {
    let prefix = encode_key(PREFIX_ACCESS_META, &[ns, db]);
    let mut out = Vec::new();
    for (_, raw) in storage.scan_prefix(&prefix)? {
        if let Ok(meta) = serde_json::from_slice::<AccessMeta>(&raw) {
            out.push(meta);
        }
    }
    Ok(out)
}

/// Issue a revocable `TYPE BEARER` grant (`ACCESS <name> GRANT ...`). Returns `(grant_id, raw_bearer_token)`.
pub fn grant_bearer(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    access_name: &str,
    subject: &str,
    roles: Vec<String>,
    ttl_secs: Option<i64>,
) -> Result<(String, String)> {
    let grant_id = Uuid::new_v4().simple().to_string();
    let raw_token = format!("nxb_{}_{}", grant_id, Uuid::new_v4().simple());
    let now = Utc::now().timestamp();
    let grant = BearerGrant {
        grant_id: grant_id.clone(),
        access_name: access_name.to_string(),
        subject: subject.to_string(),
        roles,
        token_hash: hash_password(&raw_token),
        revoked: false,
        created_at: now,
        expires_at: ttl_secs.map(|s| now + s),
    };
    let key = encode_key(PREFIX_BEARER_GRANT, &[ns, db, access_name, &grant_id]);
    storage.put(&key, &serde_json::to_vec(&grant)?)?;
    Ok((grant_id, raw_token))
}

/// Revoke an existing `TYPE BEARER` grant (`ACCESS <name> REVOKE <grant_id>`).
pub fn revoke_bearer(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    access_name: &str,
    grant_id: &str,
) -> Result<bool> {
    let key = encode_key(PREFIX_BEARER_GRANT, &[ns, db, access_name, grant_id]);
    if let Some(raw) = storage.get(&key)? {
        let mut grant: BearerGrant = serde_json::from_slice(&raw)?;
        grant.revoked = true;
        storage.put(&key, &serde_json::to_vec(&grant)?)?;
        return Ok(true);
    }
    Ok(false)
}

/// Authenticate a bearer token (`nxb_...`) or HS256 JWT against configured `DEFINE ACCESS` rules.
pub fn authenticate_token(
    storage: &dyn StorageBackend,
    ns: &str,
    db: &str,
    token: &str,
) -> Result<AuthContext> {
    // 1. Check revocable Bearer grants (`nxb_<grant_id>_...`)
    if token.starts_with("nxb_") {
        let prefix = encode_key(PREFIX_BEARER_GRANT, &[ns, db]);
        let now = Utc::now().timestamp();
        for (_, raw) in storage.scan_prefix(&prefix)? {
            let Ok(grant) = serde_json::from_slice::<BearerGrant>(&raw) else {
                continue;
            };
            if grant.revoked {
                continue;
            }
            if let Some(exp) = grant.expires_at {
                if now >= exp {
                    continue;
                }
            }
            if verify_password(&grant.token_hash, token) {
                let mut roles: Vec<Role> = grant
                    .roles
                    .iter()
                    .filter_map(|r| Role::parse(r))
                    .collect();
                if roles.is_empty() {
                    roles.push(Role::Viewer);
                }
                return Ok(AuthContext {
                    level: AuthLevel::Database(ns.to_string(), db.to_string()),
                    roles,
                    actor: Some(grant.subject),
                    access_name: Some(grant.access_name),
                    token_claims: None,
                });
            }
        }
        return Err(anyhow!("Invalid, expired, or revoked bearer token"));
    }

    // 2. Try verifying HS256 JWT against any configured `DEFINE ACCESS ... KEY` first, then default key.
    let mut keys = Vec::new();
    for access in list_accesses(storage, ns, db)? {
        if let Some(k) = access.jwt_key {
            keys.push(k);
        }
    }
    keys.push(DEFAULT_JWT_SECRET.to_string());

    for secret in keys {
        if let Ok(claims) = verify_jwt(token, &secret) {
            return Ok(AuthContext::from_jwt_claims(&claims));
        }
    }
    Err(anyhow!("Authentication failed: invalid or expired JWT"))
}
