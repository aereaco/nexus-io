//! Nexus-IDP — Universal Identity-First, Hierarchical Organization & Authorization Engine
//!
//! Backed directly by `nexus-db` (`nexus::system`) with **zero extra crates in `core`**
//! (reusing `argon2`, `ed25519-dalek`, `blake3`, `base64`, and `uuid` already in `core`).
//!
//! Core Architectural Invariants:
//! 1. **Identity-First Sovereignty:** `Identity` exists independently of every `Organization`.
//!    Self-certifying portable ID: `nxid_<BLAKE3("NEXUS-ID-v1" || T || N || K_0)>` with
//!    Ed25519 signed genesis record and signed key-rotation chain. Revoking an org membership
//!    revokes org-scoped tokens/grants without deleting the holder's identity or personal data.
//! 2. **Universal Hierarchical Organizations (No Operating Modes):** Arbitrary-depth nesting
//!    bounded by configurable `HierarchyLimits` (`max_depth`, `max_subtree_size`). Materialized
//!    paths use **immutable `org_id`s** (`/org_root/org_emea/org_de`) so renaming `slug` never
//!    requires rewriting descendant paths.
//! 3. **Hierarchy != Authorization:** Parent org administration does NOT implicitly grant child
//!    org access. Every `OrgMembership` carries an explicit, auditable, revocable `DelegationScope`
//!    (`SelfOnly`, `Descendants`, `Subtree`, `Selected`).
//! 4. **Roles as Permission Bundles & Policy-Specific Composition:** Roles expand to granular
//!    permissions evaluated server-side; security policies compose down the ancestor chain with
//!    per-field semantics and explicit provenance (`InheritedEnforced`, `InheritedDefault`,
//!    `LocallyOverridden`, `ProhibitedByParent`).
//! 5. **Standards-Compliant Cryptography:** Argon2id for client secrets, Ed25519 `EdDSA` JWTs
//!    with RFC 8037 `OKP` JWKS, OAuth 2.1 mandatory PKCE `S256`, rotating refresh tokens with
//!    token-family replay revocation, RFC 6238 TOTP MFA, and immutable `sys_iam_audit`.

use anyhow::{anyhow, Result};
use base64::Engine as _;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::db::Database;

/// Serializes refresh-token rotation + replay-family revocation to prevent concurrent refresh races.
static REFRESH_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Serializes organization hierarchy mutations (`create_org`, `reparent_org`) to prevent split-brain cycles.
static HIERARCHY_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

fn random_token(prefix: &str) -> String {
    let a = uuid::Uuid::new_v4().simple().to_string();
    let b = uuid::Uuid::new_v4().simple().to_string();
    format!("{}_{}{}", prefix, a, b)
}

fn hash_lookup_key(raw: &str) -> String {
    blake3::hash(raw.as_bytes()).to_hex().to_string()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// =============================================================================
// 1. Portable Self-Certifying Identity Core (`NEXUS-ID-v1`)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    Active,
    Suspended,
}

/// Immutable cryptographic genesis proof for a Nexus Identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityGenesis {
    pub version: String,
    pub created_at_ms: u64,
    pub nonce: String,
    pub root_pubkey: String,
    pub genesis_sig: String,
}

/// Signed key-rotation transition chaining `prev_pubkey -> new_pubkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKeyTransition {
    pub seq: u64,
    pub prev_pubkey: String,
    pub new_pubkey: String,
    pub rotated_at_ms: u64,
    pub sig_by_prev: String,
}

/// Permanent, organization-independent identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub identity_id: String,
    pub display_name: String,
    pub primary_email: Option<String>,
    pub genesis: IdentityGenesis,
    pub active_pubkey: String,
    pub key_history: Vec<IdentityKeyTransition>,
    pub status: IdentityStatus,
    pub created_at_ms: u64,
}

/// Signed portable identity package for cross-cluster recognition.
/// Strictly excludes private secrets, recovery keys, and local org memberships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableIdentityPackage {
    pub identity_id: String,
    pub display_name: String,
    pub genesis: IdentityGenesis,
    pub active_pubkey: String,
    pub key_history: Vec<IdentityKeyTransition>,
    pub exported_at_ms: u64,
    pub package_sig: String,
}

fn validate_ed25519_pubkey_b64url(pk: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pk)
        .map_err(|_| anyhow!("Invalid base64url Ed25519 public key"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must be exactly 32 bytes"))?;
    Ok(arr)
}

fn validate_genesis_nonce(nonce: &str) -> Result<()> {
    if nonce.len() < 16 || nonce.len() > 128 {
        anyhow::bail!("Genesis nonce must be 16..=128 characters");
    }
    if !nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        anyhow::bail!("Genesis nonce contains invalid characters");
    }
    Ok(())
}

/// Unambiguous length-prefixed canonical genesis framing:
/// `"NEXUS-ID-v1" || u64_be(T) || u32_be(nonce.len) || nonce || u32_be(pk.len) || pk`.
pub fn canonical_genesis_bytes(created_at_ms: u64, nonce: &str, root_pubkey: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(11 + 8 + 4 + nonce.len() + 4 + root_pubkey.len());
    buf.extend_from_slice(b"NEXUS-ID-v1");
    buf.extend_from_slice(&created_at_ms.to_be_bytes());
    buf.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    buf.extend_from_slice(nonce.as_bytes());
    buf.extend_from_slice(&(root_pubkey.len() as u32).to_be_bytes());
    buf.extend_from_slice(root_pubkey.as_bytes());
    buf
}

/// Compute self-certifying immutable identity ID: `nxid_<BLAKE3(canonical_genesis_bytes)>`.
pub fn compute_identity_id(created_at_ms: u64, nonce: &str, root_pubkey: &str) -> String {
    let payload = canonical_genesis_bytes(created_at_ms, nonce, root_pubkey);
    format!("nxid_{}", blake3::hash(&payload).to_hex())
}

fn canonical_rotation_bytes(
    identity_id: &str,
    seq: u64,
    prev_pubkey: &str,
    new_pubkey: &str,
    rotated_at_ms: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        19 + 4 + identity_id.len() + 8 + 4 + prev_pubkey.len() + 4 + new_pubkey.len() + 8,
    );
    buf.extend_from_slice(b"NEXUS-KEY-ROTATE-v1");
    buf.extend_from_slice(&(identity_id.len() as u32).to_be_bytes());
    buf.extend_from_slice(identity_id.as_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&(prev_pubkey.len() as u32).to_be_bytes());
    buf.extend_from_slice(prev_pubkey.as_bytes());
    buf.extend_from_slice(&(new_pubkey.len() as u32).to_be_bytes());
    buf.extend_from_slice(new_pubkey.as_bytes());
    buf.extend_from_slice(&rotated_at_ms.to_be_bytes());
    buf
}

fn canonical_package_bytes(
    identity_id: &str,
    active_pubkey: &str,
    history_len: usize,
    exported_at_ms: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + 4 + identity_id.len() + 4 + active_pubkey.len() + 8 + 8);
    buf.extend_from_slice(b"NEXUS-ID-EXPORT-v1");
    buf.extend_from_slice(&(identity_id.len() as u32).to_be_bytes());
    buf.extend_from_slice(identity_id.as_bytes());
    buf.extend_from_slice(&(active_pubkey.len() as u32).to_be_bytes());
    buf.extend_from_slice(active_pubkey.as_bytes());
    buf.extend_from_slice(&(history_len as u64).to_be_bytes());
    buf.extend_from_slice(&exported_at_ms.to_be_bytes());
    buf
}

/// Cryptographically verify a `PortableIdentityPackage` with default freshness policy
/// (`max_age_secs = 86_400`, `max_future_skew_secs = 300`).
pub fn verify_identity_package(pkg: &PortableIdentityPackage) -> Result<()> {
    verify_identity_package_with_policy(pkg, 86_400, 300)
}

/// Cryptographically verify a `PortableIdentityPackage` with explicit freshness & skew bounds.
pub fn verify_identity_package_with_policy(
    pkg: &PortableIdentityPackage,
    max_age_secs: u64,
    max_future_skew_secs: u64,
) -> Result<()> {
    if pkg.genesis.version != "NEXUS-ID-v1" {
        anyhow::bail!("Unsupported identity genesis version '{}'", pkg.genesis.version);
    }
    validate_genesis_nonce(&pkg.genesis.nonce)?;
    validate_ed25519_pubkey_b64url(&pkg.genesis.root_pubkey)?;
    validate_ed25519_pubkey_b64url(&pkg.active_pubkey)?;

    // Freshness & clock-skew checks
    let now = now_ms();
    let max_future_ms = max_future_skew_secs.saturating_mul(1000);
    let max_age_ms = max_age_secs.saturating_mul(1000);
    if pkg.exported_at_ms > now.saturating_add(max_future_ms) {
        anyhow::bail!("Portable identity package exported_at_ms is in the future");
    }
    if now.saturating_sub(pkg.exported_at_ms) > max_age_ms {
        anyhow::bail!("Portable identity package has expired (exceeded max_age_secs)");
    }
    if pkg.exported_at_ms < pkg.genesis.created_at_ms {
        anyhow::bail!("Portable identity package exported_at_ms precedes genesis created_at_ms");
    }

    let expected_id = compute_identity_id(
        pkg.genesis.created_at_ms,
        &pkg.genesis.nonce,
        &pkg.genesis.root_pubkey,
    );
    if !constant_time_eq(expected_id.as_bytes(), pkg.identity_id.as_bytes()) {
        anyhow::bail!("Identity ID does not match genesis hash");
    }
    let gen_bytes = canonical_genesis_bytes(
        pkg.genesis.created_at_ms,
        &pkg.genesis.nonce,
        &pkg.genesis.root_pubkey,
    );
    if !nexus_db::auth::ed25519_verify(
        &pkg.genesis.root_pubkey,
        &gen_bytes,
        &pkg.genesis.genesis_sig,
    ) {
        anyhow::bail!("Invalid Ed25519 genesis signature");
    }

    let mut current_pk = pkg.genesis.root_pubkey.clone();
    let mut prev_ts = pkg.genesis.created_at_ms;
    let mut seen_keys: HashSet<String> = HashSet::new();
    seen_keys.insert(current_pk.clone());

    for (idx, tr) in pkg.key_history.iter().enumerate() {
        let expected_seq = (idx as u64) + 1;
        if tr.seq != expected_seq || tr.prev_pubkey != current_pk {
            anyhow::bail!("Broken key transition chain at seq {}", tr.seq);
        }
        validate_ed25519_pubkey_b64url(&tr.new_pubkey)?;
        if tr.new_pubkey == tr.prev_pubkey || seen_keys.contains(&tr.new_pubkey) {
            anyhow::bail!("Key rotation cannot reuse a previous or compromised public key");
        }
        if tr.rotated_at_ms < prev_ts {
            anyhow::bail!("Key transition timestamp regression at seq {}", tr.seq);
        }
        let rot_bytes = canonical_rotation_bytes(
            &pkg.identity_id,
            tr.seq,
            &tr.prev_pubkey,
            &tr.new_pubkey,
            tr.rotated_at_ms,
        );
        if !nexus_db::auth::ed25519_verify(&tr.prev_pubkey, &rot_bytes, &tr.sig_by_prev) {
            anyhow::bail!("Invalid key transition signature at seq {}", tr.seq);
        }
        seen_keys.insert(tr.new_pubkey.clone());
        current_pk = tr.new_pubkey.clone();
        prev_ts = tr.rotated_at_ms;
    }
    if current_pk != pkg.active_pubkey {
        anyhow::bail!("active_pubkey does not match end of key history chain");
    }
    let pkg_bytes = canonical_package_bytes(
        &pkg.identity_id,
        &pkg.active_pubkey,
        pkg.key_history.len(),
        pkg.exported_at_ms,
    );
    if !nexus_db::auth::ed25519_verify(&pkg.active_pubkey, &pkg_bytes, &pkg.package_sig) {
        anyhow::bail!("Invalid portable identity package signature");
    }
    Ok(())
}

/// Complete RFC 7519 / RFC 8037 JWT validation policy (header + claims + JWKS signature).
#[derive(Debug, Clone)]
pub struct JwtValidationPolicy {
    pub expected_issuer: String,
    pub expected_audience: String,
    pub expected_typ: String,
    pub clock_skew_secs: u64,
}

impl JwtValidationPolicy {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            expected_issuer: issuer.into(),
            expected_audience: audience.into(),
            expected_typ: "JWT".into(),
            clock_skew_secs: 60,
        }
    }
}

/// Complete RFC 7519 / RFC 8037 `EdDSA` JWT verifier:
/// Validates `alg == "EdDSA"`, `typ`, `kid` lookup in JWKS (`kty == "OKP"`, `crv == "Ed25519"`),
/// Ed25519 signature, `iss`, `aud`, `exp`, `nbf`, and `iat`.
pub fn validate_eddsa_jwt(
    token: &str,
    jwks: &serde_json::Value,
    policy: &JwtValidationPolicy,
) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Malformed JWT: expected 3 dot-separated segments");
    }
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid JWT header base64url"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| anyhow!("Invalid JWT header JSON"))?;

    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        anyhow::bail!("JWT header alg must be 'EdDSA'");
    }
    if header.get("typ").and_then(|v| v.as_str()) != Some(policy.expected_typ.as_str()) {
        anyhow::bail!("JWT header typ mismatch");
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("JWT header missing required 'kid'"))?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("JWKS missing 'keys' array"))?;
    let jwk = keys
        .iter()
        .find(|k| {
            k.get("kid").and_then(|v| v.as_str()) == Some(kid)
                && k.get("kty").and_then(|v| v.as_str()) == Some("OKP")
                && k.get("crv").and_then(|v| v.as_str()) == Some("Ed25519")
        })
        .ok_or_else(|| anyhow!("No matching Ed25519 JWK found for kid '{}'", kid))?;
    let pub_x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Matched JWK missing 'x' public key"))?;

    let claims = nexus_db::auth::verify_eddsa_jwt_json(token, pub_x)?;

    if claims.get("iss").and_then(|v| v.as_str()) != Some(policy.expected_issuer.as_str()) {
        anyhow::bail!("JWT issuer mismatch");
    }
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == &policy.expected_audience,
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .any(|v| v.as_str() == Some(policy.expected_audience.as_str())),
        _ => false,
    };
    if !aud_ok {
        anyhow::bail!("JWT audience mismatch");
    }
    let now = now_secs();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("JWT missing required 'exp' claim"))?;
    if now > exp.saturating_add(policy.clock_skew_secs) {
        anyhow::bail!("JWT has expired");
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_u64()) {
        if now.saturating_add(policy.clock_skew_secs) < nbf {
            anyhow::bail!("JWT is not yet valid (nbf)");
        }
    }
    if let Some(iat) = claims.get("iat").and_then(|v| v.as_u64()) {
        if iat > now.saturating_add(policy.clock_skew_secs) {
            anyhow::bail!("JWT iat is in the future");
        }
    }
    Ok(claims)
}

// =============================================================================
// 2. Hierarchical Organizations & Policy-Specific Composition
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgStatus {
    Active,
    Suspended,
    Pending,
}

/// Configurable guardrails preventing pathological resource consumption in arbitrary-depth trees.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HierarchyLimits {
    pub max_depth: u32,
    pub max_subtree_size: usize,
}

impl Default for HierarchyLimits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_subtree_size: 10_000,
        }
    }
}

/// Per-organization locally configured policy settings (only fields explicitly set on this org).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgPolicyPatch {
    /// Monotonic tighten-only: once `true` on an ancestor, descendants cannot disable MFA.
    #[serde(default)]
    pub mfa_required: Option<bool>,
    /// Monotonic max: descendants can increase minimum password length, never decrease it.
    #[serde(default)]
    pub min_password_length: Option<u32>,
    /// Monotonic min: descendants can shorten max session lifetime, never extend it.
    #[serde(default)]
    pub max_session_ttl_secs: Option<u64>,
    /// Set intersection: descendants can only restrict allowed authentication methods.
    #[serde(default)]
    pub allowed_auth_methods: Option<Vec<String>>,
    /// Child-overrideable branding display name.
    #[serde(default)]
    pub branding_name: Option<String>,
    /// Child-overrideable login page theme / customization identifier.
    #[serde(default)]
    pub login_theme: Option<String>,
    /// Parent-restricted, child-selectable external IdPs (subset of parent's allowed list).
    #[serde(default)]
    pub allowed_external_idps: Option<Vec<String>>,
}

/// Explicit provenance surfaced to the UI so policy inheritance is transparent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProvenance {
    InheritedEnforced,
    InheritedDefault,
    LocallyOverridden,
    ProhibitedByParent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPolicyField<T> {
    pub value: T,
    pub provenance: PolicyProvenance,
    pub source_org_id: String,
}

/// Fully composed effective policy for an organization, with per-field provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposedOrgPolicy {
    pub org_id: String,
    pub mfa_required: ResolvedPolicyField<bool>,
    pub min_password_length: ResolvedPolicyField<u32>,
    pub max_session_ttl_secs: ResolvedPolicyField<u64>,
    pub allowed_auth_methods: ResolvedPolicyField<Vec<String>>,
    pub branding_name: ResolvedPolicyField<String>,
    pub login_theme: ResolvedPolicyField<String>,
    pub allowed_external_idps: ResolvedPolicyField<Vec<String>>,
}

/// First-class hierarchical Organization with immutable-ID materialized path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub parent_org_id: Option<String>,
    /// Immutable-ID materialized path, e.g. `/org_acme/org_emea/org_de`.
    pub path: String,
    pub depth: u32,
    pub status: OrgStatus,
    pub primary_domain: Option<String>,
    #[serde(default)]
    pub local_policy: OrgPolicyPatch,
    pub created_at_ms: u64,
}

// =============================================================================
// 3. Explicit Membership, Delegation Scopes & Permission Bundles
// =============================================================================

/// Explicit delegation boundary — hierarchy NEVER implies automatic child authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelegationScope {
    /// Authority applies strictly to `org_id` alone (default).
    SelfOnly,
    /// Authority applies to `org_id` and all descendants in its materialized path.
    Descendants,
    /// Authority applies to an explicitly named subtree root and its descendants.
    Subtree { root_org_id: String },
    /// Authority applies strictly to an explicit allowlist of organization IDs.
    Selected { org_ids: Vec<String> },
}

impl Default for DelegationScope {
    fn default() -> Self {
        Self::SelfOnly
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    Invited,
    Active,
    Suspended,
    Revoked,
}

/// Explicit relationship binding an independent `Identity` to an `Organization`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMembership {
    pub membership_id: String,
    pub subject_id: String,
    pub org_id: String,
    pub role_assignments: Vec<String>,
    #[serde(default)]
    pub direct_permissions: Vec<String>,
    #[serde(default)]
    pub scope: DelegationScope,
    pub status: MembershipStatus,
    pub granted_by: String,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
}

/// Custom or built-in Role (strictly a named bundle of granular permissions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBundle {
    pub role_id: String,
    pub org_id: Option<String>,
    pub name: String,
    pub permissions: Vec<String>,
}

/// Server-side permission evaluation decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub subject_id: String,
    pub org_id: String,
    pub action: String,
    pub reason: String,
    pub matched_membership_id: Option<String>,
}

/// Built-in default permission bundles (roles are never hardcoded security primitives).
pub fn builtin_role_permissions(role_name: &str) -> Vec<&'static str> {
    match role_name.to_ascii_uppercase().as_str() {
        "ORG_ADMIN" => vec![
            "iam.org.read",
            "iam.org.update",
            "iam.org.create_child",
            "iam.users.read",
            "iam.users.manage",
            "iam.groups.manage",
            "iam.roles.manage",
            "iam.clients.read",
            "iam.clients.manage",
            "iam.policy.read",
            "iam.policy.update",
            "iam.audit.read",
        ],
        "USER_MANAGER" => vec!["iam.org.read", "iam.users.read", "iam.users.manage", "iam.groups.manage"],
        "APP_ADMIN" => vec!["iam.org.read", "iam.clients.read", "iam.clients.manage"],
        "AUDITOR" => vec!["iam.org.read", "iam.users.read", "iam.policy.read", "iam.audit.read"],
        "MEMBER" => vec!["iam.org.read"],
        _ => vec![],
    }
}

// =============================================================================
// 4. OAuth 2.1 / OIDC Clients, Tokens, Signing Keys, TOTP & Audit
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcClientType {
    Public,
    Confidential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    pub client_id: String,
    pub org_id: String,
    pub name: String,
    pub client_type: OidcClientType,
    /// Argon2id PHC string for confidential clients (`None` for public PKCE clients).
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub pkce_required: bool,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeRecord {
    pub code_hash: String,
    pub client_id: String,
    pub org_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub used: bool,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedTokenRecord {
    pub token_hash: String,
    pub family_id: String,
    pub token_type: String,
    pub client_id: String,
    pub org_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub scope: String,
    pub rotated: bool,
    pub revoked: bool,
    pub expires_at_ms: u64,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub org_id: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSigningKey {
    pub kid: String,
    pub secret_b64url: String,
    pub public_b64url: String,
    pub active: bool,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
    pub subject: String,
    pub org_id: String,
    pub secret_base32: String,
    pub verified: bool,
    pub recovery_code_hashes: Vec<String>,
    pub enrolled_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamAuditEvent {
    pub event_id: String,
    pub org_id: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub detail: String,
    pub timestamp_ms: u64,
}

// =============================================================================
// 5. NexusIdp Engine
// =============================================================================

#[derive(Clone)]
pub struct NexusIdp {
    db: Arc<Database>,
    limits: HierarchyLimits,
}

impl NexusIdp {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            limits: HierarchyLimits::default(),
        }
    }

    pub fn with_hierarchy_limits(mut self, limits: HierarchyLimits) -> Self {
        self.limits = limits;
        self
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_iam_identity SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_org SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_org_member SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_role SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_oidc_client SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_auth_code SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_token SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_signing_key SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_totp SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_audit SCHEMALESS;";
        let _ = self.db.client.query(ddl).await;
        self.ensure_default_org().await?;
        let _ = self.ensure_active_signing_key().await?;
        Ok(())
    }

    async fn ensure_default_org(&self) -> Result<()> {
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_org', 'default')")
            .await?;
        let existing: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        if existing.is_empty() {
            let default_org = Organization {
                org_id: "default".into(),
                slug: "default".into(),
                name: "Default Organization".into(),
                parent_org_id: None,
                path: "/default".into(),
                depth: 0,
                status: OrgStatus::Active,
                primary_domain: None,
                local_policy: OrgPolicyPatch::default(),
                created_at_ms: now_ms(),
            };
            let val = serde_json::to_value(&default_org)?;
            let _ = self
                .db
                .client
                .query("UPSERT type::record('sys_iam_org', 'default') CONTENT $org;")
                .bind(("org", val))
                .await;
        }
        Ok(())
    }

    /// Ensure an active Ed25519 `EdDSA` signing key exists for OIDC `id_token` & `/.well-known/jwks.json`.
    pub async fn ensure_active_signing_key(&self) -> Result<ClusterSigningKey> {
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_signing_key")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        for v in rows {
            if let Ok(k) = serde_json::from_value::<ClusterSigningKey>(v) {
                if k.active {
                    return Ok(k);
                }
            }
        }
        let (sk, pk) = nexus_db::auth::ed25519_generate_keypair();
        let kid = format!("nxk_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let key = ClusterSigningKey {
            kid: kid.clone(),
            secret_b64url: sk,
            public_b64url: pk,
            active: true,
            created_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&key)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_signing_key', $id) CONTENT $k;")
            .bind(("id", kid))
            .bind(("k", val))
            .await?
            .check()?;
        Ok(key)
    }

    /// Return RFC 8037 JWKS JSON (`{"keys": [...]}`) containing all cluster Ed25519 public keys.
    pub async fn jwks(&self) -> Result<serde_json::Value> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_signing_key")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let keys: Vec<serde_json::Value> = rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ClusterSigningKey>(v).ok())
            .map(|k| nexus_db::auth::ed25519_jwk(&k.kid, &k.public_b64url))
            .collect();
        Ok(serde_json::json!({ "keys": keys }))
    }

    // -------------------------------------------------------------------------
    // Immutable Audit Log
    // -------------------------------------------------------------------------

    pub async fn append_audit(
        &self,
        org_id: &str,
        actor: &str,
        action: &str,
        target: &str,
        outcome: &str,
        detail: &str,
    ) -> Result<()> {
        let ev = IamAuditEvent {
            event_id: uuid::Uuid::new_v4().simple().to_string(),
            org_id: org_id.to_string(),
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            outcome: outcome.to_string(),
            detail: detail.to_string(),
            timestamp_ms: now_ms(),
        };
        let val = serde_json::to_value(&ev)?;
        let _ = self
            .db
            .client
            .query("UPSERT type::record('sys_iam_audit', $id) CONTENT $ev;")
            .bind(("id", ev.event_id.clone()))
            .bind(("ev", val))
            .await;
        Ok(())
    }

    pub async fn list_audit_events(
        &self,
        org_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<IamAuditEvent>> {
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_audit").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut out: Vec<IamAuditEvent> = rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<IamAuditEvent>(v).ok())
            .filter(|e| org_id.map(|o| e.org_id == o).unwrap_or(true))
            .collect();
        out.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        out.truncate(limit.clamp(1, 500));
        Ok(out)
    }

    // -------------------------------------------------------------------------
    // Identity Core (Self-Certifying Portable Identities)
    // -------------------------------------------------------------------------

    /// Create a new organization-independent `Identity` with an Ed25519 genesis proof.
    /// Returns `(Identity, root_secret_b64url)`. The private key is returned once to the holder.
    pub async fn create_identity(
        &self,
        display_name: &str,
        primary_email: Option<String>,
    ) -> Result<(Identity, String)> {
        self.ensure_tables().await?;
        let created_at_ms = now_ms();
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let (root_secret, root_pubkey) = nexus_db::auth::ed25519_generate_keypair();
        let gen_bytes = canonical_genesis_bytes(created_at_ms, &nonce, &root_pubkey);
        let genesis_sig = nexus_db::auth::ed25519_sign(&root_secret, &gen_bytes)?;
        let identity_id = compute_identity_id(created_at_ms, &nonce, &root_pubkey);

        let identity = Identity {
            identity_id: identity_id.clone(),
            display_name: display_name.trim().to_string(),
            primary_email,
            genesis: IdentityGenesis {
                version: "NEXUS-ID-v1".into(),
                created_at_ms,
                nonce,
                root_pubkey: root_pubkey.clone(),
                genesis_sig,
            },
            active_pubkey: root_pubkey,
            key_history: Vec::new(),
            status: IdentityStatus::Active,
            created_at_ms,
        };
        let val = serde_json::to_value(&identity)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_identity', $id) CONTENT $ident;")
            .bind(("id", identity_id.clone()))
            .bind(("ident", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                "instance",
                &identity_id,
                "identity.create",
                &identity_id,
                "ok",
                "NEXUS-ID-v1 genesis created",
            )
            .await;
        Ok((identity, root_secret))
    }

    pub async fn get_identity(&self, identity_id: &str) -> Result<Option<Identity>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_identity', $id)")
            .bind(("id", identity_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<Identity>(v.clone()).ok()))
    }

    pub async fn list_identities(&self) -> Result<Vec<Identity>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_identity")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut out: Vec<Identity> = rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Identity>(v).ok())
            .collect();
        out.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms));
        Ok(out)
    }

    /// Rotate an identity's active Ed25519 key by proving possession of the current secret key.
    pub async fn rotate_identity_key(
        &self,
        identity_id: &str,
        current_secret_b64url: &str,
    ) -> Result<(Identity, String)> {
        let mut ident = self
            .get_identity(identity_id)
            .await?
            .ok_or_else(|| anyhow!("Identity '{}' not found", identity_id))?;
        let (new_secret, new_pubkey) = nexus_db::auth::ed25519_generate_keypair();
        let seq = (ident.key_history.len() as u64) + 1;
        let rotated_at_ms = now_ms();
        let rot_bytes = canonical_rotation_bytes(
            &ident.identity_id,
            seq,
            &ident.active_pubkey,
            &new_pubkey,
            rotated_at_ms,
        );
        let sig_by_prev = nexus_db::auth::ed25519_sign(current_secret_b64url, &rot_bytes)?;
        if !nexus_db::auth::ed25519_verify(&ident.active_pubkey, &rot_bytes, &sig_by_prev) {
            anyhow::bail!("Current secret key does not match identity's active_pubkey");
        }
        ident.key_history.push(IdentityKeyTransition {
            seq,
            prev_pubkey: ident.active_pubkey.clone(),
            new_pubkey: new_pubkey.clone(),
            rotated_at_ms,
            sig_by_prev,
        });
        ident.active_pubkey = new_pubkey;
        let val = serde_json::to_value(&ident)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_identity', $id) CONTENT $ident;")
            .bind(("id", ident.identity_id.clone()))
            .bind(("ident", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                "instance",
                &ident.identity_id,
                "identity.key.rotate",
                &ident.identity_id,
                "ok",
                &format!("seq={}", seq),
            )
            .await;
        Ok((ident, new_secret))
    }

    /// Export a signed, portable identity package (public genesis + key history only; zero secrets).
    pub async fn export_identity_package(
        &self,
        identity_id: &str,
        active_secret_b64url: &str,
    ) -> Result<PortableIdentityPackage> {
        let ident = self
            .get_identity(identity_id)
            .await?
            .ok_or_else(|| anyhow!("Identity '{}' not found", identity_id))?;
        let exported_at_ms = now_ms();
        let pkg_bytes = canonical_package_bytes(
            &ident.identity_id,
            &ident.active_pubkey,
            ident.key_history.len(),
            exported_at_ms,
        );
        let package_sig = nexus_db::auth::ed25519_sign(active_secret_b64url, &pkg_bytes)?;
        let pkg = PortableIdentityPackage {
            identity_id: ident.identity_id,
            display_name: ident.display_name,
            genesis: ident.genesis,
            active_pubkey: ident.active_pubkey,
            key_history: ident.key_history,
            exported_at_ms,
            package_sig,
        };
        verify_identity_package(&pkg)?;
        Ok(pkg)
    }

    /// Import a cryptographically verified `PortableIdentityPackage` onto this cluster.
    /// Grants ZERO automatic organizational memberships or permissions, and NEVER overwrites
    /// an already-registered local identity.
    pub async fn import_portable_identity(
        &self,
        pkg: &PortableIdentityPackage,
    ) -> Result<Identity> {
        self.ensure_tables().await?;
        verify_identity_package(pkg)?;
        if self.get_identity(&pkg.identity_id).await?.is_some() {
            anyhow::bail!(
                "Identity '{}' already exists locally; refusing overwrite via portable import",
                pkg.identity_id
            );
        }
        let ident = Identity {
            identity_id: pkg.identity_id.clone(),
            display_name: pkg.display_name.clone(),
            primary_email: None,
            genesis: pkg.genesis.clone(),
            active_pubkey: pkg.active_pubkey.clone(),
            key_history: pkg.key_history.clone(),
            status: IdentityStatus::Active,
            created_at_ms: pkg.genesis.created_at_ms,
        };
        let val = serde_json::to_value(&ident)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_identity', $id) CONTENT $ident;")
            .bind(("id", ident.identity_id.clone()))
            .bind(("ident", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                "instance",
                &ident.identity_id,
                "identity.import",
                &ident.identity_id,
                "ok",
                "Verified NEXUS-ID-v1 portable package",
            )
            .await;
        Ok(ident)
    }

    // -------------------------------------------------------------------------
    // Hierarchical Organization Management
    // -------------------------------------------------------------------------

    pub async fn get_org(&self, org_id: &str) -> Result<Option<Organization>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_org', $id)")
            .bind(("id", org_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<Organization>(v.clone()).ok()))
    }

    pub async fn list_all_orgs(&self) -> Result<Vec<Organization>> {
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_org").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut orgs: Vec<Organization> = rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Organization>(v).ok())
            .collect();
        orgs.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(orgs)
    }

    pub async fn create_org(
        &self,
        actor: &str,
        slug: &str,
        name: &str,
        parent_org_id: Option<String>,
        primary_domain: Option<String>,
        local_policy: OrgPolicyPatch,
    ) -> Result<Organization> {
        let _guard = HIERARCHY_LOCK.lock().await;
        self.ensure_tables().await?;
        let clean_slug = slug.trim().to_ascii_lowercase();
        if clean_slug.is_empty()
            || !clean_slug
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!("Organization slug must be non-empty alphanumeric/dash/underscore");
        }
        let org_id = format!("org_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let (path, depth) = if let Some(ref pid) = parent_org_id {
            let parent = self
                .get_org(pid)
                .await?
                .ok_or_else(|| anyhow!("Parent organization '{}' not found", pid))?;
            let next_depth = parent.depth + 1;
            if next_depth > self.limits.max_depth {
                anyhow::bail!(
                    "Organization nesting exceeds configured max_depth ({})",
                    self.limits.max_depth
                );
            }
            let all = self.list_all_orgs().await?;
            let prefix = format!("{}/", parent.path);
            let subtree_count = all
                .iter()
                .filter(|o| o.org_id == parent.org_id || o.path.starts_with(&prefix))
                .count();
            if subtree_count >= self.limits.max_subtree_size {
                anyhow::bail!(
                    "Parent organization subtree exceeds max_subtree_size ({})",
                    self.limits.max_subtree_size
                );
            }
            (format!("{}/{}", parent.path, org_id), next_depth)
        } else {
            (format!("/{}", org_id), 0)
        };

        let org = Organization {
            org_id: org_id.clone(),
            slug: clean_slug,
            name: name.trim().to_string(),
            parent_org_id: parent_org_id.clone(),
            path,
            depth,
            status: OrgStatus::Active,
            primary_domain,
            local_policy,
            created_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&org)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_org', $id) CONTENT $org;")
            .bind(("id", org_id.clone()))
            .bind(("org", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                &org_id,
                actor,
                "org.create",
                &org_id,
                "ok",
                &format!("name={} parent={:?} depth={}", org.name, parent_org_id, depth),
            )
            .await;
        Ok(org)
    }

    /// Update an organization's mutable metadata or local policy patch (never alters `org_id` or `path`).
    pub async fn update_org_policy(
        &self,
        actor: &str,
        org_id: &str,
        patch: OrgPolicyPatch,
    ) -> Result<Organization> {
        let mut org = self
            .get_org(org_id)
            .await?
            .ok_or_else(|| anyhow!("Organization '{}' not found", org_id))?;
        org.local_policy = patch;
        let val = serde_json::to_value(&org)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_org', $id) CONTENT $org;")
            .bind(("id", org.org_id.clone()))
            .bind(("org", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(org_id, actor, "org.policy.update", org_id, "ok", "updated")
            .await;
        Ok(org)
    }

    /// Safely reparent an organization (and its descendants) with indexed cycle detection,
    /// serialized hierarchy locking, depth enforcement, and O(k) descendant path updates.
    pub async fn reparent_org(
        &self,
        actor: &str,
        org_id: &str,
        new_parent_org_id: Option<String>,
    ) -> Result<Organization> {
        let _guard = HIERARCHY_LOCK.lock().await;
        let mut org = self
            .get_org(org_id)
            .await?
            .ok_or_else(|| anyhow!("Organization '{}' not found", org_id))?;
        let old_path = org.path.clone();
        let old_prefix = format!("{}/", old_path);
        let (new_path, new_depth) = if let Some(ref pid) = new_parent_org_id {
            let new_parent = self
                .get_org(pid)
                .await?
                .ok_or_else(|| anyhow!("Target parent '{}' not found", pid))?;
            if new_parent.org_id == org.org_id || new_parent.path.starts_with(&old_prefix) {
                anyhow::bail!("Cycle detected: cannot reparent organization under itself or its descendant");
            }
            (format!("{}/{}", new_parent.path, org.org_id), new_parent.depth + 1)
        } else {
            (format!("/{}", org.org_id), 0)
        };

        let all = self.list_all_orgs().await?;
        let descendants: Vec<Organization> = all
            .into_iter()
            .filter(|o| o.path.starts_with(&old_prefix))
            .collect();
        let max_rel_depth = descendants
            .iter()
            .map(|d| d.depth.saturating_sub(org.depth))
            .max()
            .unwrap_or(0);
        if new_depth + max_rel_depth > self.limits.max_depth {
            anyhow::bail!(
                "Reparenting would exceed configured max_depth ({})",
                self.limits.max_depth
            );
        }

        let depth_delta = (new_depth as i64) - (org.depth as i64);
        org.parent_org_id = new_parent_org_id.clone();
        org.path = new_path.clone();
        org.depth = new_depth;
        let val = serde_json::to_value(&org)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_org', $id) CONTENT $org;")
            .bind(("id", org.org_id.clone()))
            .bind(("org", val))
            .await?
            .check()?;

        for mut desc in descendants {
            let suffix = &desc.path[old_path.len()..];
            desc.path = format!("{}{}", new_path, suffix);
            desc.depth = ((desc.depth as i64) + depth_delta).max(0) as u32;
            let dval = serde_json::to_value(&desc)?;
            self.db
                .client
                .query("UPSERT type::record('sys_iam_org', $id) CONTENT $org;")
                .bind(("id", desc.org_id.clone()))
                .bind(("org", dval))
                .await?
                .check()?;
        }
        let _ = self
            .append_audit(
                org_id,
                actor,
                "org.reparent",
                org_id,
                "ok",
                &format!("new_parent={:?} new_path={}", new_parent_org_id, new_path),
            )
            .await;
        Ok(org)
    }

    /// Resolve effective policy for `org_id` by composing ancestors from root -> target.
    pub async fn resolve_org_policy(&self, org_id: &str) -> Result<ComposedOrgPolicy> {
        let target = self
            .get_org(org_id)
            .await?
            .ok_or_else(|| anyhow!("Organization '{}' not found", org_id))?;
        let ancestor_ids: Vec<&str> = target
            .path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut chain = Vec::with_capacity(ancestor_ids.len());
        for aid in ancestor_ids {
            if let Some(o) = self.get_org(aid).await? {
                chain.push(o);
            }
        }

        let mut mfa = ResolvedPolicyField {
            value: false,
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: "instance".into(),
        };
        let mut min_pw = ResolvedPolicyField {
            value: 12u32,
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: "instance".into(),
        };
        let mut max_ttl = ResolvedPolicyField {
            value: 86_400u64,
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: "instance".into(),
        };
        let mut auth_methods = ResolvedPolicyField {
            value: vec!["password".into(), "passkey".into(), "totp".into(), "oidc".into()],
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: "instance".into(),
        };
        let mut branding = ResolvedPolicyField {
            value: target.name.clone(),
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: target.org_id.clone(),
        };
        let mut login_theme = ResolvedPolicyField {
            value: "nexus-default".into(),
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: "instance".into(),
        };
        let mut ext_idps = ResolvedPolicyField {
            value: vec!["oidc".into(), "saml".into()],
            provenance: PolicyProvenance::InheritedDefault,
            source_org_id: "instance".into(),
        };

        for node in &chain {
            let is_target = node.org_id == target.org_id;
            let p = &node.local_policy;

            // 1. MFA required: monotonic tighten-only (`true` cannot be disabled by descendants)
            if let Some(req_mfa) = p.mfa_required {
                if mfa.value && !req_mfa && is_target {
                    mfa.provenance = PolicyProvenance::ProhibitedByParent;
                } else if req_mfa && !mfa.value {
                    mfa = ResolvedPolicyField {
                        value: true,
                        provenance: if is_target {
                            PolicyProvenance::LocallyOverridden
                        } else {
                            PolicyProvenance::InheritedEnforced
                        },
                        source_org_id: node.org_id.clone(),
                    };
                }
            }

            // 2. Minimum password length: monotonic max
            if let Some(pw_len) = p.min_password_length {
                if pw_len > min_pw.value {
                    min_pw = ResolvedPolicyField {
                        value: pw_len,
                        provenance: if is_target {
                            PolicyProvenance::LocallyOverridden
                        } else {
                            PolicyProvenance::InheritedEnforced
                        },
                        source_org_id: node.org_id.clone(),
                    };
                } else if pw_len < min_pw.value && is_target {
                    min_pw.provenance = PolicyProvenance::ProhibitedByParent;
                }
            }

            // 3. Max session lifetime: monotonic min
            if let Some(ttl) = p.max_session_ttl_secs {
                if ttl < max_ttl.value {
                    max_ttl = ResolvedPolicyField {
                        value: ttl,
                        provenance: if is_target {
                            PolicyProvenance::LocallyOverridden
                        } else {
                            PolicyProvenance::InheritedEnforced
                        },
                        source_org_id: node.org_id.clone(),
                    };
                } else if ttl > max_ttl.value && is_target {
                    max_ttl.provenance = PolicyProvenance::ProhibitedByParent;
                }
            }

            // 4. Allowed auth methods: set intersection (descendants can only restrict)
            if let Some(ref methods) = p.allowed_auth_methods {
                let current: HashSet<String> = auth_methods.value.iter().cloned().collect();
                let intersected: Vec<String> = methods
                    .iter()
                    .filter(|m| current.contains(*m))
                    .cloned()
                    .collect();
                let requested_disallowed = methods.iter().any(|m| !current.contains(m));
                auth_methods = ResolvedPolicyField {
                    value: intersected,
                    provenance: if is_target {
                        if requested_disallowed {
                            PolicyProvenance::ProhibitedByParent
                        } else {
                            PolicyProvenance::LocallyOverridden
                        }
                    } else {
                        PolicyProvenance::InheritedEnforced
                    },
                    source_org_id: node.org_id.clone(),
                };
            }

            // 5. Branding & login theme: child-overrideable
            if let Some(ref b) = p.branding_name {
                branding = ResolvedPolicyField {
                    value: b.clone(),
                    provenance: if is_target {
                        PolicyProvenance::LocallyOverridden
                    } else {
                        PolicyProvenance::InheritedDefault
                    },
                    source_org_id: node.org_id.clone(),
                };
            }
            if let Some(ref lt) = p.login_theme {
                login_theme = ResolvedPolicyField {
                    value: lt.clone(),
                    provenance: if is_target {
                        PolicyProvenance::LocallyOverridden
                    } else {
                        PolicyProvenance::InheritedDefault
                    },
                    source_org_id: node.org_id.clone(),
                };
            }

            // 6. External IdPs: parent restricts, child selects within parent's allowed set
            if let Some(ref idps) = p.allowed_external_idps {
                let current: HashSet<String> = ext_idps.value.iter().cloned().collect();
                let filtered: Vec<String> = idps
                    .iter()
                    .filter(|x| current.contains(*x))
                    .cloned()
                    .collect();
                let requested_disallowed = idps.iter().any(|x| !current.contains(x));
                ext_idps = ResolvedPolicyField {
                    value: filtered,
                    provenance: if is_target {
                        if requested_disallowed {
                            PolicyProvenance::ProhibitedByParent
                        } else {
                            PolicyProvenance::LocallyOverridden
                        }
                    } else {
                        PolicyProvenance::InheritedEnforced
                    },
                    source_org_id: node.org_id.clone(),
                };
            }
        }

        Ok(ComposedOrgPolicy {
            org_id: target.org_id,
            mfa_required: mfa,
            min_password_length: min_pw,
            max_session_ttl_secs: max_ttl,
            allowed_auth_methods: auth_methods,
            branding_name: branding,
            login_theme,
            allowed_external_idps: ext_idps,
        })
    }

    // -------------------------------------------------------------------------
    // Explicit Organization Membership, Delegation & Permission Evaluation
    // -------------------------------------------------------------------------

    pub async fn grant_membership(
        &self,
        granted_by: &str,
        org_id: &str,
        subject_id: &str,
        role_assignments: Vec<String>,
        direct_permissions: Vec<String>,
        scope: DelegationScope,
        expires_at_ms: Option<u64>,
    ) -> Result<OrgMembership> {
        self.ensure_tables().await?;
        if self.get_org(org_id).await?.is_none() {
            anyhow::bail!("Organization '{}' not found", org_id);
        }
        let membership_id = format!("mem_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let mem = OrgMembership {
            membership_id: membership_id.clone(),
            subject_id: subject_id.to_string(),
            org_id: org_id.to_string(),
            role_assignments,
            direct_permissions,
            scope,
            status: MembershipStatus::Active,
            granted_by: granted_by.to_string(),
            created_at_ms: now_ms(),
            expires_at_ms,
        };
        let val = serde_json::to_value(&mem)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_org_member', $id) CONTENT $m;")
            .bind(("id", membership_id))
            .bind(("m", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                org_id,
                granted_by,
                "org.member.grant",
                subject_id,
                "ok",
                &format!("scope={:?}", mem.scope),
            )
            .await;
        Ok(mem)
    }

    /// Revoke an identity's membership in `org_id` AND invalidate its org-scoped tokens.
    /// NEVER deletes or modifies the underlying `Identity` or personal records!
    pub async fn revoke_membership(
        &self,
        actor: &str,
        org_id: &str,
        subject_id: &str,
    ) -> Result<usize> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_org_member")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut revoked_count = 0usize;
        for v in rows {
            if let Ok(mut mem) = serde_json::from_value::<OrgMembership>(v) {
                if mem.org_id == org_id && mem.subject_id == subject_id && mem.status != MembershipStatus::Revoked {
                    mem.status = MembershipStatus::Revoked;
                    let mval = serde_json::to_value(&mem)?;
                    let _ = self
                        .db
                        .client
                        .query("UPSERT type::record('sys_iam_org_member', $id) CONTENT $m;")
                        .bind(("id", mem.membership_id.clone()))
                        .bind(("m", mval))
                        .await;
                    revoked_count += 1;
                }
            }
        }
        // Revoke all active org-scoped tokens for this subject
        let mut tresp = self.db.client.query("SELECT * FROM sys_iam_token").await?;
        let trows: Vec<serde_json::Value> = tresp.take(0).unwrap_or_default();
        for v in trows {
            if let Ok(mut tok) = serde_json::from_value::<IssuedTokenRecord>(v) {
                if tok.org_id == org_id && tok.subject == subject_id && !tok.revoked {
                    tok.revoked = true;
                    let _ = self.persist_token(&tok).await;
                }
            }
        }
        let _ = self
            .append_audit(
                org_id,
                actor,
                "org.member.revoke",
                subject_id,
                "ok",
                &format!("revoked_memberships={}", revoked_count),
            )
            .await;
        Ok(revoked_count)
    }

    pub async fn list_memberships_for_org(&self, org_id: &str) -> Result<Vec<OrgMembership>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_org_member")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<OrgMembership>(v).ok())
            .filter(|m| m.org_id == org_id)
            .collect())
    }

    pub async fn list_memberships_for_subject(&self, subject_id: &str) -> Result<Vec<OrgMembership>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_org_member")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let now = now_ms();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<OrgMembership>(v).ok())
            .filter(|m| {
                m.subject_id == subject_id
                    && m.status == MembershipStatus::Active
                    && m.expires_at_ms.map(|e| e > now).unwrap_or(true)
            })
            .collect())
    }

    pub async fn create_role_bundle(
        &self,
        actor: &str,
        org_id: Option<String>,
        name: &str,
        permissions: Vec<String>,
    ) -> Result<RoleBundle> {
        self.ensure_tables().await?;
        let role_id = format!("role_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let bundle = RoleBundle {
            role_id: role_id.clone(),
            org_id: org_id.clone(),
            name: name.trim().to_string(),
            permissions,
        };
        let val = serde_json::to_value(&bundle)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_role', $id) CONTENT $r;")
            .bind(("id", role_id.clone()))
            .bind(("r", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                org_id.as_deref().unwrap_or("instance"),
                actor,
                "role.create",
                &role_id,
                "ok",
                &bundle.name,
            )
            .await;
        Ok(bundle)
    }

    async fn membership_covers_org(&self, mem: &OrgMembership, target: &Organization) -> bool {
        match &mem.scope {
            DelegationScope::SelfOnly => mem.org_id == target.org_id,
            DelegationScope::Descendants => {
                if mem.org_id == target.org_id {
                    return true;
                }
                if let Ok(Some(base)) = self.get_org(&mem.org_id).await {
                    let prefix = format!("{}/", base.path);
                    return target.path.starts_with(&prefix);
                }
                false
            }
            DelegationScope::Subtree { root_org_id } => {
                if root_org_id == &target.org_id {
                    return true;
                }
                if let Ok(Some(root)) = self.get_org(root_org_id).await {
                    let prefix = format!("{}/", root.path);
                    return target.path.starts_with(&prefix);
                }
                false
            }
            DelegationScope::Selected { org_ids } => {
                mem.org_id == target.org_id || org_ids.iter().any(|id| id == &target.org_id)
            }
        }
    }

    /// Return only the organizations the subject is authorized to discover/view.
    pub async fn list_authorized_orgs(
        &self,
        subject_id: &str,
        is_platform_admin: bool,
    ) -> Result<Vec<Organization>> {
        let all = self.list_all_orgs().await?;
        if is_platform_admin {
            return Ok(all);
        }
        let memberships = self.list_memberships_for_subject(subject_id).await?;
        let mut allowed = Vec::new();
        for org in all {
            let mut ok = false;
            for mem in &memberships {
                if self.membership_covers_org(mem, &org).await {
                    ok = true;
                    break;
                }
            }
            if ok {
                allowed.push(org);
            }
        }
        Ok(allowed)
    }

    /// Server-side scoped permission evaluation:
    /// Evaluates `(subject_id, action, target_org)` against explicit memberships, delegation scopes,
    /// built-in + custom role permission bundles, and direct permissions.
    pub async fn evaluate_permission(
        &self,
        subject_id: &str,
        is_platform_admin: bool,
        target_org_id: &str,
        action: &str,
    ) -> Result<PermissionDecision> {
        self.ensure_tables().await?;
        if is_platform_admin {
            return Ok(PermissionDecision {
                allowed: true,
                subject_id: subject_id.into(),
                org_id: target_org_id.into(),
                action: action.into(),
                reason: "Platform/Instance Administrator scope".into(),
                matched_membership_id: None,
            });
        }
        let Some(target_org) = self.get_org(target_org_id).await? else {
            return Ok(PermissionDecision {
                allowed: false,
                subject_id: subject_id.into(),
                org_id: target_org_id.into(),
                action: action.into(),
                reason: "Target organization not found".into(),
                matched_membership_id: None,
            });
        };
        if target_org.status != OrgStatus::Active {
            return Ok(PermissionDecision {
                allowed: false,
                subject_id: subject_id.into(),
                org_id: target_org_id.into(),
                action: action.into(),
                reason: "Target organization is not active".into(),
                matched_membership_id: None,
            });
        }

        let custom_roles: Vec<RoleBundle> = {
            let mut r = self.db.client.query("SELECT * FROM sys_iam_role").await?;
            r.take::<Vec<serde_json::Value>>(0)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| serde_json::from_value::<RoleBundle>(v).ok())
                .collect()
        };

        let memberships = self.list_memberships_for_subject(subject_id).await?;
        for mem in memberships {
            if !self.membership_covers_org(&mem, &target_org).await {
                continue;
            }
            if mem.direct_permissions.iter().any(|p| p == action || p == "*") {
                return Ok(PermissionDecision {
                    allowed: true,
                    subject_id: subject_id.into(),
                    org_id: target_org_id.into(),
                    action: action.into(),
                    reason: format!("Direct permission grant via {:?}", mem.scope),
                    matched_membership_id: Some(mem.membership_id),
                });
            }
            for role_name in &mem.role_assignments {
                if builtin_role_permissions(role_name)
                    .iter()
                    .any(|p| *p == action)
                {
                    return Ok(PermissionDecision {
                        allowed: true,
                        subject_id: subject_id.into(),
                        org_id: target_org_id.into(),
                        action: action.into(),
                        reason: format!("Role '{}' via {:?}", role_name, mem.scope),
                        matched_membership_id: Some(mem.membership_id),
                    });
                }
                if custom_roles.iter().any(|cr| {
                    cr.name.eq_ignore_ascii_case(role_name)
                        && (cr.org_id.is_none() || cr.org_id.as_deref() == Some(&mem.org_id))
                        && cr.permissions.iter().any(|p| p == action || p == "*")
                }) {
                    return Ok(PermissionDecision {
                        allowed: true,
                        subject_id: subject_id.into(),
                        org_id: target_org_id.into(),
                        action: action.into(),
                        reason: format!("Custom role '{}' via {:?}", role_name, mem.scope),
                        matched_membership_id: Some(mem.membership_id),
                    });
                }
            }
        }

        Ok(PermissionDecision {
            allowed: false,
            subject_id: subject_id.into(),
            org_id: target_org_id.into(),
            action: action.into(),
            reason: "No matching explicit membership or delegation scope grants this action".into(),
            matched_membership_id: None,
        })
    }

    // -------------------------------------------------------------------------
    // OIDC / OAuth 2.1 Clients (Argon2id Secrets, Mandatory PKCE S256, EdDSA JWT)
    // -------------------------------------------------------------------------

    pub async fn create_oidc_client(
        &self,
        actor: &str,
        org_id: &str,
        name: &str,
        client_type: OidcClientType,
        redirect_uris: Vec<String>,
        grant_types: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<(OidcClient, Option<String>)> {
        self.ensure_tables().await?;
        let client_id = format!("nxc_{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
        let (plain_secret, secret_hash) = match client_type {
            OidcClientType::Confidential => {
                let sec = random_token("nxs");
                let h = nexus_db::auth::hash_password(&sec);
                (Some(sec), Some(h))
            }
            OidcClientType::Public => (None, None),
        };
        let grants = if grant_types.is_empty() {
            vec!["authorization_code".into(), "refresh_token".into()]
        } else {
            grant_types
        };
        let sc = if scopes.is_empty() {
            vec!["openid".into(), "profile".into(), "email".into()]
        } else {
            scopes
        };
        let client = OidcClient {
            client_id: client_id.clone(),
            org_id: org_id.to_string(),
            name: name.trim().to_string(),
            client_type,
            client_secret_hash: secret_hash,
            redirect_uris,
            grant_types: grants,
            scopes: sc,
            pkce_required: true,
            created_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&client)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_oidc_client', $id) CONTENT $c;")
            .bind(("id", client_id.clone()))
            .bind(("c", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(
                org_id,
                actor,
                "oidc_client.create",
                &client_id,
                "ok",
                &client.name,
            )
            .await;
        Ok((client, plain_secret))
    }

    pub async fn get_oidc_client(&self, client_id: &str) -> Result<Option<OidcClient>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_oidc_client', $id)")
            .bind(("id", client_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<OidcClient>(v.clone()).ok()))
    }

    pub async fn list_oidc_clients(&self, org_id: Option<&str>) -> Result<Vec<OidcClient>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_oidc_client")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<OidcClient>(v).ok())
            .filter(|c| org_id.map(|o| c.org_id == o).unwrap_or(true))
            .collect())
    }

    pub async fn issue_authorization_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        nonce: Option<String>,
        subject: &str,
        roles: Vec<String>,
    ) -> Result<String> {
        self.ensure_tables().await?;
        let client = self
            .get_oidc_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Unknown OIDC client_id '{}'", client_id))?;
        if redirect_uri.contains('#') || !client.redirect_uris.iter().any(|u| u == redirect_uri) {
            anyhow::bail!("redirect_uri '{}' is invalid or not registered for client '{}'", redirect_uri, client_id);
        }
        if code_challenge.trim().is_empty() || code_challenge_method != "S256" {
            anyhow::bail!("OAuth 2.1 requires PKCE with code_challenge_method=S256");
        }
        // Validate every requested scope is permitted for this client
        for s in scope.split_whitespace() {
            if !client.scopes.iter().any(|allowed| allowed == s) {
                anyhow::bail!("Requested scope '{}' is not allowed for client '{}'", s, client_id);
            }
        }
        let plain_code = random_token("nxac");
        let chash = hash_lookup_key(&plain_code);
        let rec = AuthCodeRecord {
            code_hash: chash.clone(),
            client_id: client.client_id.clone(),
            org_id: client.org_id.clone(),
            subject: subject.to_string(),
            roles,
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            code_challenge: code_challenge.to_string(),
            code_challenge_method: "S256".into(),
            nonce,
            used: false,
            expires_at_ms: now_ms() + 5 * 60 * 1000,
        };
        let val = serde_json::to_value(&rec)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_auth_code', $id) CONTENT $r;")
            .bind(("id", chash))
            .bind(("r", val))
            .await?
            .check()?;
        let _ = self
            .append_audit(&client.org_id, subject, "oauth.authorize", client_id, "ok", scope)
            .await;
        Ok(plain_code)
    }

    async fn persist_token(&self, rec: &IssuedTokenRecord) -> Result<()> {
        let val = serde_json::to_value(rec)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_token', $id) CONTENT $t;")
            .bind(("id", rec.token_hash.clone()))
            .bind(("t", val))
            .await?
            .check()?;
        Ok(())
    }

    async fn revoke_token_family(&self, family_id: &str) -> Result<usize> {
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_token").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut count = 0usize;
        for v in rows {
            if let Ok(mut tok) = serde_json::from_value::<IssuedTokenRecord>(v) {
                if tok.family_id == family_id && !tok.revoked {
                    tok.revoked = true;
                    let _ = self.persist_token(&tok).await;
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_token(
        &self,
        grant_type: &str,
        client_id: &str,
        client_secret: Option<&str>,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
        refresh_token: Option<&str>,
        scope: Option<&str>,
    ) -> Result<TokenResponse> {
        self.ensure_tables().await?;
        let client = self
            .get_oidc_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Unknown client_id '{}'", client_id))?;

        if !client.grant_types.iter().any(|g| g == grant_type) {
            anyhow::bail!("grant_type '{}' is not enabled for client '{}'", grant_type, client_id);
        }

        if client.client_type == OidcClientType::Confidential {
            let expected_hash = client
                .client_secret_hash
                .as_deref()
                .ok_or_else(|| anyhow!("Confidential client missing secret hash"))?;
            let provided = client_secret
                .ok_or_else(|| anyhow!("Confidential client requires client_secret"))?;
            if !nexus_db::auth::verify_password(expected_hash, provided) {
                let _ = self
                    .append_audit(&client.org_id, client_id, "oauth.token", client_id, "denied", "invalid client_secret")
                    .await;
                anyhow::bail!("Invalid client_secret");
            }
        }

        match grant_type {
            "authorization_code" => {
                let plain_code = code.ok_or_else(|| anyhow!("Missing authorization code"))?;
                let redir = redirect_uri.ok_or_else(|| anyhow!("Missing redirect_uri"))?;
                let verifier = code_verifier.ok_or_else(|| anyhow!("OAuth 2.1 requires PKCE code_verifier"))?;
                let chash = hash_lookup_key(plain_code);
                let mut resp = self
                    .db
                    .client
                    .query("SELECT * FROM type::record('sys_iam_auth_code', $id)")
                    .bind(("id", chash.clone()))
                    .await?;
                let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
                let mut rec: AuthCodeRecord = rows
                    .first()
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .ok_or_else(|| anyhow!("Invalid or unknown authorization code"))?;

                if rec.used || now_ms() > rec.expires_at_ms {
                    anyhow::bail!("Authorization code expired or already used");
                }
                if rec.client_id != client_id || rec.redirect_uri != redir {
                    anyhow::bail!("Authorization code client_id or redirect_uri mismatch");
                }

                // RFC 7636 PKCE verifier syntax (43..=128 unreserved ASCII chars) + S256 check
                if verifier.len() < 43
                    || verifier.len() > 128
                    || !verifier
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
                {
                    anyhow::bail!("PKCE code_verifier violates RFC 7636 length/character requirements");
                }
                let digest = sha256(verifier.as_bytes());
                let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
                if !constant_time_eq(computed.as_bytes(), rec.code_challenge.as_bytes()) {
                    let _ = self
                        .append_audit(&rec.org_id, &rec.subject, "oauth.token", client_id, "denied", "PKCE S256 mismatch")
                        .await;
                    anyhow::bail!("PKCE S256 verification failed");
                }

                rec.used = true;
                let rec_val = serde_json::to_value(&rec)?;
                self.db
                    .client
                    .query("UPSERT type::record('sys_iam_auth_code', $id) CONTENT $r;")
                    .bind(("id", chash))
                    .bind(("r", rec_val))
                    .await?
                    .check()?;

                let family_id = uuid::Uuid::new_v4().simple().to_string();
                let access = random_token("nxat");
                let refresh = random_token("nxrt");
                let now = now_ms();
                self.persist_token(&IssuedTokenRecord {
                    token_hash: hash_lookup_key(&access),
                    family_id: family_id.clone(),
                    token_type: "access".into(),
                    client_id: client.client_id.clone(),
                    org_id: rec.org_id.clone(),
                    subject: rec.subject.clone(),
                    roles: rec.roles.clone(),
                    scope: rec.scope.clone(),
                    rotated: false,
                    revoked: false,
                    expires_at_ms: now + 3_600_000,
                    issued_at_ms: now,
                })
                .await?;
                self.persist_token(&IssuedTokenRecord {
                    token_hash: hash_lookup_key(&refresh),
                    family_id,
                    token_type: "refresh".into(),
                    client_id: client.client_id.clone(),
                    org_id: rec.org_id.clone(),
                    subject: rec.subject.clone(),
                    roles: rec.roles.clone(),
                    scope: rec.scope.clone(),
                    rotated: false,
                    revoked: false,
                    expires_at_ms: now + 30 * 86_400_000,
                    issued_at_ms: now,
                })
                .await?;

                // Sign real RFC 8037 EdDSA (`Ed25519`) OIDC `id_token`
                let sk = self.ensure_active_signing_key().await?;
                let iat = now_secs();
                let id_claims = serde_json::json!({
                    "iss": "nexus-idp",
                    "sub": rec.subject,
                    "aud": client.client_id,
                    "org_id": rec.org_id,
                    "roles": rec.roles,
                    "nonce": rec.nonce,
                    "iat": iat,
                    "nbf": iat,
                    "exp": iat + 3600,
                });
                let id_token =
                    nexus_db::auth::sign_eddsa_jwt(&sk.kid, &sk.secret_b64url, &id_claims)?;

                let _ = self
                    .append_audit(&rec.org_id, &rec.subject, "oauth.token.issued", client_id, "ok", &rec.scope)
                    .await;

                Ok(TokenResponse {
                    access_token: access,
                    token_type: "Bearer".into(),
                    expires_in: 3600,
                    scope: rec.scope,
                    refresh_token: Some(refresh),
                    id_token: Some(id_token),
                    org_id: rec.org_id,
                    subject: rec.subject,
                })
            }
            "refresh_token" => {
                let _refresh_guard = REFRESH_LOCK.lock().await;
                let raw_rt = refresh_token.ok_or_else(|| anyhow!("Missing refresh_token"))?;
                let rhash = hash_lookup_key(raw_rt);
                let mut resp = self
                    .db
                    .client
                    .query("SELECT * FROM type::record('sys_iam_token', $id)")
                    .bind(("id", rhash))
                    .await?;
                let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
                let mut rec: IssuedTokenRecord = rows
                    .first()
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .ok_or_else(|| anyhow!("Invalid refresh_token"))?;

                if rec.token_type != "refresh" || rec.client_id != client_id {
                    anyhow::bail!("Refresh token does not match client");
                }

                // Replay detection: reusing a rotated refresh token revokes the entire token family!
                if rec.rotated || rec.revoked {
                    let revoked_n = self.revoke_token_family(&rec.family_id).await.unwrap_or(0);
                    let _ = self
                        .append_audit(
                            &rec.org_id,
                            &rec.subject,
                            "oauth.refresh.replay_detected",
                            &rec.family_id,
                            "revoked_family",
                            &format!("revoked {} tokens in family", revoked_n),
                        )
                        .await;
                    anyhow::bail!("Refresh token replay detected; entire token family revoked");
                }
                if now_ms() > rec.expires_at_ms {
                    anyhow::bail!("Refresh token expired");
                }

                rec.rotated = true;
                self.persist_token(&rec).await?;

                let new_access = random_token("nxat");
                let new_refresh = random_token("nxrt");
                let now = now_ms();
                self.persist_token(&IssuedTokenRecord {
                    token_hash: hash_lookup_key(&new_access),
                    family_id: rec.family_id.clone(),
                    token_type: "access".into(),
                    client_id: rec.client_id.clone(),
                    org_id: rec.org_id.clone(),
                    subject: rec.subject.clone(),
                    roles: rec.roles.clone(),
                    scope: rec.scope.clone(),
                    rotated: false,
                    revoked: false,
                    expires_at_ms: now + 3_600_000,
                    issued_at_ms: now,
                })
                .await?;
                self.persist_token(&IssuedTokenRecord {
                    token_hash: hash_lookup_key(&new_refresh),
                    family_id: rec.family_id.clone(),
                    token_type: "refresh".into(),
                    client_id: rec.client_id.clone(),
                    org_id: rec.org_id.clone(),
                    subject: rec.subject.clone(),
                    roles: rec.roles.clone(),
                    scope: rec.scope.clone(),
                    rotated: false,
                    revoked: false,
                    expires_at_ms: now + 30 * 86_400_000,
                    issued_at_ms: now,
                })
                .await?;

                Ok(TokenResponse {
                    access_token: new_access,
                    token_type: "Bearer".into(),
                    expires_in: 3600,
                    scope: rec.scope,
                    refresh_token: Some(new_refresh),
                    id_token: None,
                    org_id: rec.org_id,
                    subject: rec.subject,
                })
            }
            "client_credentials" => {
                if client.client_type != OidcClientType::Confidential {
                    anyhow::bail!("client_credentials grant requires a confidential client");
                }
                let granted_scope = scope.unwrap_or("api").to_string();
                let access = random_token("nxat");
                let now = now_ms();
                let subject = format!("sa:{}", client.client_id);
                self.persist_token(&IssuedTokenRecord {
                    token_hash: hash_lookup_key(&access),
                    family_id: uuid::Uuid::new_v4().simple().to_string(),
                    token_type: "access".into(),
                    client_id: client.client_id.clone(),
                    org_id: client.org_id.clone(),
                    subject: subject.clone(),
                    roles: vec!["SERVICE".into()],
                    scope: granted_scope.clone(),
                    rotated: false,
                    revoked: false,
                    expires_at_ms: now + 3_600_000,
                    issued_at_ms: now,
                })
                .await?;
                let _ = self
                    .append_audit(&client.org_id, &subject, "oauth.token.client_credentials", client_id, "ok", &granted_scope)
                    .await;
                Ok(TokenResponse {
                    access_token: access,
                    token_type: "Bearer".into(),
                    expires_in: 3600,
                    scope: granted_scope,
                    refresh_token: None,
                    id_token: None,
                    org_id: client.org_id,
                    subject,
                })
            }
            other => anyhow::bail!("Unsupported grant_type '{}'", other),
        }
    }

    pub async fn introspect_token(&self, raw_token: &str) -> Result<Option<IssuedTokenRecord>> {
        self.ensure_tables().await?;
        let thash = hash_lookup_key(raw_token);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_token', $id)")
            .bind(("id", thash))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let Some(rec) = rows
            .first()
            .and_then(|v| serde_json::from_value::<IssuedTokenRecord>(v.clone()).ok())
        else {
            return Ok(None);
        };
        if rec.revoked || rec.rotated || now_ms() > rec.expires_at_ms {
            return Ok(None);
        }
        Ok(Some(rec))
    }

    pub async fn revoke_token(&self, raw_token: &str) -> Result<bool> {
        self.ensure_tables().await?;
        let thash = hash_lookup_key(raw_token);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_token', $id)")
            .bind(("id", thash))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        if let Some(mut rec) = rows
            .first()
            .and_then(|v| serde_json::from_value::<IssuedTokenRecord>(v.clone()).ok())
        {
            rec.revoked = true;
            self.persist_token(&rec).await?;
            return Ok(true);
        }
        Ok(false)
    }

    // -------------------------------------------------------------------------
    // RFC 6238 TOTP MFA (Pure-Rust HMAC-SHA1 + Argon2id Recovery Codes)
    // -------------------------------------------------------------------------

    pub async fn enroll_totp(&self, org_id: &str, subject: &str) -> Result<(String, String, Vec<String>)> {
        self.ensure_tables().await?;
        let mut raw_secret = [0u8; 20];
        let u1 = uuid::Uuid::new_v4();
        let u2 = uuid::Uuid::new_v4();
        raw_secret[..16].copy_from_slice(u1.as_bytes());
        raw_secret[16..].copy_from_slice(&u2.as_bytes()[..4]);
        let secret_b32 = base32_encode(&raw_secret);

        let recovery_codes: Vec<String> = (0..6)
            .map(|_| {
                let hex = uuid::Uuid::new_v4().simple().to_string();
                format!("{}-{}", &hex[0..4].to_ascii_uppercase(), &hex[4..8].to_ascii_uppercase())
            })
            .collect();
        let recovery_hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| hash_lookup_key(c))
            .collect();

        let rec = TotpEnrollment {
            subject: subject.to_string(),
            org_id: org_id.to_string(),
            secret_base32: secret_b32.clone(),
            verified: false,
            recovery_code_hashes: recovery_hashes,
            enrolled_at_ms: now_ms(),
        };
        let key = format!("{}_{}", org_id, subject);
        let val = serde_json::to_value(&rec)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_totp', $id) CONTENT $t;")
            .bind(("id", key))
            .bind(("t", val))
            .await?
            .check()?;
        let otpauth_uri = format!(
            "otpauth://totp/Nexus-IDP:{}?secret={}&issuer=Nexus-IDP&digits=6&period=30",
            subject, secret_b32
        );
        let _ = self
            .append_audit(org_id, subject, "mfa.totp.enroll", subject, "ok", "enrolled")
            .await;
        Ok((secret_b32, otpauth_uri, recovery_codes))
    }

    pub async fn verify_totp(&self, org_id: &str, subject: &str, code: &str) -> Result<bool> {
        self.ensure_tables().await?;
        let key = format!("{}_{}", org_id, subject);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_totp', $id)")
            .bind(("id", key.clone()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let Some(mut rec) = rows
            .first()
            .and_then(|v| serde_json::from_value::<TotpEnrollment>(v.clone()).ok())
        else {
            return Ok(false);
        };
        let trimmed = code.trim();

        // Check single-use recovery codes first
        let rhash = hash_lookup_key(trimmed);
        if let Some(pos) = rec.recovery_code_hashes.iter().position(|h| constant_time_eq(h.as_bytes(), rhash.as_bytes())) {
            rec.recovery_code_hashes.remove(pos);
            rec.verified = true;
            let val = serde_json::to_value(&rec)?;
            let _ = self
                .db
                .client
                .query("UPSERT type::record('sys_iam_totp', $id) CONTENT $t;")
                .bind(("id", key))
                .bind(("t", val))
                .await;
            let _ = self
                .append_audit(org_id, subject, "mfa.recovery.used", subject, "ok", "recovery code consumed")
                .await;
            return Ok(true);
        }

        let secret = base32_decode(&rec.secret_base32)?;
        let step = now_secs() / 30;
        let matched = [step.saturating_sub(1), step, step + 1]
            .iter()
            .any(|&s| constant_time_eq(totp_code_for_step(&secret, s).as_bytes(), trimmed.as_bytes()));

        if matched && !rec.verified {
            rec.verified = true;
            let val = serde_json::to_value(&rec)?;
            let _ = self
                .db
                .client
                .query("UPSERT type::record('sys_iam_totp', $id) CONTENT $t;")
                .bind(("id", key))
                .bind(("t", val))
                .await;
        }
        let _ = self
            .append_audit(
                org_id,
                subject,
                "mfa.totp.verify",
                subject,
                if matched { "ok" } else { "denied" },
                if matched { "valid" } else { "invalid" },
            )
            .await;
        Ok(matched)
    }
}

// =============================================================================
// Pure-Rust RFC 6238 TOTP (HMAC-SHA1 + Base32) & FIPS 180-4 SHA-256 (PKCE S256)
// =============================================================================

pub fn totp_code_for_step(secret: &[u8], step: u64) -> String {
    let msg = step.to_be_bytes();
    let mac = hmac_sha1(secret, &msg);
    let offset = (mac[19] & 0x0f) as usize;
    let binary = (((mac[offset] & 0x7f) as u32) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    format!("{:06}", binary % 1_000_000)
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let kh = sha1(key);
        k[..20].copy_from_slice(&kh);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut i_pad = [0x36u8; 64];
    let mut o_pad = [0x5cu8; 64];
    for i in 0..64 {
        i_pad[i] ^= k[i];
        o_pad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&i_pad);
    inner.extend_from_slice(msg);
    let ih = sha1(&inner);
    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&o_pad);
    outer.extend_from_slice(&ih);
    sha1(&outer)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let ml = (data.len() as u64) * 8;
    let mut buf = data.to_vec();
    buf.push(0x80);
    while (buf.len() % 64) != 56 {
        buf.push(0);
    }
    buf.extend_from_slice(&ml.to_be_bytes());
    for chunk in buf.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for ch in s.bytes() {
        if ch == b'=' || ch.is_ascii_whitespace() {
            continue;
        }
        let val = match ch.to_ascii_uppercase() {
            b'A'..=b'Z' => (ch.to_ascii_uppercase() - b'A') as u32,
            b'2'..=b'7' => (ch - b'2' + 26) as u32,
            _ => anyhow::bail!("Invalid Base32 character"),
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(temp1);
            d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn identity_first_hierarchy_non_implicit_delegation_policy_composition_and_oidc_eddsa() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db);

        // 1. Self-certifying portable NEXUS-ID-v1 identity + key rotation + cross-cluster verify
        let (alice, sk0) = idp
            .create_identity("Alice", Some("alice@personal.nexus".into()))
            .await
            .unwrap();
        assert!(alice.identity_id.starts_with("nxid_"));
        let (alice_rot, sk1) = idp.rotate_identity_key(&alice.identity_id, &sk0).await.unwrap();
        assert_eq!(alice_rot.key_history.len(), 1);
        let pkg = idp
            .export_identity_package(&alice.identity_id, &sk1)
            .await
            .unwrap();
        verify_identity_package(&pkg).expect("Portable identity package MUST verify standalone");

        // Import onto a completely separate Nexus-IO cluster
        let db2 = Arc::new(Database::open_mem());
        let idp2 = NexusIdp::new(db2);
        let imported = idp2.import_portable_identity(&pkg).await.unwrap();
        assert_eq!(imported.identity_id, alice.identity_id);

        // 2. Arbitrary-depth org hierarchy with immutable-ID materialized paths
        let acme = idp
            .create_org(
                "root",
                "acme",
                "Acme Holdings",
                None,
                Some("acme.example".into()),
                OrgPolicyPatch {
                    mfa_required: Some(true),
                    min_password_length: Some(14),
                    max_session_ttl_secs: Some(7200),
                    allowed_auth_methods: Some(vec!["passkey".into(), "totp".into()]),
                    branding_name: Some("Acme Global".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let emea = idp
            .create_org(
                "root",
                "acme-emea",
                "Acme Europe",
                Some(acme.org_id.clone()),
                None,
                OrgPolicyPatch {
                    mfa_required: Some(false),        // Attempt to weaken parent MFA -> ProhibitedByParent!
                    min_password_length: Some(16),    // Tighter -> LocallyOverridden
                    branding_name: Some("Acme EU".into()), // Overrideable -> LocallyOverridden
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let de = idp
            .create_org("root", "acme-de", "Acme Germany", Some(emea.org_id.clone()), None, OrgPolicyPatch::default())
            .await
            .unwrap();
        assert_eq!(de.depth, 2);
        assert_eq!(de.path, format!("/{}/{}/{}", acme.org_id, emea.org_id, de.org_id));

        // Cycle detection on reparent
        assert!(idp.reparent_org("root", &acme.org_id, Some(de.org_id.clone())).await.is_err());

        // 3. Policy-specific composition with provenance
        let emea_pol = idp.resolve_org_policy(&emea.org_id).await.unwrap();
        assert!(emea_pol.mfa_required.value, "Parent mandatory MFA cannot be weakened");
        assert_eq!(emea_pol.mfa_required.provenance, PolicyProvenance::ProhibitedByParent);
        assert_eq!(emea_pol.min_password_length.value, 16);
        assert_eq!(emea_pol.min_password_length.provenance, PolicyProvenance::LocallyOverridden);
        assert_eq!(emea_pol.max_session_ttl_secs.value, 7200);
        assert_eq!(emea_pol.max_session_ttl_secs.provenance, PolicyProvenance::InheritedEnforced);
        assert_eq!(emea_pol.branding_name.value, "Acme EU");
        assert_eq!(emea_pol.branding_name.provenance, PolicyProvenance::LocallyOverridden);

        // 4. Hierarchy != Authorization: Alice as ORG_ADMIN on Acme with SelfOnly is DENIED on EMEA!
        idp.grant_membership(
            "root",
            &acme.org_id,
            &alice.identity_id,
            vec!["ORG_ADMIN".into()],
            vec![],
            DelegationScope::SelfOnly,
            None,
        )
        .await
        .unwrap();
        assert!(idp.evaluate_permission(&alice.identity_id, false, &acme.org_id, "iam.users.manage").await.unwrap().allowed);
        assert!(!idp.evaluate_permission(&alice.identity_id, false, &emea.org_id, "iam.users.manage").await.unwrap().allowed);

        // Explicit Descendants delegation grants EMEA & Germany
        idp.grant_membership(
            "root",
            &emea.org_id,
            &alice.identity_id,
            vec!["USER_MANAGER".into()],
            vec![],
            DelegationScope::Descendants,
            None,
        )
        .await
        .unwrap();
        assert!(idp.evaluate_permission(&alice.identity_id, false, &de.org_id, "iam.users.manage").await.unwrap().allowed);
        assert!(!idp.evaluate_permission(&alice.identity_id, false, &de.org_id, "iam.clients.manage").await.unwrap().allowed);

        // 5. OIDC PKCE S256 + Argon2id client secret + EdDSA JWT + Refresh Replay + Membership Revocation preserves Identity!
        let (client, secret) = idp
            .create_oidc_client(
                "root",
                &acme.org_id,
                "Acme Portal",
                OidcClientType::Confidential,
                vec!["https://acme.example/cb".into()],
                vec!["authorization_code".into(), "refresh_token".into(), "client_credentials".into()],
                vec!["openid".into(), "profile".into()],
            )
            .await
            .unwrap();
        let secret = secret.unwrap();
        assert!(client.client_secret_hash.as_deref().unwrap().starts_with("$argon2"));

        let verifier = "super-secret-pkce-code-verifier-of-sufficient-length-1234567890";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
        let code = idp
            .issue_authorization_code(
                &client.client_id,
                "https://acme.example/cb",
                "openid profile",
                &challenge,
                "S256",
                Some("nonce-1".into()),
                &alice.identity_id,
                vec!["ORG_ADMIN".into()],
            )
            .await
            .unwrap();
        let tok1 = idp
            .exchange_token(
                "authorization_code",
                &client.client_id,
                Some(&secret),
                Some(&code),
                Some("https://acme.example/cb"),
                Some(verifier),
                None,
                None,
            )
            .await
            .unwrap();

        // Verify EdDSA id_token against /.well-known/jwks.json public key!
        let jwks = idp.jwks().await.unwrap();
        let pk_x = jwks["keys"][0]["x"].as_str().unwrap();
        let claims = nexus_db::auth::verify_eddsa_jwt_json(tok1.id_token.as_deref().unwrap(), pk_x).unwrap();
        assert_eq!(claims["sub"], alice.identity_id);
        assert_eq!(claims["org_id"], acme.org_id);

        // Revoking Acme membership revokes Acme access token while preserving Alice's Identity!
        idp.revoke_membership("root", &acme.org_id, &alice.identity_id).await.unwrap();
        assert!(idp.introspect_token(&tok1.access_token).await.unwrap().is_none());
        assert!(idp.get_identity(&alice.identity_id).await.unwrap().is_some(), "Identity MUST survive org removal!");
    }

    #[tokio::test]
    async fn security_genesis_canonical_framing_and_tamper_boundaries() {
        // Length-prefixed framing prevents boundary concatenation ambiguity:
        // ("ab", "cd") != ("abc", "d")
        assert_ne!(
            canonical_genesis_bytes(1000, "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"),
            canonical_genesis_bytes(1000, "aaaaaaaaaaaaaaaab", "bbbbbbbbbbbbbbb")
        );
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db);
        let (ident, sk0) = idp.create_identity("Bob", None).await.unwrap();
        let mut pkg = idp.export_identity_package(&ident.identity_id, &sk0).await.unwrap();
        assert!(verify_identity_package(&pkg).is_ok());

        // Tamper timestamp -> MUST fail
        pkg.genesis.created_at_ms += 1;
        assert!(verify_identity_package(&pkg).is_err());
        pkg.genesis.created_at_ms -= 1;

        // Invalid short nonce -> MUST fail
        pkg.genesis.nonce = "short".into();
        assert!(verify_identity_package(&pkg).is_err());
    }

    #[tokio::test]
    async fn security_key_rotation_rejects_reordered_gapped_duplicate_replayed_and_compromised_keys() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db);
        let (ident, sk0) = idp.create_identity("Carol", None).await.unwrap();
        let (_, sk1) = idp.rotate_identity_key(&ident.identity_id, &sk0).await.unwrap();
        // Compromised/old sk0 MUST NOT be able to rotate again!
        assert!(idp.rotate_identity_key(&ident.identity_id, &sk0).await.is_err());
        let (_, sk2) = idp.rotate_identity_key(&ident.identity_id, &sk1).await.unwrap();
        let base_pkg = idp.export_identity_package(&ident.identity_id, &sk2).await.unwrap();
        assert!(verify_identity_package(&base_pkg).is_ok());

        // 1. Reordered transitions -> MUST fail
        let mut reordered = base_pkg.clone();
        reordered.key_history.swap(0, 1);
        assert!(verify_identity_package(&reordered).is_err());

        // 2. Gapped seq -> MUST fail
        let mut gapped = base_pkg.clone();
        gapped.key_history[1].seq = 3;
        assert!(verify_identity_package(&gapped).is_err());

        // 3. Missing intermediate transition -> MUST fail
        let mut missing = base_pkg.clone();
        missing.key_history.remove(0);
        assert!(verify_identity_package(&missing).is_err());

        // 4. Duplicate/compromised key reuse -> MUST fail
        let mut reused = base_pkg.clone();
        reused.key_history[1].new_pubkey = reused.genesis.root_pubkey.clone();
        assert!(verify_identity_package(&reused).is_err());
    }

    #[tokio::test]
    async fn security_portable_package_freshness_and_anti_overwrite() {
        let db1 = Arc::new(Database::open_mem());
        let idp1 = NexusIdp::new(db1);
        let (ident, sk0) = idp1.create_identity("Dave", None).await.unwrap();
        let pkg = idp1.export_identity_package(&ident.identity_id, &sk0).await.unwrap();

        // Expired package (max_age = 0 with simulated past timestamp) -> MUST fail
        let mut stale = pkg.clone();
        stale.exported_at_ms = stale.exported_at_ms.saturating_sub(120_000);
        assert!(verify_identity_package_with_policy(&stale, 60, 60).is_err());

        // Future-dated package -> MUST fail
        let mut future_pkg = pkg.clone();
        future_pkg.exported_at_ms = now_ms() + 600_000;
        assert!(verify_identity_package_with_policy(&future_pkg, 86_400, 60).is_err());

        // Import onto Cluster 2 succeeds ONCE, second import MUST refuse overwrite!
        let db2 = Arc::new(Database::open_mem());
        let idp2 = NexusIdp::new(db2);
        assert!(idp2.import_portable_identity(&pkg).await.is_ok());
        assert!(
            idp2.import_portable_identity(&pkg).await.is_err(),
            "Portable import MUST NEVER overwrite an existing local identity"
        );
    }

    #[tokio::test]
    async fn security_full_jwt_validator_enforces_alg_typ_kid_iss_aud_exp_nbf_and_sig() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db);
        idp.ensure_tables().await.unwrap();
        let sk = idp.ensure_active_signing_key().await.unwrap();
        let jwks = idp.jwks().await.unwrap();
        let now = now_secs();

        let good_claims = serde_json::json!({
            "iss": "nexus-idp",
            "sub": "nxid_test",
            "aud": "client_1",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        });
        let good_tok = nexus_db::auth::sign_eddsa_jwt(&sk.kid, &sk.secret_b64url, &good_claims).unwrap();
        let pol = JwtValidationPolicy::new("nexus-idp", "client_1");
        assert!(validate_eddsa_jwt(&good_tok, &jwks, &pol).is_ok());

        // Wrong issuer -> MUST fail
        assert!(validate_eddsa_jwt(&good_tok, &jwks, &JwtValidationPolicy::new("evil-idp", "client_1")).is_err());
        // Wrong audience -> MUST fail
        assert!(validate_eddsa_jwt(&good_tok, &jwks, &JwtValidationPolicy::new("nexus-idp", "other_client")).is_err());

        // Expired token -> MUST fail
        let exp_claims = serde_json::json!({
            "iss": "nexus-idp", "sub": "nxid_test", "aud": "client_1",
            "iat": now - 600, "exp": now - 120,
        });
        let exp_tok = nexus_db::auth::sign_eddsa_jwt(&sk.kid, &sk.secret_b64url, &exp_claims).unwrap();
        assert!(validate_eddsa_jwt(&exp_tok, &jwks, &pol).is_err());

        // Future nbf -> MUST fail
        let nbf_claims = serde_json::json!({
            "iss": "nexus-idp", "sub": "nxid_test", "aud": "client_1",
            "iat": now, "nbf": now + 300, "exp": now + 600,
        });
        let nbf_tok = nexus_db::auth::sign_eddsa_jwt(&sk.kid, &sk.secret_b64url, &nbf_claims).unwrap();
        assert!(validate_eddsa_jwt(&nbf_tok, &jwks, &pol).is_err());

        // Unknown kid -> MUST fail
        let bad_kid_tok = nexus_db::auth::sign_eddsa_jwt("unknown_kid", &sk.secret_b64url, &good_claims).unwrap();
        assert!(validate_eddsa_jwt(&bad_kid_tok, &jwks, &pol).is_err());

        // alg:none downgrade -> MUST fail
        let none_hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT","kid":"x"}"#);
        let parts: Vec<&str> = good_tok.split('.').collect();
        let downgraded = format!("{}.{}.{}", none_hdr, parts[1], parts[2]);
        assert!(validate_eddsa_jwt(&downgraded, &jwks, &pol).is_err());
    }

    #[tokio::test]
    async fn security_oauth21_redirect_pkce_scope_and_client_auth_guards() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db);
        let (pub_cli, _) = idp
            .create_oidc_client(
                "root",
                "default",
                "Public SPA",
                OidcClientType::Public,
                vec!["https://app.example/cb".into()],
                vec!["authorization_code".into(), "refresh_token".into()],
                vec!["openid".into(), "profile".into()],
            )
            .await
            .unwrap();

        let verifier = "valid-rfc7636-pkce-code-verifier-string-0123456789abcd";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));

        // Fragment in redirect_uri -> MUST fail
        assert!(idp
            .issue_authorization_code(&pub_cli.client_id, "https://app.example/cb#frag", "openid", &challenge, "S256", None, "u1", vec![])
            .await
            .is_err());
        // Unregistered prefix redirect_uri -> MUST fail
        assert!(idp
            .issue_authorization_code(&pub_cli.client_id, "https://app.example/cb/evil", "openid", &challenge, "S256", None, "u1", vec![])
            .await
            .is_err());
        // PKCE plain method -> MUST fail
        assert!(idp
            .issue_authorization_code(&pub_cli.client_id, "https://app.example/cb", "openid", verifier, "plain", None, "u1", vec![])
            .await
            .is_err());
        // Unregistered scope escalation -> MUST fail
        assert!(idp
            .issue_authorization_code(&pub_cli.client_id, "https://app.example/cb", "openid admin:all", &challenge, "S256", None, "u1", vec![])
            .await
            .is_err());
        // Public client cannot use client_credentials -> MUST fail
        assert!(idp
            .exchange_token("client_credentials", &pub_cli.client_id, None, None, None, None, None, Some("openid"))
            .await
            .is_err());

        // Short (< 43 chars) PKCE verifier -> MUST fail RFC 7636 check
        let short_v = "too-short-verifier";
        let short_ch = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(short_v.as_bytes()));
        let code = idp
            .issue_authorization_code(&pub_cli.client_id, "https://app.example/cb", "openid", &short_ch, "S256", None, "u1", vec![])
            .await
            .unwrap();
        assert!(idp
            .exchange_token("authorization_code", &pub_cli.client_id, None, Some(&code), Some("https://app.example/cb"), Some(short_v), None, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn security_concurrent_refresh_token_race_triggers_atomic_family_revocation() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db);
        let (cli, sec) = idp
            .create_oidc_client(
                "root",
                "default",
                "Race Client",
                OidcClientType::Confidential,
                vec!["https://race.example/cb".into()],
                vec!["authorization_code".into(), "refresh_token".into()],
                vec!["openid".into()],
            )
            .await
            .unwrap();
        let sec = sec.unwrap();
        let verifier = "concurrent-refresh-race-pkce-verifier-0123456789abcdef";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
        let code = idp
            .issue_authorization_code(&cli.client_id, "https://race.example/cb", "openid", &challenge, "S256", None, "u_race", vec![])
            .await
            .unwrap();
        let tok1 = idp
            .exchange_token("authorization_code", &cli.client_id, Some(&sec), Some(&code), Some("https://race.example/cb"), Some(verifier), None, None)
            .await
            .unwrap();
        let rt1 = tok1.refresh_token.unwrap();

        // Fire two concurrent refresh exchanges with the exact same rt1!
        let (r1, r2) = tokio::join!(
            idp.exchange_token("refresh_token", &cli.client_id, Some(&sec), None, None, None, Some(&rt1), None),
            idp.exchange_token("refresh_token", &cli.client_id, Some(&sec), None, None, None, Some(&rt1), None),
        );
        // Exactly ONE succeeds and ONE triggers replay detection; the winning access_token MUST be revoked!
        let (winner, loser_err) = match (r1, r2) {
            (Ok(w), Err(e)) | (Err(e), Ok(w)) => (w, e),
            (Ok(_), Ok(_)) => panic!("Concurrent refresh race MUST NEVER allow both to succeed!"),
            (Err(e1), Err(e2)) => panic!("One refresh should have succeeded before replay: {:?} / {:?}", e1, e2),
        };
        assert!(loser_err.to_string().contains("replay"));
        assert!(
            idp.introspect_token(&winner.access_token).await.unwrap().is_none(),
            "Replay from racing refresh MUST atomically revoke the winning token's entire family"
        );
    }

    #[tokio::test]
    async fn security_hierarchy_limits_deep_reparent_and_concurrent_moves() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db).with_hierarchy_limits(HierarchyLimits {
            max_depth: 3,
            max_subtree_size: 4,
        });
        let a = idp.create_org("root", "a", "A", None, None, OrgPolicyPatch::default()).await.unwrap();
        let b = idp.create_org("root", "b", "B", Some(a.org_id.clone()), None, OrgPolicyPatch::default()).await.unwrap();
        let c = idp.create_org("root", "c", "C", Some(b.org_id.clone()), None, OrgPolicyPatch::default()).await.unwrap();
        let d = idp.create_org("root", "d", "D", Some(c.org_id.clone()), None, OrgPolicyPatch::default()).await.unwrap();
        assert_eq!(d.depth, 3);
        // Exceeding max_depth=3 -> MUST fail
        assert!(idp.create_org("root", "e", "E", Some(d.org_id.clone()), None, OrgPolicyPatch::default()).await.is_err());

        // Create second root X and reparent subtree B->C->D under X (depth 1->2->3 OK!)
        let x = idp.create_org("root", "x", "X", None, None, OrgPolicyPatch::default()).await.unwrap();
        let b_moved = idp.reparent_org("root", &b.org_id, Some(x.org_id.clone())).await.unwrap();
        assert_eq!(b_moved.path, format!("/{}/{}", x.org_id, b.org_id));
        let d_after = idp.get_org(&d.org_id).await.unwrap().unwrap();
        assert_eq!(d_after.path, format!("/{}/{}/{}/{}", x.org_id, b.org_id, c.org_id, d.org_id));
        assert_eq!(d_after.depth, 3);

        // Concurrent opposing reparents (X under B vs B under A) MUST NOT create a cycle!
        let (m1, m2) = tokio::join!(
            idp.reparent_org("root", &x.org_id, Some(b.org_id.clone())),
            idp.reparent_org("root", &b.org_id, Some(a.org_id.clone())),
        );
        // Either X under B failed (because B is under X) or B moved to A first so X under B succeeded without cycle
        let x_fin = idp.get_org(&x.org_id).await.unwrap().unwrap();
        let b_fin = idp.get_org(&b.org_id).await.unwrap().unwrap();
        assert!(!(x_fin.path.contains(&b.org_id) && b_fin.path.contains(&x.org_id)), "Cycle MUST be impossible: m1={:?} m2={:?}", m1, m2);
    }
}
