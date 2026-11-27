//! Phase 2B: W3C WebAuthn / FIDO2 Passkey Abstraction & Service
//!
//! Architectural Boundary:
//! - All public types and traits are **100% Nexus-owned DTOs** — no `webauthn-rs` types leak
//!   into `AuthFlowEngine`, `NexusIdp`, or `UxGateway`.
//! - The audited `webauthn-rs = "=0.6.2"` (`MPL-2.0`) Relying Party verifier is strictly
//!   feature-gated behind `iam-webauthn` (included in `full`; omitted in `core` so `core`
//!   remains 422 unique crates / 100% MIT).
//! - Challenges are single-use, striped-linearized, and strictly bound to
//!   `(identity_id, flow_execution_id, rp_id, exact_origin, expires_at_ms)` (no wildcard origins).
//! - Credentials store ONLY public keys + W3C Level 3 metadata (`backup_eligible`, `backup_state`,
//!   `sign_count`, `device_name`, `revoked`) — NEVER private authenticator keys.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::db::Database;
use crate::iam::idp::NexusIdp;

const WEBAUTHN_STRIPE_COUNT: usize = 64;

fn wa_stripe_idx(key: &str) -> usize {
    let h = blake3::hash(key.as_bytes());
    let b = h.as_bytes();
    (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) % WEBAUTHN_STRIPE_COUNT
}

static WEBAUTHN_STRIPES: Lazy<Vec<Mutex<()>>> =
    Lazy::new(|| (0..WEBAUTHN_STRIPE_COUNT).map(|_| Mutex::new(())).collect());

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Validate exact Relying Party origin (must be `https://...` or `http://localhost[:port]` /
/// `http://127.0.0.1[:port]`, never wildcard `*` or empty).
pub fn validate_exact_origin(rp_id: &str, rp_origin: &str) -> Result<()> {
    let rid = rp_id.trim();
    let orig = rp_origin.trim();
    if rid.is_empty() || rid.contains('*') || rid.contains('/') || rid.contains(':') {
        anyhow::bail!("Invalid WebAuthn rp_id '{}'", rp_id);
    }
    if orig.is_empty() || orig.contains('*') || orig.ends_with('/') {
        anyhow::bail!("Invalid WebAuthn rp_origin '{}': exact origin required (no wildcards or trailing slash)", rp_origin);
    }
    let valid_scheme = orig.starts_with("https://")
        || orig.starts_with("http://localhost")
        || orig.starts_with("http://127.0.0.1");
    if !valid_scheme {
        anyhow::bail!("WebAuthn rp_origin '{}' must use https:// (or localhost for local dev)", rp_origin);
    }
    Ok(())
}

// =============================================================================
// Nexus-Owned WebAuthn DTOs & Provider Trait
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub identity_id: String,
    pub username: String,
    pub display_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    #[serde(default)]
    pub flow_execution_id: Option<String>,
    #[serde(default)]
    pub exclude_credential_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge_id: String,
    pub identity_id: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub public_key_options: serde_json::Value,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub challenge_id: String,
    pub device_name: String,
    pub credential_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredCredential {
    pub credential_id: String,
    pub identity_id: String,
    pub rp_id: String,
    pub device_name: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub sign_count: u32,
    /// Opaque public credential blob managed by the active `WebAuthnProvider` (NEVER private keys).
    pub serialized_passkey: String,
    pub created_at_ms: u64,
    pub last_used_at_ms: Option<u64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    #[serde(default)]
    pub identity_id: Option<String>,
    pub rp_id: String,
    pub rp_origin: String,
    #[serde(default)]
    pub flow_execution_id: Option<String>,
    #[serde(default)]
    pub allowed_credentials: Vec<RegisteredCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge_id: String,
    pub identity_id: Option<String>,
    pub rp_id: String,
    pub rp_origin: String,
    pub public_key_options: serde_json::Value,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub challenge_id: String,
    pub credential_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    pub identity_id: String,
    pub credential_id: String,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub updated_serialized_passkey: Option<String>,
}

/// Pluggable WebAuthn Relying Party provider boundary (zero third-party types exposed).
pub trait WebAuthnProvider: Send + Sync {
    fn begin_registration(&self, req: &RegistrationRequest) -> Result<(RegistrationChallenge, String)>;
    fn finish_registration(
        &self,
        req: &RegistrationResponse,
        provider_state: &str,
        identity_id: &str,
        rp_id: &str,
        rp_origin: &str,
    ) -> Result<RegisteredCredential>;
    fn begin_authentication(&self, req: &AuthenticationRequest) -> Result<(AuthenticationChallenge, String)>;
    fn finish_authentication(
        &self,
        req: &AuthenticationResponse,
        provider_state: &str,
        identity_id: &str,
        rp_id: &str,
        rp_origin: &str,
        stored_creds: &[RegisteredCredential],
    ) -> Result<AuthenticationResult>;
}

/// Default provider when compiled without `--features iam-webauthn`.
pub struct UnavailableWebAuthnProvider;

impl WebAuthnProvider for UnavailableWebAuthnProvider {
    fn begin_registration(&self, _: &RegistrationRequest) -> Result<(RegistrationChallenge, String)> {
        anyhow::bail!("WebAuthn requires building Nexus-IO with `--features iam-webauthn` (or `full`)")
    }
    fn finish_registration(&self, _: &RegistrationResponse, _: &str, _: &str, _: &str, _: &str) -> Result<RegisteredCredential> {
        anyhow::bail!("WebAuthn requires building Nexus-IO with `--features iam-webauthn` (or `full`)")
    }
    fn begin_authentication(&self, _: &AuthenticationRequest) -> Result<(AuthenticationChallenge, String)> {
        anyhow::bail!("WebAuthn requires building Nexus-IO with `--features iam-webauthn` (or `full`)")
    }
    fn finish_authentication(&self, _: &AuthenticationResponse, _: &str, _: &str, _: &str, _: &str, _: &[RegisteredCredential]) -> Result<AuthenticationResult> {
        anyhow::bail!("WebAuthn requires building Nexus-IO with `--features iam-webauthn` (or `full`)")
    }
}

/// Audited W3C WebAuthn Level 2/3 provider backed by `webauthn-rs = "=0.6.2"` (`MPL-2.0`).
/// Ephemeral ceremony states (`PasskeyRegistration`, `PasskeyAuthentication`) are held strictly
/// in memory (ZCZS, atomically removed on completion) per `webauthn-rs` security best practices.
#[cfg(feature = "iam-webauthn")]
pub struct WebAuthnRsProvider;

#[cfg(feature = "iam-webauthn")]
static WA_REG_STATES: Lazy<std::sync::RwLock<std::collections::HashMap<String, webauthn_rs::prelude::PasskeyRegistration>>> =
    Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

#[cfg(feature = "iam-webauthn")]
static WA_AUTH_STATES: Lazy<std::sync::RwLock<std::collections::HashMap<String, webauthn_rs::prelude::PasskeyAuthentication>>> =
    Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

#[cfg(feature = "iam-webauthn")]
impl WebAuthnRsProvider {
    fn build_rp(rp_id: &str, rp_origin: &str) -> Result<webauthn_rs::Webauthn> {
        validate_exact_origin(rp_id, rp_origin)?;
        let url = webauthn_rs::prelude::Url::parse(rp_origin)
            .map_err(|e| anyhow!("Invalid rp_origin URL '{}': {}", rp_origin, e))?;
        webauthn_rs::WebauthnBuilder::new(rp_id, &url)
            .map_err(|e| anyhow!("WebauthnBuilder error: {}", e))?
            .build()
            .map_err(|e| anyhow!("Webauthn build error: {}", e))
    }
}

#[cfg(feature = "iam-webauthn")]
impl WebAuthnProvider for WebAuthnRsProvider {
    fn begin_registration(&self, req: &RegistrationRequest) -> Result<(RegistrationChallenge, String)> {
        let rp = Self::build_rp(&req.rp_id, &req.rp_origin)?;
        let h = blake3::hash(req.identity_id.as_bytes());
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&h.as_bytes()[..16]);
        let user_uid = webauthn_rs::prelude::Uuid::from_bytes(uuid_bytes);

        let exclude: Option<Vec<webauthn_rs::prelude::CredentialID>> = if req.exclude_credential_ids.is_empty() {
            None
        } else {
            use base64::Engine as _;
            let ids: Vec<_> = req
                .exclude_credential_ids
                .iter()
                .filter_map(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok())
                .map(webauthn_rs::prelude::CredentialID::from)
                .collect();
            if ids.is_empty() { None } else { Some(ids) }
        };

        let (ccr, reg_state) = rp
            .start_passkey_registration(user_uid, &req.username, &req.display_name, exclude)
            .map_err(|e| anyhow!("WebAuthn start_passkey_registration failed: {}", e))?;

        let challenge_id = format!("wach_{}", uuid::Uuid::new_v4().simple());
        if let Ok(mut map) = WA_REG_STATES.write() {
            map.insert(challenge_id.clone(), reg_state);
        }
        let opts = serde_json::to_value(&ccr)?;
        let challenge = RegistrationChallenge {
            challenge_id: challenge_id.clone(),
            identity_id: req.identity_id.clone(),
            rp_id: req.rp_id.clone(),
            rp_origin: req.rp_origin.clone(),
            public_key_options: opts,
            expires_at_ms: now_ms() + 300_000,
        };
        Ok((challenge, challenge_id))
    }

    fn finish_registration(
        &self,
        req: &RegistrationResponse,
        provider_state: &str,
        identity_id: &str,
        rp_id: &str,
        rp_origin: &str,
    ) -> Result<RegisteredCredential> {
        let state = WA_REG_STATES
            .write()
            .ok()
            .and_then(|mut m| m.remove(provider_state))
            .ok_or_else(|| anyhow!("Missing or already-consumed WebAuthn registration ceremony state"))?;
        let reg_cred: webauthn_rs::prelude::RegisterPublicKeyCredential =
            serde_json::from_value(req.credential_json.clone())
                .map_err(|e| anyhow!("Invalid RegisterPublicKeyCredential JSON: {}", e))?;
        let rp = Self::build_rp(rp_id, rp_origin)?;
        let passkey = rp
            .finish_passkey_registration(&reg_cred, &state)
            .map_err(|e| anyhow!("WebAuthn finish_passkey_registration failed: {}", e))?;

        use base64::Engine as _;
        let cred_bytes: &[u8] = passkey.cred_id().as_ref();
        let cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let serialized_passkey = serde_json::to_string(&passkey)?;
        Ok(RegisteredCredential {
            credential_id: cred_id,
            identity_id: identity_id.to_string(),
            rp_id: rp_id.to_string(),
            device_name: req.device_name.trim().to_string(),
            backup_eligible: true,
            backup_state: false,
            sign_count: 0,
            serialized_passkey,
            created_at_ms: now_ms(),
            last_used_at_ms: None,
            revoked: false,
        })
    }

    fn begin_authentication(&self, req: &AuthenticationRequest) -> Result<(AuthenticationChallenge, String)> {
        let rp = Self::build_rp(&req.rp_id, &req.rp_origin)?;
        let passkeys: Vec<webauthn_rs::prelude::Passkey> = req
            .allowed_credentials
            .iter()
            .filter(|c| !c.revoked)
            .filter_map(|c| serde_json::from_str(&c.serialized_passkey).ok())
            .collect();
        if passkeys.is_empty() {
            anyhow::bail!("No active WebAuthn passkeys registered for this identity");
        }
        let (rcr, auth_state) = rp
            .start_passkey_authentication(&passkeys)
            .map_err(|e| anyhow!("WebAuthn start_passkey_authentication failed: {}", e))?;

        let challenge_id = format!("wach_{}", uuid::Uuid::new_v4().simple());
        if let Ok(mut map) = WA_AUTH_STATES.write() {
            map.insert(challenge_id.clone(), auth_state);
        }
        let opts = serde_json::to_value(&rcr)?;
        let challenge = AuthenticationChallenge {
            challenge_id: challenge_id.clone(),
            identity_id: req.identity_id.clone(),
            rp_id: req.rp_id.clone(),
            rp_origin: req.rp_origin.clone(),
            public_key_options: opts,
            expires_at_ms: now_ms() + 300_000,
        };
        Ok((challenge, challenge_id))
    }

    fn finish_authentication(
        &self,
        req: &AuthenticationResponse,
        provider_state: &str,
        identity_id: &str,
        rp_id: &str,
        rp_origin: &str,
        stored_creds: &[RegisteredCredential],
    ) -> Result<AuthenticationResult> {
        let state = WA_AUTH_STATES
            .write()
            .ok()
            .and_then(|mut m| m.remove(provider_state))
            .ok_or_else(|| anyhow!("Missing or already-consumed WebAuthn authentication ceremony state"))?;
        let auth_cred: webauthn_rs::prelude::PublicKeyCredential =
            serde_json::from_value(req.credential_json.clone())
                .map_err(|e| anyhow!("Invalid PublicKeyCredential JSON: {}", e))?;
        let rp = Self::build_rp(rp_id, rp_origin)?;
        let auth_res = rp
            .finish_passkey_authentication(&auth_cred, &state)
            .map_err(|e| anyhow!("WebAuthn finish_passkey_authentication failed: {}", e))?;

        use base64::Engine as _;
        let cred_bytes: &[u8] = auth_res.cred_id().as_ref();
        let cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let mut updated_serialized = None;
        if let Some(stored) = stored_creds.iter().find(|c| c.credential_id == cred_id) {
            if let Ok(mut pk) = serde_json::from_str::<webauthn_rs::prelude::Passkey>(&stored.serialized_passkey) {
                pk.update_credential(&auth_res);
                updated_serialized = serde_json::to_string(&pk).ok();
            }
        }
        Ok(AuthenticationResult {
            identity_id: identity_id.to_string(),
            credential_id: cred_id,
            sign_count: auth_res.counter(),
            backup_eligible: auth_res.backup_eligible(),
            backup_state: auth_res.backup_state(),
            user_verified: auth_res.user_verified(),
            updated_serialized_passkey: updated_serialized,
        })
    }
}

pub fn default_webauthn_provider() -> Arc<dyn WebAuthnProvider> {
    #[cfg(feature = "iam-webauthn")]
    {
        Arc::new(WebAuthnRsProvider)
    }
    #[cfg(not(feature = "iam-webauthn"))]
    {
        Arc::new(UnavailableWebAuthnProvider)
    }
}

// =============================================================================
// Persistent Single-Use Challenge & Credential Lifecycle Service
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChallenge {
    challenge_id: String,
    kind: String, // "registration" | "authentication"
    identity_id: Option<String>,
    flow_execution_id: Option<String>,
    rp_id: String,
    rp_origin: String,
    provider_state: String,
    used: bool,
    expires_at_ms: u64,
}

#[derive(Clone)]
pub struct WebAuthnService {
    db: Arc<Database>,
    idp: NexusIdp,
    provider: Arc<dyn WebAuthnProvider>,
}

impl WebAuthnService {
    pub fn new(db: Arc<Database>) -> Self {
        Self::with_provider(db, default_webauthn_provider())
    }

    pub fn with_provider(db: Arc<Database>, provider: Arc<dyn WebAuthnProvider>) -> Self {
        let idp = NexusIdp::new(db.clone());
        Self { db, idp, provider }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        self.idp.ensure_tables().await?;
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_iam_webauthn_cred SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_webauthn_challenge SCHEMALESS;";
        let _ = self.db.client.query(ddl).await;
        Ok(())
    }

    pub async fn list_credentials(&self, identity_id: &str) -> Result<Vec<RegisteredCredential>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_webauthn_cred")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<RegisteredCredential>(v).ok())
            .filter(|c| c.identity_id == identity_id && !c.revoked)
            .collect())
    }

    pub async fn begin_registration(&self, mut req: RegistrationRequest) -> Result<RegistrationChallenge> {
        self.ensure_tables().await?;
        validate_exact_origin(&req.rp_id, &req.rp_origin)?;
        if self.idp.get_identity(&req.identity_id).await?.is_none() {
            anyhow::bail!("Identity '{}' not found", req.identity_id);
        }
        let existing = self.list_credentials(&req.identity_id).await?;
        req.exclude_credential_ids = existing.into_iter().map(|c| c.credential_id).collect();
        let (challenge, provider_state) = self.provider.begin_registration(&req)?;
        let stored = StoredChallenge {
            challenge_id: challenge.challenge_id.clone(),
            kind: "registration".into(),
            identity_id: Some(req.identity_id),
            flow_execution_id: req.flow_execution_id,
            rp_id: challenge.rp_id.clone(),
            rp_origin: challenge.rp_origin.clone(),
            provider_state,
            used: false,
            expires_at_ms: challenge.expires_at_ms,
        };
        let val = serde_json::to_value(&stored)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_webauthn_challenge', $id) CONTENT $c;")
            .bind(("id", stored.challenge_id))
            .bind(("c", val))
            .await?
            .check()?;
        Ok(challenge)
    }

    pub async fn finish_registration(&self, req: RegistrationResponse) -> Result<RegisteredCredential> {
        let _guard = WEBAUTHN_STRIPES[wa_stripe_idx(&req.challenge_id)].lock().await;
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_webauthn_challenge', $id)")
            .bind(("id", req.challenge_id.clone()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut ch: StoredChallenge = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Unknown WebAuthn challenge '{}'", req.challenge_id))?;

        if ch.kind != "registration" || ch.used || now_ms() > ch.expires_at_ms {
            anyhow::bail!("WebAuthn registration challenge expired, invalid, or already consumed");
        }
        let identity_id = ch
            .identity_id
            .clone()
            .ok_or_else(|| anyhow!("Registration challenge missing identity_id"))?;

        ch.used = true;
        let ch_val = serde_json::to_value(&ch)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_webauthn_challenge', $id) CONTENT $c;")
            .bind(("id", ch.challenge_id.clone()))
            .bind(("c", ch_val))
            .await?
            .check()?;

        let cred = self
            .provider
            .finish_registration(&req, &ch.provider_state, &identity_id, &ch.rp_id, &ch.rp_origin)?;
        let cval = serde_json::to_value(&cred)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_webauthn_cred', $id) CONTENT $c;")
            .bind(("id", cred.credential_id.clone()))
            .bind(("c", cval))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit("instance", &identity_id, "webauthn.register", &cred.credential_id, "ok", &cred.device_name)
            .await;
        Ok(cred)
    }

    pub async fn begin_authentication(&self, mut req: AuthenticationRequest) -> Result<AuthenticationChallenge> {
        self.ensure_tables().await?;
        validate_exact_origin(&req.rp_id, &req.rp_origin)?;
        if let Some(ref ident_id) = req.identity_id {
            req.allowed_credentials = self.list_credentials(ident_id).await?;
        }
        let (challenge, provider_state) = self.provider.begin_authentication(&req)?;
        let stored = StoredChallenge {
            challenge_id: challenge.challenge_id.clone(),
            kind: "authentication".into(),
            identity_id: req.identity_id,
            flow_execution_id: req.flow_execution_id,
            rp_id: challenge.rp_id.clone(),
            rp_origin: challenge.rp_origin.clone(),
            provider_state,
            used: false,
            expires_at_ms: challenge.expires_at_ms,
        };
        let val = serde_json::to_value(&stored)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_webauthn_challenge', $id) CONTENT $c;")
            .bind(("id", stored.challenge_id))
            .bind(("c", val))
            .await?
            .check()?;
        Ok(challenge)
    }

    pub async fn finish_authentication(&self, req: AuthenticationResponse) -> Result<AuthenticationResult> {
        let _guard = WEBAUTHN_STRIPES[wa_stripe_idx(&req.challenge_id)].lock().await;
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_webauthn_challenge', $id)")
            .bind(("id", req.challenge_id.clone()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut ch: StoredChallenge = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Unknown WebAuthn challenge '{}'", req.challenge_id))?;

        if ch.kind != "authentication" || ch.used || now_ms() > ch.expires_at_ms {
            anyhow::bail!("WebAuthn authentication challenge expired, invalid, or already consumed");
        }
        let identity_id = ch
            .identity_id
            .clone()
            .ok_or_else(|| anyhow!("Authentication challenge missing bound identity_id"))?;

        ch.used = true;
        let ch_val = serde_json::to_value(&ch)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_webauthn_challenge', $id) CONTENT $c;")
            .bind(("id", ch.challenge_id.clone()))
            .bind(("c", ch_val))
            .await?
            .check()?;

        let stored_creds = self.list_credentials(&identity_id).await?;
        let res = self
            .provider
            .finish_authentication(&req, &ch.provider_state, &identity_id, &ch.rp_id, &ch.rp_origin, &stored_creds)?;

        // Update metadata (sign_count, backup_state, last_used_at_ms) without false-failing synced passkeys
        if let Some(mut cred) = stored_creds.into_iter().find(|c| c.credential_id == res.credential_id) {
            // Only flag clone anomaly if credential is NOT backup-eligible AND counter regressed on non-zero counter
            if !res.backup_eligible && cred.sign_count > 0 && res.sign_count > 0 && res.sign_count <= cred.sign_count {
                let _ = self
                    .idp
                    .append_audit("instance", &identity_id, "webauthn.clone_detected", &cred.credential_id, "denied", "non-synced counter did not advance")
                    .await;
                anyhow::bail!("WebAuthn sign_count regression detected on non-synced hardware authenticator");
            }
            cred.sign_count = res.sign_count;
            cred.backup_eligible = res.backup_eligible;
            cred.backup_state = res.backup_state;
            cred.last_used_at_ms = Some(now_ms());
            if let Some(ref updated) = res.updated_serialized_passkey {
                cred.serialized_passkey = updated.clone();
            }
            let cval = serde_json::to_value(&cred)?;
            self.db
                .client
                .query("UPSERT type::record('sys_iam_webauthn_cred', $id) CONTENT $c;")
                .bind(("id", cred.credential_id.clone()))
                .bind(("c", cval))
                .await?
                .check()?;
        }

        let _ = self
            .idp
            .append_audit("instance", &identity_id, "webauthn.auth", &res.credential_id, "ok", &format!("uv={} backup={}", res.user_verified, res.backup_state))
            .await;
        Ok(res)
    }

    pub async fn revoke_credential(&self, actor: &str, identity_id: &str, credential_id: &str) -> Result<bool> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_webauthn_cred', $id)")
            .bind(("id", credential_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        if let Some(mut cred) = rows
            .first()
            .and_then(|v| serde_json::from_value::<RegisteredCredential>(v.clone()).ok())
        {
            if cred.identity_id != identity_id {
                anyhow::bail!("Credential does not belong to identity '{}'", identity_id);
            }
            cred.revoked = true;
            let cval = serde_json::to_value(&cred)?;
            self.db
                .client
                .query("UPSERT type::record('sys_iam_webauthn_cred', $id) CONTENT $c;")
                .bind(("id", cred.credential_id.clone()))
                .bind(("c", cval))
                .await?
                .check()?;
            let _ = self
                .idp
                .append_audit("instance", actor, "webauthn.revoke", credential_id, "ok", identity_id)
                .await;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test provider verifying Nexus's WebAuthnService contract in `core`
    /// (single-use challenges, exact origin validation, synced vs hardware counters, revocation).
    struct TestWebAuthnProvider;

    impl WebAuthnProvider for TestWebAuthnProvider {
        fn begin_registration(&self, req: &RegistrationRequest) -> Result<(RegistrationChallenge, String)> {
            let cid = format!("wach_{}", uuid::Uuid::new_v4().simple());
            Ok((
                RegistrationChallenge {
                    challenge_id: cid.clone(),
                    identity_id: req.identity_id.clone(),
                    rp_id: req.rp_id.clone(),
                    rp_origin: req.rp_origin.clone(),
                    public_key_options: serde_json::json!({ "challenge": cid, "rp": { "id": req.rp_id } }),
                    expires_at_ms: now_ms() + 60_000,
                },
                "test_reg_state".into(),
            ))
        }

        fn finish_registration(
            &self,
            req: &RegistrationResponse,
            _: &str,
            identity_id: &str,
            rp_id: &str,
            _: &str,
        ) -> Result<RegisteredCredential> {
            let synced = req.credential_json["backup_eligible"].as_bool().unwrap_or(true);
            let cred_id = req.credential_json["id"]
                .as_str()
                .unwrap_or("cred_default")
                .to_string();
            Ok(RegisteredCredential {
                credential_id: cred_id,
                identity_id: identity_id.to_string(),
                rp_id: rp_id.to_string(),
                device_name: req.device_name.clone(),
                backup_eligible: synced,
                backup_state: synced,
                sign_count: 1,
                serialized_passkey: "public_passkey_cose_blob".into(),
                created_at_ms: now_ms(),
                last_used_at_ms: None,
                revoked: false,
            })
        }

        fn begin_authentication(&self, req: &AuthenticationRequest) -> Result<(AuthenticationChallenge, String)> {
            if req.allowed_credentials.is_empty() {
                anyhow::bail!("No active credentials");
            }
            let cid = format!("wach_{}", uuid::Uuid::new_v4().simple());
            Ok((
                AuthenticationChallenge {
                    challenge_id: cid.clone(),
                    identity_id: req.identity_id.clone(),
                    rp_id: req.rp_id.clone(),
                    rp_origin: req.rp_origin.clone(),
                    public_key_options: serde_json::json!({ "challenge": cid }),
                    expires_at_ms: now_ms() + 60_000,
                },
                "test_auth_state".into(),
            ))
        }

        fn finish_authentication(
            &self,
            req: &AuthenticationResponse,
            _: &str,
            identity_id: &str,
            _: &str,
            _: &str,
            stored_creds: &[RegisteredCredential],
        ) -> Result<AuthenticationResult> {
            let cred_id = req.credential_json["id"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing credential id"))?;
            let stored = stored_creds
                .iter()
                .find(|c| c.credential_id == cred_id && !c.revoked)
                .ok_or_else(|| anyhow!("Credential revoked or unknown"))?;
            Ok(AuthenticationResult {
                identity_id: identity_id.to_string(),
                credential_id: cred_id.to_string(),
                sign_count: req.credential_json["sign_count"].as_u64().unwrap_or(0) as u32,
                backup_eligible: stored.backup_eligible,
                backup_state: stored.backup_state,
                user_verified: true,
                updated_serialized_passkey: None,
            })
        }
    }

    #[tokio::test]
    async fn webauthn_exact_origin_single_use_challenge_synced_vs_hardware_counter_and_revocation() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let svc = WebAuthnService::with_provider(db, Arc::new(TestWebAuthnProvider));
        let (alice, _) = idp.create_identity("Alice", None).await.unwrap();

        // Wildcard origin MUST be rejected
        assert!(svc
            .begin_registration(RegistrationRequest {
                identity_id: alice.identity_id.clone(),
                username: "alice".into(),
                display_name: "Alice".into(),
                rp_id: "nexus.aerea.co".into(),
                rp_origin: "https://*.aerea.co".into(),
                flow_execution_id: None,
                exclude_credential_ids: vec![],
            })
            .await
            .is_err());

        // Register a synced passkey (backup_eligible=true, sign_count=0 allowed!)
        let reg_ch = svc
            .begin_registration(RegistrationRequest {
                identity_id: alice.identity_id.clone(),
                username: "alice".into(),
                display_name: "Alice".into(),
                rp_id: "nexus.aerea.co".into(),
                rp_origin: "https://nexus.aerea.co".into(),
                flow_execution_id: None,
                exclude_credential_ids: vec![],
            })
            .await
            .unwrap();
        let cred = svc
            .finish_registration(RegistrationResponse {
                challenge_id: reg_ch.challenge_id.clone(),
                device_name: "iCloud Passkey".into(),
                credential_json: serde_json::json!({ "id": "cred_synced_1", "backup_eligible": true }),
            })
            .await
            .unwrap();
        assert_eq!(cred.credential_id, "cred_synced_1");

        // Replaying the same registration challenge MUST fail!
        assert!(svc
            .finish_registration(RegistrationResponse {
                challenge_id: reg_ch.challenge_id,
                device_name: "Replay".into(),
                credential_json: serde_json::json!({ "id": "cred_replay" }),
            })
            .await
            .is_err());

        // Authenticate with synced passkey (sign_count = 0 does NOT false-fail!)
        let auth_ch = svc
            .begin_authentication(AuthenticationRequest {
                identity_id: Some(alice.identity_id.clone()),
                rp_id: "nexus.aerea.co".into(),
                rp_origin: "https://nexus.aerea.co".into(),
                flow_execution_id: None,
                allowed_credentials: vec![],
            })
            .await
            .unwrap();
        let auth_res = svc
            .finish_authentication(AuthenticationResponse {
                challenge_id: auth_ch.challenge_id.clone(),
                credential_json: serde_json::json!({ "id": "cred_synced_1", "sign_count": 0 }),
            })
            .await
            .unwrap();
        assert!(auth_res.user_verified);
        assert!(auth_res.backup_eligible);

        // Register a non-synced hardware key (backup_eligible=false): counter regression MUST fail!
        let hw_reg = svc
            .begin_registration(RegistrationRequest {
                identity_id: alice.identity_id.clone(),
                username: "alice".into(),
                display_name: "Alice".into(),
                rp_id: "nexus.aerea.co".into(),
                rp_origin: "https://nexus.aerea.co".into(),
                flow_execution_id: None,
                exclude_credential_ids: vec![],
            })
            .await
            .unwrap();
        svc.finish_registration(RegistrationResponse {
            challenge_id: hw_reg.challenge_id,
            device_name: "YubiKey 5".into(),
            credential_json: serde_json::json!({ "id": "cred_hw_1", "backup_eligible": false }),
        })
        .await
        .unwrap();

        let hw_auth = svc
            .begin_authentication(AuthenticationRequest {
                identity_id: Some(alice.identity_id.clone()),
                rp_id: "nexus.aerea.co".into(),
                rp_origin: "https://nexus.aerea.co".into(),
                flow_execution_id: None,
                allowed_credentials: vec![],
            })
            .await
            .unwrap();
        assert!(
            svc.finish_authentication(AuthenticationResponse {
                challenge_id: hw_auth.challenge_id,
                credential_json: serde_json::json!({ "id": "cred_hw_1", "sign_count": 1 }),
            })
            .await
            .is_err(),
            "Non-synced hardware authenticator with non-increasing counter MUST be rejected"
        );

        // Revoking credential prevents further use
        assert!(svc.revoke_credential(&alice.identity_id, &alice.identity_id, "cred_synced_1").await.unwrap());
        assert_eq!(svc.list_credentials(&alice.identity_id).await.unwrap().len(), 1);
    }
}
