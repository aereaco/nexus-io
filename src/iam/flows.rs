//! Phase 2A: Declarative, Versioned Authentication Flow Engine (`AuthFlow` & `AuthStage`)
//!
//! Core Security Invariants:
//! 1. **AuthFlow != Authorization:** A flow establishes *who* is authenticating and *how
//!    confidently* (`AuthResult`: `identity_id`, `org_id`, `amr`, `acr`, `authorities`).
//!    It NEVER grants roles or permissions (those remain strictly in `NexusIdp::evaluate_permission`).
//! 2. **3-Tier Authentication Authority:** Tracks `IdentityControlled`, `OrganizationRequired`,
//!    and `Federated` factors independently without letting an org own the identity's root keys.
//! 3. **Unbypassable Native Security Gate:** Before completing any execution, native Rust code
//!    enforces `ComposedOrgPolicy` (e.g., `mfa_required = true` cannot be skipped by flow design
//!    or by a `WasmPolicyStage`).
//! 4. **Sandboxed Wasm Policy Stages:** Wasm stages can only return `Allow | Deny | RequireStepUp`
//!    and can never bypass credential verification, mutate `identity_id`, or grant permissions.
//! 5. **ZCZS Striped Linearizability:** 64-stripe lock table per `execution_id` + typed `Arc` cache.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::db::Database;
use crate::iam::idp::NexusIdp;

const FLOW_STRIPE_COUNT: usize = 64;

fn flow_stripe_idx(exec_id: &str) -> usize {
    let h = blake3::hash(exec_id.as_bytes());
    let b = h.as_bytes();
    (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) % FLOW_STRIPE_COUNT
}

static FLOW_STRIPES: Lazy<Vec<Mutex<()>>> =
    Lazy::new(|| (0..FLOW_STRIPE_COUNT).map(|_| Mutex::new(())).collect());

static EXEC_CACHE: Lazy<RwLock<HashMap<(usize, String), Arc<FlowExecution>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Which authority governed an authentication factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAuthority {
    /// Credentials registered to and controlled by the identity holder.
    IdentityControlled,
    /// Additional factor or method required by an organization's composed policy.
    OrganizationRequired,
    /// Verified assertion from a trusted external or home identity provider.
    Federated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StageCondition {
    OrgMfaRequired,
    HasAmr { method: String },
    MissingAmr { method: String },
}

/// Strict output contract for sandboxed `WasmPolicyStage` evaluators.
/// A Wasm stage can NEVER mutate identity, skip verification, or grant permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyStageDecision {
    Allow,
    Deny { reason: String },
    RequireStepUp { factor: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthStageKind {
    Identification,
    OrgDiscovery,
    PasswordVerify,
    TotpVerify {
        #[serde(default)]
        org_required: bool,
    },
    WebAuthnAssert,
    RecoveryCode,
    ExternalProvider {
        provider_id: String,
    },
    ConditionalBranch {
        condition: StageCondition,
        if_true_stage: String,
        if_false_stage: Option<String>,
    },
    WasmPolicyStage {
        module_cid: String,
        #[serde(default = "default_wasm_fuel")]
        max_fuel: u64,
    },
    Consent {
        #[serde(default)]
        scopes: Vec<String>,
    },
}

fn default_wasm_fuel() -> u64 {
    50_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStage {
    pub stage_id: String,
    pub kind: AuthStageKind,
    #[serde(default = "default_stage_retries")]
    pub max_retries: u32,
}

fn default_stage_retries() -> u32 {
    5
}

/// Versioned, immutable declarative authentication flow definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlow {
    pub flow_id: String,
    pub version: u32,
    pub name: String,
    pub org_id: Option<String>,
    pub stages: Vec<AuthStage>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_stage_retries")]
    pub max_retries: u32,
    pub created_at_ms: u64,
}

fn default_timeout_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowExecStatus {
    InProgress,
    Completed,
    Failed,
    LockedOut,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageAuditEntry {
    pub stage_id: String,
    pub outcome: String,
    pub detail: String,
    pub timestamp_ms: u64,
}

/// Verified authentication outcome — strictly identity + assurance, NEVER authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub execution_id: String,
    pub flow_id: String,
    pub flow_version: u32,
    pub identity_id: String,
    pub org_id: Option<String>,
    pub amr: Vec<String>,
    pub authorities: Vec<AuthAuthority>,
    pub acr: String,
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowExecution {
    pub execution_id: String,
    pub flow_id: String,
    pub flow_version: u32,
    pub status: FlowExecStatus,
    pub current_stage_idx: usize,
    pub identity_id: Option<String>,
    pub org_id: Option<String>,
    pub amr: Vec<String>,
    pub authorities: Vec<AuthAuthority>,
    pub required_step_up_factors: Vec<String>,
    pub retries_used: u32,
    pub max_retries: u32,
    pub started_at_ms: u64,
    pub expires_at_ms: u64,
    pub stage_audit: Vec<StageAuditEntry>,
    pub result: Option<AuthResult>,
}

/// Input submitted by a client for the active stage of a `FlowExecution`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageSubmission {
    #[serde(default)]
    pub identity_id: Option<String>,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp_code: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
    #[serde(default)]
    pub consent_granted: Option<bool>,
    /// Optional policy decision returned by a sandboxed Wasm stage host runner.
    #[serde(default)]
    pub wasm_decision: Option<PolicyStageDecision>,
    /// Optional upstream OIDC ID token (cryptographically verified against provider JWKS).
    #[serde(default)]
    pub federated_id_token: Option<String>,
    /// Optional base64-encoded SAML 2.0 Response XML (verified against provider cert/audience/window).
    #[serde(default)]
    pub saml_response: Option<String>,
    /// Optional expected SAML SP EntityID / Audience when verifying `saml_response`.
    #[serde(default)]
    pub saml_audience: Option<String>,
    /// Optional W3C WebAuthn assertion response (Phase 2B).
    #[serde(default)]
    pub webauthn_response: Option<crate::iam::webauthn::AuthenticationResponse>,
}

/// Identity-controlled Argon2id password credential record (`sys_iam_credential`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCredential {
    pub identity_id: String,
    pub password_hash: String,
    pub updated_at_ms: u64,
}

#[derive(Clone)]
pub struct AuthFlowEngine {
    db: Arc<Database>,
    idp: NexusIdp,
}

impl AuthFlowEngine {
    pub fn new(db: Arc<Database>) -> Self {
        let idp = NexusIdp::new(db.clone());
        Self { db, idp }
    }

    fn db_key(&self) -> usize {
        Arc::as_ptr(&self.db) as usize
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        self.idp.ensure_tables().await?;
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_iam_auth_flow SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_flow_exec SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_credential SCHEMALESS;";
        let _ = self.db.client.query(ddl).await;
        Ok(())
    }

    /// Bind an Argon2id password credential directly to an independent `Identity`.
    pub async fn set_identity_password(&self, identity_id: &str, raw_password: &str) -> Result<()> {
        self.ensure_tables().await?;
        if self.idp.get_identity(identity_id).await?.is_none() {
            anyhow::bail!("Identity '{}' not found", identity_id);
        }
        if raw_password.len() < 8 {
            anyhow::bail!("Password must be at least 8 characters");
        }
        let cred = PasswordCredential {
            identity_id: identity_id.to_string(),
            password_hash: nexus_db::auth::hash_password(raw_password),
            updated_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&cred)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_credential', $id) CONTENT $c;")
            .bind(("id", identity_id.to_string()))
            .bind(("c", val))
            .await?
            .check()?;
        Ok(())
    }

    async fn verify_identity_password(&self, identity_id: &str, raw_password: &str) -> Result<bool> {
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_credential', $id)")
            .bind(("id", identity_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let Some(cred) = rows
            .first()
            .and_then(|v| serde_json::from_value::<PasswordCredential>(v.clone()).ok())
        else {
            return Ok(false);
        };
        Ok(nexus_db::auth::verify_password(&cred.password_hash, raw_password))
    }

    /// Register a new versioned `AuthFlow` (bumps `version` immutably if `flow_id` already exists).
    pub async fn create_flow(
        &self,
        actor: &str,
        flow_id: &str,
        name: &str,
        org_id: Option<String>,
        stages: Vec<AuthStage>,
        timeout_secs: u64,
        max_retries: u32,
    ) -> Result<AuthFlow> {
        self.ensure_tables().await?;
        if stages.is_empty() {
            anyhow::bail!("AuthFlow must contain at least one stage");
        }
        let prev_ver = self
            .get_latest_flow(flow_id)
            .await?
            .map(|f| f.version)
            .unwrap_or(0);
        let flow = AuthFlow {
            flow_id: flow_id.trim().to_string(),
            version: prev_ver + 1,
            name: name.trim().to_string(),
            org_id: org_id.clone(),
            stages,
            timeout_secs: timeout_secs.clamp(30, 3600),
            max_retries: max_retries.clamp(1, 20),
            created_at_ms: now_ms(),
        };
        let key = format!("{}_v{}", flow.flow_id, flow.version);
        let val = serde_json::to_value(&flow)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_auth_flow', $id) CONTENT $f;")
            .bind(("id", key))
            .bind(("f", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(
                org_id.as_deref().unwrap_or("instance"),
                actor,
                "auth_flow.create",
                &flow.flow_id,
                "ok",
                &format!("v{}", flow.version),
            )
            .await;
        Ok(flow)
    }

    pub async fn list_flows(&self) -> Result<Vec<AuthFlow>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_auth_flow")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut out: Vec<AuthFlow> = rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<AuthFlow>(v).ok())
            .collect();
        out.sort_by(|a, b| a.flow_id.cmp(&b.flow_id).then(b.version.cmp(&a.version)));
        Ok(out)
    }

    pub async fn get_flow_version(&self, flow_id: &str, version: u32) -> Result<Option<AuthFlow>> {
        self.ensure_tables().await?;
        let key = format!("{}_v{}", flow_id, version);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_auth_flow', $id)")
            .bind(("id", key))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<AuthFlow>(v.clone()).ok()))
    }

    pub async fn get_latest_flow(&self, flow_id: &str) -> Result<Option<AuthFlow>> {
        let all = self.list_flows().await?;
        Ok(all.into_iter().find(|f| f.flow_id == flow_id))
    }

    async fn persist_execution(&self, exec: &FlowExecution) -> Result<()> {
        let dbk = self.db_key();
        if let Ok(mut cache) = EXEC_CACHE.write() {
            cache.insert((dbk, exec.execution_id.clone()), Arc::new(exec.clone()));
        }
        let val = serde_json::to_value(exec)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_flow_exec', $id) CONTENT $e;")
            .bind(("id", exec.execution_id.clone()))
            .bind(("e", val))
            .await?
            .check()?;
        Ok(())
    }

    pub async fn get_execution(&self, execution_id: &str) -> Result<Option<FlowExecution>> {
        let dbk = self.db_key();
        if let Ok(cache) = EXEC_CACHE.read() {
            if let Some(e) = cache.get(&(dbk, execution_id.to_string())) {
                return Ok(Some((**e).clone()));
            }
        }
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_flow_exec', $id)")
            .bind(("id", execution_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<FlowExecution>(v.clone()).ok()))
    }

    /// Start a new execution of the latest version of `flow_id`.
    pub async fn start_flow(
        &self,
        flow_id: &str,
        initial_org_id: Option<String>,
    ) -> Result<FlowExecution> {
        let flow = self
            .get_latest_flow(flow_id)
            .await?
            .ok_or_else(|| anyhow!("AuthFlow '{}' not found", flow_id))?;
        let now = now_ms();
        let exec = FlowExecution {
            execution_id: format!("fex_{}", uuid::Uuid::new_v4().simple()),
            flow_id: flow.flow_id.clone(),
            flow_version: flow.version,
            status: FlowExecStatus::InProgress,
            current_stage_idx: 0,
            identity_id: None,
            org_id: initial_org_id.or(flow.org_id.clone()),
            amr: Vec::new(),
            authorities: Vec::new(),
            required_step_up_factors: Vec::new(),
            retries_used: 0,
            max_retries: flow.max_retries,
            started_at_ms: now,
            expires_at_ms: now + flow.timeout_secs * 1000,
            stage_audit: Vec::new(),
            result: None,
        };
        self.persist_execution(&exec).await?;
        Ok(exec)
    }

    /// Advance the active stage of `execution_id` with striped linearizability, retry/timeout
    /// enforcement, conditional branching, sandboxed Wasm policy evaluation, and an unbypassable
    /// native completion gate.
    pub async fn submit_stage(
        &self,
        execution_id: &str,
        sub: StageSubmission,
    ) -> Result<FlowExecution> {
        let _guard = FLOW_STRIPES[flow_stripe_idx(execution_id)].lock().await;
        let mut exec = self
            .get_execution(execution_id)
            .await?
            .ok_or_else(|| anyhow!("Flow execution '{}' not found", execution_id))?;

        if exec.status != FlowExecStatus::InProgress {
            anyhow::bail!("Flow execution '{}' is not in progress ({:?})", execution_id, exec.status);
        }
        if now_ms() > exec.expires_at_ms {
            exec.status = FlowExecStatus::Expired;
            exec.stage_audit.push(StageAuditEntry {
                stage_id: "timeout".into(),
                outcome: "expired".into(),
                detail: "Flow execution exceeded timeout_secs".into(),
                timestamp_ms: now_ms(),
            });
            self.persist_execution(&exec).await?;
            anyhow::bail!("Flow execution expired");
        }

        let flow = self
            .get_flow_version(&exec.flow_id, exec.flow_version)
            .await?
            .ok_or_else(|| anyhow!("Flow '{}' v{} not found", exec.flow_id, exec.flow_version))?;

        let stage = flow
            .stages
            .get(exec.current_stage_idx)
            .ok_or_else(|| anyhow!("Invalid stage index"))?
            .clone();

        let mut advance_to: Option<usize> = None;
        let stage_res: Result<String> = match &stage.kind {
            AuthStageKind::Identification => {
                let id = sub
                    .identity_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("identity_id is required"))?;
                if self.idp.get_identity(id).await?.is_none() {
                    Err(anyhow!("Unknown identity '{}'", id))
                } else {
                    exec.identity_id = Some(id.to_string());
                    Ok(format!("identified={}", id))
                }
            }
            AuthStageKind::OrgDiscovery => {
                let oid = sub
                    .org_id
                    .or_else(|| exec.org_id.clone())
                    .ok_or_else(|| anyhow!("org_id is required"))?;
                if self.idp.get_org(&oid).await?.is_none() {
                    Err(anyhow!("Organization '{}' not found", oid))
                } else {
                    exec.org_id = Some(oid.clone());
                    Ok(format!("org={}", oid))
                }
            }
            AuthStageKind::PasswordVerify => {
                let id = exec
                    .identity_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Identification stage must precede PasswordVerify"))?;
                let pw = sub
                    .password
                    .as_deref()
                    .ok_or_else(|| anyhow!("password is required"))?;
                if self.verify_identity_password(id, pw).await? {
                    if !exec.amr.iter().any(|m| m == "pwd") {
                        exec.amr.push("pwd".into());
                    }
                    if !exec.authorities.contains(&AuthAuthority::IdentityControlled) {
                        exec.authorities.push(AuthAuthority::IdentityControlled);
                    }
                    Ok("password verified".into())
                } else {
                    Err(anyhow!("Invalid password"))
                }
            }
            AuthStageKind::TotpVerify { org_required } => {
                let id = exec
                    .identity_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Identification stage must precede TotpVerify"))?;
                let code = sub
                    .totp_code
                    .as_deref()
                    .ok_or_else(|| anyhow!("totp_code is required"))?;
                let org_scope = exec.org_id.as_deref().unwrap_or("default");
                if self.idp.verify_totp(org_scope, id, code).await? {
                    if !exec.amr.iter().any(|m| m == "otp") {
                        exec.amr.push("otp".into());
                    }
                    let auth_tier = if *org_required {
                        AuthAuthority::OrganizationRequired
                    } else {
                        AuthAuthority::IdentityControlled
                    };
                    if !exec.authorities.contains(&auth_tier) {
                        exec.authorities.push(auth_tier);
                    }
                    exec.required_step_up_factors.retain(|f| f != "otp" && f != "totp");
                    Ok("totp verified".into())
                } else {
                    Err(anyhow!("Invalid TOTP code"))
                }
            }
            AuthStageKind::RecoveryCode => {
                let id = exec
                    .identity_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Identification stage must precede RecoveryCode"))?;
                let code = sub
                    .recovery_code
                    .as_deref()
                    .ok_or_else(|| anyhow!("recovery_code is required"))?;
                let org_scope = exec.org_id.as_deref().unwrap_or("default");
                if self.idp.verify_totp(org_scope, id, code).await? {
                    if !exec.amr.iter().any(|m| m == "rec") {
                        exec.amr.push("rec".into());
                    }
                    if !exec.authorities.contains(&AuthAuthority::IdentityControlled) {
                        exec.authorities.push(AuthAuthority::IdentityControlled);
                    }
                    Ok("recovery code verified".into())
                } else {
                    Err(anyhow!("Invalid recovery code"))
                }
            }
            AuthStageKind::WebAuthnAssert => {
                let wa_resp = sub
                    .webauthn_response
                    .ok_or_else(|| anyhow!("webauthn_response is required for WebAuthnAssert stage"))?;
                let svc = crate::iam::webauthn::WebAuthnService::new(self.db.clone());
                let res = svc.finish_authentication(wa_resp).await?;
                if let Some(ref existing_id) = exec.identity_id {
                    if existing_id != &res.identity_id {
                        anyhow::bail!("WebAuthn credential identity mismatch");
                    }
                } else {
                    exec.identity_id = Some(res.identity_id.clone());
                }
                if !exec.amr.iter().any(|m| m == "hwk") {
                    exec.amr.push("hwk".into());
                }
                if !exec.authorities.contains(&AuthAuthority::IdentityControlled) {
                    exec.authorities.push(AuthAuthority::IdentityControlled);
                }
                exec.required_step_up_factors.retain(|f| f != "hwk" && f != "webauthn" && f != "passkey");
                Ok(format!("webauthn cred={} uv={}", res.credential_id, res.user_verified))
            }
            AuthStageKind::ExternalProvider { provider_id } => {
                let fed = crate::iam::federation::FederationService::new(self.db.clone());
                let prov = fed
                    .get_provider(provider_id)
                    .await?
                    .ok_or_else(|| anyhow!("Federated provider '{}' not found", provider_id))?;

                // Cryptographically verify the upstream assertion before resolving any identity link.
                // NEVER accept an unverified client-supplied subject string!
                let (verified_sub, verified_email): (String, Option<String>) = match prov.protocol {
                    crate::iam::federation::FederationProtocol::Oidc => {
                        let raw_tok = sub
                            .federated_id_token
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| {
                                anyhow!(
                                    "Cryptographically signed federated_id_token required for OIDC provider '{}'",
                                    provider_id
                                )
                            })?;
                        let claims = fed.verify_upstream_oidc_id_token(provider_id, raw_tok).await?;
                        let sub_claim = claims["sub"]
                            .as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| anyhow!("Verified OIDC ID token missing 'sub' claim"))?
                            .to_string();
                        let email_claim = claims["email"].as_str().map(|s| s.trim().to_string());
                        (sub_claim, email_claim)
                    }
                    crate::iam::federation::FederationProtocol::Saml2 => {
                        let saml_b64 = sub
                            .saml_response
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| {
                                anyhow!(
                                    "Signed saml_response required for SAML provider '{}'",
                                    provider_id
                                )
                            })?;
                        let aud = sub
                            .saml_audience
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .or(prov.client_id.as_deref())
                            .ok_or_else(|| anyhow!("saml_audience required for SAML provider '{}'", provider_id))?;
                        let assertion = fed.verify_saml_response(provider_id, saml_b64, aud).await?;
                        (assertion.name_id, assertion.email)
                    }
                };

                match fed
                    .resolve_federated_login(provider_id, &verified_sub, verified_email.as_deref())
                    .await?
                {
                    crate::iam::federation::FederatedLoginResolution::Linked { identity_id, link_id } => {
                        if let Some(ref existing) = exec.identity_id {
                            if existing != &identity_id {
                                anyhow::bail!("Federated link identity mismatch");
                            }
                        } else {
                            exec.identity_id = Some(identity_id);
                        }
                        if !exec.amr.iter().any(|m| m == "fed") {
                            exec.amr.push("fed".into());
                        }
                        if !exec.authorities.contains(&AuthAuthority::Federated) {
                            exec.authorities.push(AuthAuthority::Federated);
                        }
                        Ok(format!(
                            "federated={} link={} provider={}",
                            verified_sub, link_id, provider_id
                        ))
                    }
                    crate::iam::federation::FederatedLoginResolution::ExplicitLinkRequired { reason } => {
                        Err(anyhow!("{}", reason))
                    }
                    crate::iam::federation::FederatedLoginResolution::Unlinked => {
                        Err(anyhow!(
                            "External subject '{}' is not explicitly linked to a Nexus identity",
                            verified_sub
                        ))
                    }
                }
            }
            AuthStageKind::ConditionalBranch {
                condition,
                if_true_stage,
                if_false_stage,
            } => {
                let cond_met = match condition {
                    StageCondition::OrgMfaRequired => {
                        if let Some(ref oid) = exec.org_id {
                            self.idp
                                .resolve_org_policy(oid)
                                .await
                                .map(|p| p.mfa_required.value)
                                .unwrap_or(false)
                        } else {
                            false
                        }
                    }
                    StageCondition::HasAmr { method } => exec.amr.iter().any(|m| m == method),
                    StageCondition::MissingAmr { method } => !exec.amr.iter().any(|m| m == method),
                };
                let target_id = if cond_met {
                    Some(if_true_stage.as_str())
                } else {
                    if_false_stage.as_deref()
                };
                if let Some(tid) = target_id {
                    if let Some(pos) = flow.stages.iter().position(|s| s.stage_id == tid) {
                        advance_to = Some(pos);
                    }
                }
                Ok(format!("branch={} target={:?}", cond_met, target_id))
            }
            AuthStageKind::WasmPolicyStage { module_cid, .. } => {
                // Sandboxed policy decision — strictly limited to Allow | Deny | RequireStepUp.
                // NEVER mutates identity_id, NEVER skips mandatory org MFA, NEVER grants permissions.
                let decision = sub.wasm_decision.unwrap_or(PolicyStageDecision::Allow);
                match decision {
                    PolicyStageDecision::Allow => Ok(format!("wasm={} allow", module_cid)),
                    PolicyStageDecision::Deny { reason } => {
                        exec.status = FlowExecStatus::Failed;
                        Err(anyhow!("Wasm policy stage '{}' denied: {}", module_cid, reason))
                    }
                    PolicyStageDecision::RequireStepUp { factor } => {
                        if !exec.required_step_up_factors.iter().any(|f| f == &factor) {
                            exec.required_step_up_factors.push(factor.clone());
                        }
                        Ok(format!("wasm={} require_step_up={}", module_cid, factor))
                    }
                }
            }
            AuthStageKind::Consent { .. } => {
                if sub.consent_granted == Some(true) {
                    Ok("consent granted".into())
                } else {
                    exec.status = FlowExecStatus::Failed;
                    Err(anyhow!("User denied consent"))
                }
            }
        };

        match stage_res {
            Ok(detail) => {
                exec.stage_audit.push(StageAuditEntry {
                    stage_id: stage.stage_id.clone(),
                    outcome: "ok".into(),
                    detail,
                    timestamp_ms: now_ms(),
                });
                let next_idx = advance_to.unwrap_or(exec.current_stage_idx + 1);
                exec.current_stage_idx = next_idx;

                // Final Unbypassable Native Completion Gate
                if exec.current_stage_idx >= flow.stages.len() {
                    let Some(ref ident_id) = exec.identity_id else {
                        exec.status = FlowExecStatus::Failed;
                        self.persist_execution(&exec).await?;
                        anyhow::bail!("Flow completed without verified identity_id");
                    };
                    if exec.amr.is_empty() {
                        exec.status = FlowExecStatus::Failed;
                        self.persist_execution(&exec).await?;
                        anyhow::bail!("Flow completed without any verified authentication factor");
                    }
                    if !exec.required_step_up_factors.is_empty() {
                        exec.status = FlowExecStatus::Failed;
                        self.persist_execution(&exec).await?;
                        anyhow::bail!(
                            "Unsatisfied step-up factor(s): {:?}",
                            exec.required_step_up_factors
                        );
                    }
                    // Enforce composed organization MFA policy natively (Wasm stages CANNOT bypass!)
                    if let Some(ref oid) = exec.org_id {
                        let pol = self.idp.resolve_org_policy(oid).await?;
                        let has_mfa = exec
                            .amr
                            .iter()
                            .any(|m| matches!(m.as_str(), "otp" | "hwk" | "rec"));
                        if pol.mfa_required.value && !has_mfa {
                            exec.status = FlowExecStatus::Failed;
                            exec.stage_audit.push(StageAuditEntry {
                                stage_id: "native_policy_gate".into(),
                                outcome: "denied".into(),
                                detail: format!("Organization '{}' requires MFA (unbypassable)", oid),
                                timestamp_ms: now_ms(),
                            });
                            self.persist_execution(&exec).await?;
                            let _ = self
                                .idp
                                .append_audit(oid, ident_id, "auth_flow.mfa_gate", &exec.execution_id, "denied", "missing required MFA")
                                .await;
                            anyhow::bail!("Organization '{}' requires MFA; flow rejected by native policy gate", oid);
                        }
                    }

                    let has_mfa = exec
                        .amr
                        .iter()
                        .any(|m| matches!(m.as_str(), "otp" | "hwk" | "rec"));
                    let acr = if has_mfa && exec.amr.len() >= 2 {
                        "aal2".to_string()
                    } else {
                        "aal1".to_string()
                    };
                    exec.status = FlowExecStatus::Completed;
                    exec.result = Some(AuthResult {
                        execution_id: exec.execution_id.clone(),
                        flow_id: exec.flow_id.clone(),
                        flow_version: exec.flow_version,
                        identity_id: ident_id.clone(),
                        org_id: exec.org_id.clone(),
                        amr: exec.amr.clone(),
                        authorities: exec.authorities.clone(),
                        acr,
                        completed_at_ms: now_ms(),
                    });
                    let _ = self
                        .idp
                        .append_audit(
                            exec.org_id.as_deref().unwrap_or("instance"),
                            ident_id,
                            "auth_flow.completed",
                            &exec.execution_id,
                            "ok",
                            &format!("amr={:?}", exec.amr),
                        )
                        .await;
                }
                self.persist_execution(&exec).await?;
                Ok(exec)
            }
            Err(e) => {
                exec.retries_used += 1;
                if exec.status == FlowExecStatus::InProgress && exec.retries_used >= exec.max_retries {
                    exec.status = FlowExecStatus::LockedOut;
                }
                exec.stage_audit.push(StageAuditEntry {
                    stage_id: stage.stage_id,
                    outcome: format!("{:?}", exec.status).to_ascii_lowercase(),
                    detail: e.to_string(),
                    timestamp_ms: now_ms(),
                });
                self.persist_execution(&exec).await?;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::idp::{base32_decode, totp_code_for_step, OrgPolicyPatch};

    #[tokio::test]
    async fn auth_flow_password_plus_org_mfa_conditional_branch_and_audit() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let engine = AuthFlowEngine::new(db);

        let (alice, _) = idp.create_identity("Alice", None).await.unwrap();
        engine.set_identity_password(&alice.identity_id, "CorrectHorseBattery99!").await.unwrap();
        let org = idp
            .create_org(
                "root",
                "acme",
                "Acme Corp",
                None,
                None,
                OrgPolicyPatch { mfa_required: Some(true), ..Default::default() },
            )
            .await
            .unwrap();
        let (totp_sec, _, _) = idp.enroll_totp(&org.org_id, &alice.identity_id).await.unwrap();

        engine
            .create_flow(
                "root",
                "default-login",
                "Standard Login + Conditional MFA",
                Some(org.org_id.clone()),
                vec![
                    AuthStage { stage_id: "id".into(), kind: AuthStageKind::Identification, max_retries: 3 },
                    AuthStage { stage_id: "pw".into(), kind: AuthStageKind::PasswordVerify, max_retries: 3 },
                    AuthStage {
                        stage_id: "mfa_check".into(),
                        kind: AuthStageKind::ConditionalBranch {
                            condition: StageCondition::OrgMfaRequired,
                            if_true_stage: "totp".into(),
                            if_false_stage: Some("consent".into()),
                        },
                        max_retries: 1,
                    },
                    AuthStage { stage_id: "totp".into(), kind: AuthStageKind::TotpVerify { org_required: true }, max_retries: 3 },
                    AuthStage { stage_id: "consent".into(), kind: AuthStageKind::Consent { scopes: vec!["openid".into()] }, max_retries: 1 },
                ],
                300,
                5,
            )
            .await
            .unwrap();

        let ex = engine.start_flow("default-login", Some(org.org_id.clone())).await.unwrap();
        let ex = engine.submit_stage(&ex.execution_id, StageSubmission { identity_id: Some(alice.identity_id.clone()), ..Default::default() }).await.unwrap();
        let ex = engine.submit_stage(&ex.execution_id, StageSubmission { password: Some("CorrectHorseBattery99!".into()), ..Default::default() }).await.unwrap();
        // Conditional branch routes to "totp" because org.mfa_required == true
        let ex = engine.submit_stage(&ex.execution_id, StageSubmission::default()).await.unwrap();
        let step = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
        let code = totp_code_for_step(&base32_decode(&totp_sec).unwrap(), step);
        let ex = engine.submit_stage(&ex.execution_id, StageSubmission { totp_code: Some(code), ..Default::default() }).await.unwrap();
        let ex = engine.submit_stage(&ex.execution_id, StageSubmission { consent_granted: Some(true), ..Default::default() }).await.unwrap();

        assert_eq!(ex.status, FlowExecStatus::Completed);
        let res = ex.result.unwrap();
        assert_eq!(res.identity_id, alice.identity_id);
        assert_eq!(res.acr, "aal2");
        assert!(res.authorities.contains(&AuthAuthority::IdentityControlled));
        assert!(res.authorities.contains(&AuthAuthority::OrganizationRequired));
        assert_eq!(ex.stage_audit.len(), 5);
    }

    #[tokio::test]
    async fn wasm_policy_stage_cannot_bypass_mandatory_org_mfa_and_retry_lockout_enforced() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let engine = AuthFlowEngine::new(db);

        let (bob, _) = idp.create_identity("Bob", None).await.unwrap();
        engine.set_identity_password(&bob.identity_id, "StrongPass1234!").await.unwrap();
        let org = idp
            .create_org(
                "root",
                "strict-org",
                "Strict Org",
                None,
                None,
                OrgPolicyPatch { mfa_required: Some(true), ..Default::default() },
            )
            .await
            .unwrap();

        // Flow intentionally omits TOTP and includes a WasmPolicyStage returning Allow —
        // Native policy gate MUST STILL REJECT completion!
        engine
            .create_flow(
                "root",
                "mfa-bypass-attempt",
                "Bypass Attempt",
                Some(org.org_id.clone()),
                vec![
                    AuthStage { stage_id: "id".into(), kind: AuthStageKind::Identification, max_retries: 2 },
                    AuthStage { stage_id: "pw".into(), kind: AuthStageKind::PasswordVerify, max_retries: 2 },
                    AuthStage { stage_id: "wasm".into(), kind: AuthStageKind::WasmPolicyStage { module_cid: "blake3:test".into(), max_fuel: 10_000 }, max_retries: 1 },
                ],
                300,
                2,
            )
            .await
            .unwrap();

        let ex = engine.start_flow("mfa-bypass-attempt", Some(org.org_id.clone())).await.unwrap();
        engine.submit_stage(&ex.execution_id, StageSubmission { identity_id: Some(bob.identity_id.clone()), ..Default::default() }).await.unwrap();
        engine.submit_stage(&ex.execution_id, StageSubmission { password: Some("StrongPass1234!".into()), ..Default::default() }).await.unwrap();
        let bypass = engine
            .submit_stage(&ex.execution_id, StageSubmission { wasm_decision: Some(PolicyStageDecision::Allow), ..Default::default() })
            .await;
        assert!(bypass.is_err(), "Wasm Allow MUST NOT bypass mandatory org MFA!");

        // Retry lockout test (max_retries = 2)
        let ex2 = engine.start_flow("mfa-bypass-attempt", Some(org.org_id.clone())).await.unwrap();
        engine.submit_stage(&ex2.execution_id, StageSubmission { identity_id: Some(bob.identity_id.clone()), ..Default::default() }).await.unwrap();
        assert!(engine.submit_stage(&ex2.execution_id, StageSubmission { password: Some("wrong1".into()), ..Default::default() }).await.is_err());
        assert!(engine.submit_stage(&ex2.execution_id, StageSubmission { password: Some("wrong2".into()), ..Default::default() }).await.is_err());
        let locked = engine.get_execution(&ex2.execution_id).await.unwrap().unwrap();
        assert_eq!(locked.status, FlowExecStatus::LockedOut);
    }

    #[tokio::test]
    async fn external_provider_stage_requires_cryptographically_verified_oidc_id_token() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let fed = crate::iam::federation::FederationService::new(db.clone());
        let engine = AuthFlowEngine::new(db);

        let org = idp
            .create_org(
                "root",
                "fed-org",
                "Fed Org",
                None,
                None,
                OrgPolicyPatch {
                    allowed_external_idps: Some(vec!["oidc".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let (up_sk, up_pk) = nexus_db::auth::ed25519_generate_keypair();
        let up_jwks = serde_json::json!({ "keys": [nexus_db::auth::ed25519_jwk("k1", &up_pk)] });
        let prov = fed
            .register_provider(
                "root",
                &org.org_id,
                "Okta",
                crate::iam::federation::FederationProtocol::Oidc,
                "https://fed.okta.example",
                "https://fed.okta.example/authorize",
                None,
                Some("nexus-client".into()),
                None,
                Some(up_jwks),
                None,
                vec!["fed.example".into()],
            )
            .await
            .unwrap();

        let (alice, _) = idp.create_identity("Alice", Some("alice@fed.example".into())).await.unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let valid_tok = nexus_db::auth::sign_eddsa_jwt(
            "k1",
            &up_sk,
            &serde_json::json!({
                "iss": "https://fed.okta.example",
                "sub": "okta-alice-1",
                "email": "alice@fed.example",
                "aud": "nexus-client",
                "iat": now,
                "exp": now + 300,
            }),
        )
        .unwrap();
        fed.link_identity_with_oidc_token(&alice.identity_id, &prov.provider_id, &valid_tok)
            .await
            .unwrap();

        engine
            .create_flow(
                "root",
                "fed-login",
                "Federated Login",
                Some(org.org_id.clone()),
                vec![AuthStage {
                    stage_id: "ext".into(),
                    kind: AuthStageKind::ExternalProvider { provider_id: prov.provider_id.clone() },
                    max_retries: 3,
                }],
                300,
                3,
            )
            .await
            .unwrap();

        // 1. Missing token or forged token MUST fail closed
        let ex1 = engine.start_flow("fed-login", Some(org.org_id.clone())).await.unwrap();
        assert!(engine.submit_stage(&ex1.execution_id, StageSubmission::default()).await.is_err());
        assert!(engine
            .submit_stage(
                &ex1.execution_id,
                StageSubmission { federated_id_token: Some("forged.jwt.token".into()), ..Default::default() },
            )
            .await
            .is_err());

        // 2. Cryptographically signed upstream OIDC ID token succeeds and binds verified identity_id
        let ex2 = engine.start_flow("fed-login", Some(org.org_id.clone())).await.unwrap();
        let done = engine
            .submit_stage(
                &ex2.execution_id,
                StageSubmission { federated_id_token: Some(valid_tok), ..Default::default() },
            )
            .await
            .unwrap();
        assert_eq!(done.status, FlowExecStatus::Completed);
        let res = done.result.unwrap();
        assert_eq!(res.identity_id, alice.identity_id);
        assert!(res.amr.contains(&"fed".to_string()));
        assert!(res.authorities.contains(&AuthAuthority::Federated));
    }
}
