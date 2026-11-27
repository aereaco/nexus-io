//! Phase 2D: Sessions, Device Trust, Contextual Step-Up MFA & Cross-Cluster Trust Policies
//!
//! Core Security Invariants:
//! 1. **Identity-Wide vs. Organization-Scoped Sessions:** Personal `IdentityWide` sessions
//!    are strictly isolated from `Organization { org_id }` sessions. Revoking an organization
//!    membership or org session NEVER terminates the holder's personal `IdentityWide` session.
//! 2. **Composed Org Policy Enforcement:** Organization-scoped sessions clamp their lifetime to
//!    `ComposedOrgPolicy.max_session_ttl_secs` and enforce `mfa_required`.
//! 3. **ZCZS Hot Session Cache:** Active `nxss_*` session tokens live in a typed
//!    `Arc<LiveSessionEntry>` + `AtomicBool` cache (zero JSON/SurrealQL on hot validation,
//!    instant atomic cross-thread revocation).
//! 4. **Cross-Cluster Trust != Identity Authenticity:** Cryptographically valid `NEXUS-ID-v1`
//!    portable packages still require explicit local `ClusterTrustPolicy` evaluation.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Database;
use crate::iam::flows::AuthResult;
use crate::iam::idp::{verify_identity_package, NexusIdp, PortableIdentityPackage};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hash_token(raw: &str) -> String {
    blake3::hash(raw.as_bytes()).to_hex().to_string()
}

fn acr_rank(acr: &str) -> u8 {
    match acr.to_ascii_lowercase().as_str() {
        "aal3" => 3,
        "aal2" => 2,
        "aal1" => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionScope {
    IdentityWide,
    Organization { org_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub token_hash: String,
    pub identity_id: String,
    pub scope: SessionScope,
    #[serde(default)]
    pub device_id: Option<String>,
    pub amr: Vec<String>,
    pub acr: String,
    pub revoked: bool,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpEvaluation {
    pub satisfied: bool,
    pub current_acr: String,
    pub required_acr: String,
    pub missing_mfa: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustLevel {
    Untrusted,
    Verified,
    Managed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub identity_id: String,
    pub label: String,
    pub fingerprint_hash: String,
    pub trust_level: DeviceTrustLevel,
    pub revoked: bool,
    pub registered_at_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTrustPolicy {
    pub cluster_id: String,
    pub issuer: String,
    pub root_pubkey: String,
    pub allow_portable_import: bool,
    pub require_local_mfa: bool,
    pub enabled: bool,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTrustDecision {
    pub trusted: bool,
    pub cluster_id: String,
    pub identity_id: String,
    pub require_local_mfa: bool,
    pub reason: String,
}

struct LiveSessionEntry {
    record: SessionRecord,
    revoked: AtomicBool,
}

static SESSION_CACHE: Lazy<RwLock<HashMap<(usize, String), Arc<LiveSessionEntry>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Clone)]
pub struct SessionService {
    db: Arc<Database>,
    idp: NexusIdp,
}

impl SessionService {
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
            DEFINE TABLE IF NOT EXISTS sys_iam_session SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_device SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_cluster_trust SCHEMALESS;";
        let _ = self.db.client.query(ddl).await;
        Ok(())
    }

    async fn persist_session(&self, rec: &SessionRecord) -> Result<()> {
        let dbk = self.db_key();
        let entry = Arc::new(LiveSessionEntry {
            record: rec.clone(),
            revoked: AtomicBool::new(rec.revoked),
        });
        if let Ok(mut cache) = SESSION_CACHE.write() {
            cache.insert((dbk, rec.token_hash.clone()), entry);
        }
        let val = serde_json::to_value(rec)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_session', $id) CONTENT $s;")
            .bind(("id", rec.session_id.clone()))
            .bind(("s", val))
            .await?
            .check()?;
        Ok(())
    }

    /// Issue an `IdentityWide` or `Organization`-scoped session from a verified `AuthResult`.
    /// Organization-scoped sessions clamp TTL to `ComposedOrgPolicy.max_session_ttl_secs`
    /// and enforce `mfa_required`.
    pub async fn issue_session(
        &self,
        auth: &AuthResult,
        scope: SessionScope,
        device_id: Option<String>,
        requested_ttl_secs: u64,
    ) -> Result<(SessionRecord, String)> {
        self.ensure_tables().await?;
        let mut effective_ttl = requested_ttl_secs.clamp(60, 30 * 86_400);

        if let SessionScope::Organization { ref org_id } = scope {
            let pol = self.idp.resolve_org_policy(org_id).await?;
            effective_ttl = effective_ttl.min(pol.max_session_ttl_secs.value);
            let has_mfa = auth
                .amr
                .iter()
                .any(|m| matches!(m.as_str(), "otp" | "hwk" | "rec"));
            if pol.mfa_required.value && !has_mfa {
                anyhow::bail!(
                    "Organization '{}' requires MFA before issuing an org-scoped session",
                    org_id
                );
            }
        }

        let raw_token = format!(
            "nxss_{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let now = now_ms();
        let rec = SessionRecord {
            session_id: format!("ses_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
            token_hash: hash_token(&raw_token),
            identity_id: auth.identity_id.clone(),
            scope: scope.clone(),
            device_id,
            amr: auth.amr.clone(),
            acr: auth.acr.clone(),
            revoked: false,
            created_at_ms: now,
            expires_at_ms: now + effective_ttl * 1000,
        };
        self.persist_session(&rec).await?;
        let audit_org = match &scope {
            SessionScope::IdentityWide => "instance",
            SessionScope::Organization { org_id } => org_id.as_str(),
        };
        let _ = self
            .idp
            .append_audit(
                audit_org,
                &auth.identity_id,
                "session.create",
                &rec.session_id,
                "ok",
                &format!("acr={} ttl={}", rec.acr, effective_ttl),
            )
            .await;
        Ok((rec, raw_token))
    }

    /// ZCZS hot-path session validation (zero JSON/SurrealQL on cache hit).
    pub async fn validate_session(&self, raw_token: &str) -> Result<Option<SessionRecord>> {
        let thash = hash_token(raw_token);
        let dbk = self.db_key();
        if let Ok(cache) = SESSION_CACHE.read() {
            if let Some(entry) = cache.get(&(dbk, thash.clone())) {
                if entry.revoked.load(Ordering::Acquire) || now_ms() > entry.record.expires_at_ms {
                    return Ok(None);
                }
                return Ok(Some(entry.record.clone()));
            }
        }
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_session").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        for v in rows {
            if let Ok(rec) = serde_json::from_value::<SessionRecord>(v) {
                if rec.token_hash == thash {
                    let entry = Arc::new(LiveSessionEntry {
                        record: rec.clone(),
                        revoked: AtomicBool::new(rec.revoked),
                    });
                    if let Ok(mut cache) = SESSION_CACHE.write() {
                        cache.insert((dbk, thash), entry);
                    }
                    if rec.revoked || now_ms() > rec.expires_at_ms {
                        return Ok(None);
                    }
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }

    pub async fn list_sessions(&self, identity_id: &str) -> Result<Vec<SessionRecord>> {
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_session").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<SessionRecord>(v).ok())
            .filter(|s| s.identity_id == identity_id && !s.revoked && now_ms() <= s.expires_at_ms)
            .collect())
    }

    pub async fn revoke_session(&self, actor: &str, session_id: &str) -> Result<bool> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_session', $id)")
            .bind(("id", session_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        if let Some(mut rec) = rows
            .first()
            .and_then(|v| serde_json::from_value::<SessionRecord>(v.clone()).ok())
        {
            rec.revoked = true;
            self.persist_session(&rec).await?;
            let _ = self
                .idp
                .append_audit("instance", actor, "session.revoke", session_id, "ok", &rec.identity_id)
                .await;
            return Ok(true);
        }
        Ok(false)
    }

    /// Revoke ONLY organization-scoped sessions for `(identity_id, org_id)`.
    /// Personal `IdentityWide` sessions remain completely unaffected!
    pub async fn revoke_org_sessions(
        &self,
        actor: &str,
        identity_id: &str,
        org_id: &str,
    ) -> Result<usize> {
        let active = self.list_sessions(identity_id).await?;
        let mut count = 0usize;
        for mut ses in active {
            if ses.scope == (SessionScope::Organization { org_id: org_id.to_string() }) {
                ses.revoked = true;
                self.persist_session(&ses).await?;
                count += 1;
            }
        }
        let _ = self
            .idp
            .append_audit(
                org_id,
                actor,
                "session.revoke_org",
                identity_id,
                "ok",
                &format!("revoked={}", count),
            )
            .await;
        Ok(count)
    }

    /// Evaluate whether a session meets a contextual step-up assurance requirement (`aal2` / `aal3`).
    pub fn evaluate_step_up(session: &SessionRecord, required_acr: &str) -> StepUpEvaluation {
        let cur = acr_rank(&session.acr);
        let req = acr_rank(required_acr);
        let has_mfa = session
            .amr
            .iter()
            .any(|m| matches!(m.as_str(), "otp" | "hwk" | "rec"));
        let satisfied = cur >= req && (req < 2 || has_mfa);
        StepUpEvaluation {
            satisfied,
            current_acr: session.acr.clone(),
            required_acr: required_acr.to_string(),
            missing_mfa: req >= 2 && !has_mfa,
        }
    }

    /// Upgrade a live session's assurance level after a verified step-up factor (`otp` / `hwk`).
    pub async fn upgrade_session_step_up(
        &self,
        session_id: &str,
        factor: &str,
        new_acr: &str,
    ) -> Result<SessionRecord> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_session', $id)")
            .bind(("id", session_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut rec: SessionRecord = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Session '{}' not found", session_id))?;
        if rec.revoked || now_ms() > rec.expires_at_ms {
            anyhow::bail!("Cannot step-up a revoked or expired session");
        }
        if !rec.amr.iter().any(|m| m == factor) {
            rec.amr.push(factor.to_string());
        }
        if acr_rank(new_acr) > acr_rank(&rec.acr) {
            rec.acr = new_acr.to_string();
        }
        self.persist_session(&rec).await?;
        let _ = self
            .idp
            .append_audit("instance", &rec.identity_id, "session.step_up", session_id, "ok", &rec.acr)
            .await;
        Ok(rec)
    }

    // -------------------------------------------------------------------------
    // Device Registration & Trust
    // -------------------------------------------------------------------------

    pub async fn register_device(
        &self,
        identity_id: &str,
        label: &str,
        fingerprint: &str,
        trust_level: DeviceTrustLevel,
    ) -> Result<DeviceRecord> {
        self.ensure_tables().await?;
        let now = now_ms();
        let dev = DeviceRecord {
            device_id: format!("dev_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
            identity_id: identity_id.to_string(),
            label: label.trim().to_string(),
            fingerprint_hash: hash_token(fingerprint),
            trust_level,
            revoked: false,
            registered_at_ms: now,
            last_seen_ms: now,
        };
        let val = serde_json::to_value(&dev)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_device', $id) CONTENT $d;")
            .bind(("id", dev.device_id.clone()))
            .bind(("d", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit("instance", identity_id, "device.register", &dev.device_id, "ok", &dev.label)
            .await;
        Ok(dev)
    }

    pub async fn list_devices(&self, identity_id: &str) -> Result<Vec<DeviceRecord>> {
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_device").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<DeviceRecord>(v).ok())
            .filter(|d| d.identity_id == identity_id && !d.revoked)
            .collect())
    }

    /// Revoke a device AND immediately revoke all active sessions bound to that device.
    pub async fn revoke_device(&self, actor: &str, identity_id: &str, device_id: &str) -> Result<bool> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_device', $id)")
            .bind(("id", device_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let Some(mut dev) = rows
            .first()
            .and_then(|v| serde_json::from_value::<DeviceRecord>(v.clone()).ok())
        else {
            return Ok(false);
        };
        if dev.identity_id != identity_id {
            anyhow::bail!("Device does not belong to identity '{}'", identity_id);
        }
        dev.revoked = true;
        let val = serde_json::to_value(&dev)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_device', $id) CONTENT $d;")
            .bind(("id", dev.device_id.clone()))
            .bind(("d", val))
            .await?
            .check()?;

        // Revoke all active sessions bound to this device
        for mut ses in self.list_sessions(identity_id).await? {
            if ses.device_id.as_deref() == Some(device_id) {
                ses.revoked = true;
                self.persist_session(&ses).await?;
            }
        }
        let _ = self
            .idp
            .append_audit("instance", actor, "device.revoke", device_id, "ok", identity_id)
            .await;
        Ok(true)
    }

    // -------------------------------------------------------------------------
    // Cross-Cluster Trust Policy
    // -------------------------------------------------------------------------

    pub async fn register_trusted_cluster(
        &self,
        actor: &str,
        cluster_id: &str,
        issuer: &str,
        root_pubkey: &str,
        allow_portable_import: bool,
        require_local_mfa: bool,
    ) -> Result<ClusterTrustPolicy> {
        self.ensure_tables().await?;
        let pol = ClusterTrustPolicy {
            cluster_id: cluster_id.trim().to_string(),
            issuer: issuer.trim().to_string(),
            root_pubkey: root_pubkey.trim().to_string(),
            allow_portable_import,
            require_local_mfa,
            enabled: true,
            created_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&pol)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_cluster_trust', $id) CONTENT $p;")
            .bind(("id", pol.cluster_id.clone()))
            .bind(("p", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit("instance", actor, "trust.cluster.register", &pol.cluster_id, "ok", &pol.issuer)
            .await;
        Ok(pol)
    }

    pub async fn list_trusted_clusters(&self) -> Result<Vec<ClusterTrustPolicy>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_cluster_trust")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ClusterTrustPolicy>(v).ok())
            .collect())
    }

    /// Evaluate whether a cryptographically valid portable identity from `source_cluster_id`
    /// is trusted by this cluster's local `ClusterTrustPolicy`.
    pub async fn evaluate_cluster_trust(
        &self,
        source_cluster_id: &str,
        pkg: &PortableIdentityPackage,
    ) -> Result<ClusterTrustDecision> {
        verify_identity_package(pkg)?;
        let clusters = self.list_trusted_clusters().await?;
        let Some(pol) = clusters
            .into_iter()
            .find(|c| c.cluster_id == source_cluster_id && c.enabled)
        else {
            return Ok(ClusterTrustDecision {
                trusted: false,
                cluster_id: source_cluster_id.into(),
                identity_id: pkg.identity_id.clone(),
                require_local_mfa: true,
                reason: "Identity is cryptographically authentic, but source cluster is not in local trust allowlist".into(),
            });
        };
        if !pol.allow_portable_import {
            return Ok(ClusterTrustDecision {
                trusted: false,
                cluster_id: source_cluster_id.into(),
                identity_id: pkg.identity_id.clone(),
                require_local_mfa: pol.require_local_mfa,
                reason: "Source cluster policy prohibits portable identity import".into(),
            });
        }
        Ok(ClusterTrustDecision {
            trusted: true,
            cluster_id: source_cluster_id.into(),
            identity_id: pkg.identity_id.clone(),
            require_local_mfa: pol.require_local_mfa,
            reason: "Authentic NEXUS-ID-v1 package accepted under local cluster trust policy".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::flows::AuthAuthority;
    use crate::iam::idp::OrgPolicyPatch;

    #[tokio::test]
    async fn identity_vs_org_session_isolation_step_up_device_revocation_and_cluster_trust() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let svc = SessionService::new(db);

        let (alice, sk0) = idp.create_identity("Alice", None).await.unwrap();
        let org = idp
            .create_org(
                "root",
                "bank",
                "Acme Bank",
                None,
                None,
                OrgPolicyPatch {
                    mfa_required: Some(true),
                    max_session_ttl_secs: Some(1800),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let dev = svc
            .register_device(&alice.identity_id, "MacBook Pro", "fp-mbp-1", DeviceTrustLevel::Verified)
            .await
            .unwrap();

        let aal1_auth = AuthResult {
            execution_id: "fex_1".into(),
            flow_id: "login".into(),
            flow_version: 1,
            identity_id: alice.identity_id.clone(),
            org_id: None,
            amr: vec!["pwd".into()],
            authorities: vec![AuthAuthority::IdentityControlled],
            acr: "aal1".into(),
            completed_at_ms: now_ms(),
        };

        // 1. Personal IdentityWide session succeeds at AAL1; org session requiring MFA MUST fail at AAL1!
        let (personal_ses, personal_tok) = svc
            .issue_session(&aal1_auth, SessionScope::IdentityWide, Some(dev.device_id.clone()), 7200)
            .await
            .unwrap();
        assert!(svc
            .issue_session(
                &aal1_auth,
                SessionScope::Organization { org_id: org.org_id.clone() },
                Some(dev.device_id.clone()),
                7200,
            )
            .await
            .is_err());

        // Step-up check on personal session: requires aal2 -> unsatisfied until upgraded
        assert!(!SessionService::evaluate_step_up(&personal_ses, "aal2").satisfied);
        let upgraded = svc
            .upgrade_session_step_up(&personal_ses.session_id, "otp", "aal2")
            .await
            .unwrap();
        assert!(SessionService::evaluate_step_up(&upgraded, "aal2").satisfied);

        // 2. Org-scoped session at AAL2 succeeds & clamps TTL to org's max_session_ttl_secs (1800s)
        let aal2_auth = AuthResult {
            amr: vec!["pwd".into(), "otp".into()],
            acr: "aal2".into(),
            org_id: Some(org.org_id.clone()),
            ..aal1_auth
        };
        let (org_ses, org_tok) = svc
            .issue_session(
                &aal2_auth,
                SessionScope::Organization { org_id: org.org_id.clone() },
                Some(dev.device_id.clone()),
                86_400,
            )
            .await
            .unwrap();
        assert!(org_ses.expires_at_ms - org_ses.created_at_ms <= 1_800_000);

        // 3. Revoking org sessions invalidates org_tok while preserving personal_tok!
        assert_eq!(svc.revoke_org_sessions("root", &alice.identity_id, &org.org_id).await.unwrap(), 1);
        assert!(svc.validate_session(&org_tok).await.unwrap().is_none());
        assert!(svc.validate_session(&personal_tok).await.unwrap().is_some());

        // 4. Revoking the device revokes the remaining personal session bound to it!
        assert!(svc.revoke_device(&alice.identity_id, &alice.identity_id, &dev.device_id).await.unwrap());
        assert!(svc.validate_session(&personal_tok).await.unwrap().is_none());

        // 5. Cross-cluster trust: authentic portable package is NOT trusted until source cluster is allowlisted!
        let pkg = idp.export_identity_package(&alice.identity_id, &sk0).await.unwrap();
        assert!(!svc.evaluate_cluster_trust("home-cluster-1", &pkg).await.unwrap().trusted);
        svc.register_trusted_cluster("root", "home-cluster-1", "https://home.nexus", "pk_home", true, true)
            .await
            .unwrap();
        let dec = svc.evaluate_cluster_trust("home-cluster-1", &pkg).await.unwrap();
        assert!(dec.trusted);
        assert!(dec.require_local_mfa);
    }
}
