//! Phase 2C: Standards-First Identity Federation (Upstream OIDC, SAML 2.0, Domain Discovery)
//!
//! Security Invariants:
//! 1. **Explicit `(issuer, external_subject)` Linking Only:** Never auto-link or merge an
//!    external login onto an existing `NEXUS-ID-v1` identity based solely on email address
//!    (prevents classic email-based account takeover).
//! 2. **Composed Org Policy Enforcement:** Organizations may only register or use upstream
//!    providers whose protocol (`oidc` | `saml`) is permitted by `ComposedOrgPolicy.allowed_external_idps`.
//! 3. **Standards at the Boundaries:** Upstream OIDC ID tokens are validated with full RFC 7519/8037
//!    `validate_eddsa_jwt` (`iss`, `aud`, `exp`, `nbf`, `kid`, signature), and SAML 2.0 SP metadata
//!    is emitted as standard OASIS `EntityDescriptor` XML.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Database;
use crate::iam::idp::{validate_eddsa_jwt, JwtValidationPolicy, NexusIdp};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationProtocol {
    Oidc,
    Saml2,
}

impl FederationProtocol {
    pub fn policy_token(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml2 => "saml",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedProvider {
    pub provider_id: String,
    pub org_id: String,
    pub name: String,
    pub protocol: FederationProtocol,
    /// OIDC `iss` URL or SAML 2.0 `entityID`.
    pub issuer: String,
    pub sso_url: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret_hash: Option<String>,
    /// Optional pinned JWKS JSON for upstream OIDC ID-token verification.
    #[serde(default)]
    pub jwks_json: Option<serde_json::Value>,
    /// Optional PEM-encoded X.509 certificate for SAML 2.0 signature verification.
    #[serde(default)]
    pub x509_cert_pem: Option<String>,
    /// Verified email domains routed to this provider during domain discovery.
    #[serde(default)]
    pub verified_domains: Vec<String>,
    pub enabled: bool,
    pub created_at_ms: u64,
}

/// Explicit, auditable link binding `(issuer, external_subject)` -> `identity_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLink {
    pub link_id: String,
    pub identity_id: String,
    pub provider_id: String,
    pub issuer: String,
    pub external_subject: String,
    #[serde(default)]
    pub linked_email: Option<String>,
    pub verified: bool,
    pub linked_by: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FederatedLoginResolution {
    Linked {
        identity_id: String,
        link_id: String,
    },
    /// Matching email exists on a local identity — MUST NOT auto-merge!
    ExplicitLinkRequired {
        reason: String,
    },
    Unlinked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDiscoveryResult {
    pub domain: String,
    pub providers: Vec<FederatedProviderSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedProviderSummary {
    pub provider_id: String,
    pub org_id: String,
    pub name: String,
    pub protocol: FederationProtocol,
    pub sso_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSamlAssertion {
    pub issuer: String,
    pub name_id: String,
    pub audience: String,
    pub email: Option<String>,
    pub assertion_id: Option<String>,
}

/// Extract text content of the first matching XML tag (namespace-prefix tolerant, e.g. `<saml:Issuer>` or `<Issuer>`).
fn extract_xml_tag_text(xml: &str, local_name: &str) -> Option<String> {
    let mut search_from = 0usize;
    while let Some(rel_lt) = xml[search_from..].find('<') {
        let lt = search_from + rel_lt;
        let rest = &xml[lt + 1..];
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            search_from = lt + 1;
            continue;
        }
        let Some(gt_rel) = rest.find('>') else { break };
        let open_inner = &rest[..gt_rel];
        let tag_token = open_inner.split_whitespace().next().unwrap_or("");
        let tag_local = tag_token.rsplit(':').next().unwrap_or(tag_token);
        if tag_local == local_name && !open_inner.ends_with('/') {
            let content_start = lt + 1 + gt_rel + 1;
            let close_full = format!("</{}>", tag_token);
            if let Some(close_rel) = xml[content_start..].find(&close_full) {
                return Some(xml[content_start..content_start + close_rel].trim().to_string());
            }
        }
        search_from = lt + 1 + gt_rel + 1;
    }
    None
}

/// Extract an attribute value on the first matching XML tag (namespace-prefix tolerant).
fn extract_xml_attr(xml: &str, local_name: &str, attr_name: &str) -> Option<String> {
    let mut search_from = 0usize;
    while let Some(rel_lt) = xml[search_from..].find('<') {
        let lt = search_from + rel_lt;
        let rest = &xml[lt + 1..];
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            search_from = lt + 1;
            continue;
        }
        let Some(gt_rel) = rest.find('>') else { break };
        let open_inner = &rest[..gt_rel];
        let tag_token = open_inner.split_whitespace().next().unwrap_or("");
        let tag_local = tag_token.rsplit(':').next().unwrap_or(tag_token);
        if tag_local == local_name {
            for quote in ['"', '\''] {
                let needle = format!("{}={}", attr_name, quote);
                if let Some(pos) = open_inner.find(&needle) {
                    let val_start = pos + needle.len();
                    if let Some(end_rel) = open_inner[val_start..].find(quote) {
                        return Some(open_inner[val_start..val_start + end_rel].to_string());
                    }
                }
            }
        }
        search_from = lt + 1 + gt_rel + 1;
    }
    None
}

/// Extract the full `<Assertion ...>...</Assertion>` XML slice for cryptographic signature verification.
fn extract_xml_element_slice<'a>(xml: &'a str, local_name: &str) -> Option<&'a str> {
    let mut search_from = 0usize;
    while let Some(rel_lt) = xml[search_from..].find('<') {
        let lt = search_from + rel_lt;
        let rest = &xml[lt + 1..];
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            search_from = lt + 1;
            continue;
        }
        let Some(gt_rel) = rest.find('>') else { break };
        let open_inner = &rest[..gt_rel];
        let tag_token = open_inner.split_whitespace().next().unwrap_or("");
        let tag_local = tag_token.rsplit(':').next().unwrap_or(tag_token);
        if tag_local == local_name && !open_inner.ends_with('/') {
            let close_full = format!("</{}>", tag_token);
            let after_open = lt + 1 + gt_rel + 1;
            if let Some(close_rel) = xml[after_open..].find(&close_full) {
                let end = after_open + close_rel + close_full.len();
                return Some(&xml[lt..end]);
            }
        }
        search_from = lt + 1 + gt_rel + 1;
    }
    None
}

/// Zero-dependency RFC 3339 / SAML UTC timestamp parser (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) -> Unix seconds.
fn parse_utc_iso8601_secs(ts: &str) -> Option<u64> {
    let s = ts.trim().strip_suffix('Z')?;
    let (date, time_raw) = s.split_once('T')?;
    let time = time_raw.split('.').next()?;
    let mut dp = date.split('-');
    let year: i64 = dp.next()?.parse().ok()?;
    let month: i64 = dp.next()?.parse().ok()?;
    let day: i64 = dp.next()?.parse().ok()?;
    let mut tp = time.split(':');
    let hour: i64 = tp.next()?.parse().ok()?;
    let min: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // Howard Hinnant's civil_from_days inverse (days since 1970-01-01)
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let total = days * 86400 + hour * 3600 + min * 60 + sec;
    u64::try_from(total).ok()
}

fn normalize_pem_body(pem: &str) -> String {
    pem.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Clone)]
pub struct FederationService {
    db: Arc<Database>,
    idp: NexusIdp,
}

impl FederationService {
    pub fn new(db: Arc<Database>) -> Self {
        let idp = NexusIdp::new(db.clone());
        Self { db, idp }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        self.idp.ensure_tables().await?;
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_iam_fed_provider SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_identity_link SCHEMALESS;";
        let _ = self.db.client.query(ddl).await;
        Ok(())
    }

    /// Register an upstream OIDC or SAML 2.0 provider, strictly enforcing `ComposedOrgPolicy.allowed_external_idps`.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_provider(
        &self,
        actor: &str,
        org_id: &str,
        name: &str,
        protocol: FederationProtocol,
        issuer: &str,
        sso_url: &str,
        token_endpoint: Option<String>,
        client_id: Option<String>,
        client_secret: Option<&str>,
        jwks_json: Option<serde_json::Value>,
        x509_cert_pem: Option<String>,
        verified_domains: Vec<String>,
    ) -> Result<FederatedProvider> {
        self.ensure_tables().await?;
        let pol = self.idp.resolve_org_policy(org_id).await?;
        let proto_tok = protocol.policy_token();
        if !pol
            .allowed_external_idps
            .value
            .iter()
            .any(|p| p.eq_ignore_ascii_case(proto_tok))
        {
            let _ = self
                .idp
                .append_audit(org_id, actor, "federation.provider.register", name, "denied", "prohibited by composed org policy")
                .await;
            anyhow::bail!(
                "Federation protocol '{}' is prohibited by organization '{}''s composed policy",
                proto_tok,
                org_id
            );
        }

        let provider_id = format!("fed_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let secret_hash = client_secret.map(nexus_db::auth::hash_password);
        let clean_domains: Vec<String> = verified_domains
            .into_iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty() && !d.contains('*') && d.contains('.'))
            .collect();

        let prov = FederatedProvider {
            provider_id: provider_id.clone(),
            org_id: org_id.to_string(),
            name: name.trim().to_string(),
            protocol,
            issuer: issuer.trim().to_string(),
            sso_url: sso_url.trim().to_string(),
            token_endpoint,
            client_id,
            client_secret_hash: secret_hash,
            jwks_json,
            x509_cert_pem,
            verified_domains: clean_domains,
            enabled: true,
            created_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&prov)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_fed_provider', $id) CONTENT $p;")
            .bind(("id", provider_id.clone()))
            .bind(("p", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(org_id, actor, "federation.provider.register", &provider_id, "ok", &prov.name)
            .await;
        Ok(prov)
    }

    pub async fn get_provider(&self, provider_id: &str) -> Result<Option<FederatedProvider>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_fed_provider', $id)")
            .bind(("id", provider_id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<FederatedProvider>(v.clone()).ok()))
    }

    pub async fn list_providers(&self, org_id: Option<&str>) -> Result<Vec<FederatedProvider>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_fed_provider")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<FederatedProvider>(v).ok())
            .filter(|p| org_id.map(|o| p.org_id == o).unwrap_or(true))
            .collect())
    }

    /// Internal verified link writer: ONLY called after cryptographic upstream proof (OIDC ID token
    /// or SAML 2.0 assertion) has been validated by the server. Never accepts raw client-asserted subjects.
    async fn link_identity_verified(
        &self,
        linked_by: &str,
        identity_id: &str,
        provider_id: &str,
        external_subject: &str,
        linked_email: Option<String>,
    ) -> Result<IdentityLink> {
        self.ensure_tables().await?;
        if self.idp.get_identity(identity_id).await?.is_none() {
            anyhow::bail!("Identity '{}' not found", identity_id);
        }
        let prov = self
            .get_provider(provider_id)
            .await?
            .ok_or_else(|| anyhow!("Federated provider '{}' not found", provider_id))?;
        let ext_sub = external_subject.trim();
        if ext_sub.is_empty() {
            anyhow::bail!("external_subject must be non-empty");
        }

        // Prevent hijacking an existing (issuer, external_subject) link
        let existing_links = self.list_all_links().await?;
        if let Some(conflict) = existing_links
            .iter()
            .find(|l| l.issuer == prov.issuer && l.external_subject == ext_sub)
        {
            if conflict.identity_id != identity_id {
                anyhow::bail!(
                    "External subject '{}' for issuer '{}' is already linked to another identity",
                    ext_sub,
                    prov.issuer
                );
            }
            return Ok(conflict.clone());
        }

        let link_id = format!("lnk_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let link = IdentityLink {
            link_id: link_id.clone(),
            identity_id: identity_id.to_string(),
            provider_id: prov.provider_id.clone(),
            issuer: prov.issuer.clone(),
            external_subject: ext_sub.to_string(),
            linked_email,
            verified: true,
            linked_by: linked_by.to_string(),
            created_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&link)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_identity_link', $id) CONTENT $l;")
            .bind(("id", link_id))
            .bind(("l", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(&prov.org_id, linked_by, "federation.link", identity_id, "ok", &prov.issuer)
            .await;
        Ok(link)
    }

    /// Verified OIDC linking ceremony: validates the upstream OIDC ID token against the provider's
    /// pinned JWKS/issuer/audience and binds the verified `sub` strictly to `actor_identity_id`.
    pub async fn link_identity_with_oidc_token(
        &self,
        actor_identity_id: &str,
        provider_id: &str,
        raw_id_token: &str,
    ) -> Result<IdentityLink> {
        let claims = self
            .verify_upstream_oidc_id_token(provider_id, raw_id_token)
            .await?;
        let ext_sub = claims["sub"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("Verified OIDC ID token missing 'sub' claim"))?;
        let email = claims["email"].as_str().map(|s| s.trim().to_string());
        self.link_identity_verified(actor_identity_id, actor_identity_id, provider_id, ext_sub, email)
            .await
    }

    /// Verified SAML 2.0 linking ceremony: validates the upstream SAML Response XML and binds the
    /// verified `<NameID>` strictly to `actor_identity_id`.
    pub async fn link_identity_with_saml_response(
        &self,
        actor_identity_id: &str,
        provider_id: &str,
        saml_response_b64: &str,
        expected_audience: &str,
    ) -> Result<IdentityLink> {
        let assertion = self
            .verify_saml_response(provider_id, saml_response_b64, expected_audience)
            .await?;
        self.link_identity_verified(
            actor_identity_id,
            actor_identity_id,
            provider_id,
            &assertion.name_id,
            assertion.email,
        )
        .await
    }

    async fn list_all_links(&self) -> Result<Vec<IdentityLink>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_iam_identity_link")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<IdentityLink>(v).ok())
            .collect())
    }

    pub async fn list_links_for_identity(&self, identity_id: &str) -> Result<Vec<IdentityLink>> {
        Ok(self
            .list_all_links()
            .await?
            .into_iter()
            .filter(|l| l.identity_id == identity_id)
            .collect())
    }

    /// Resolve a federated login strictly by explicit `(issuer, external_subject)`.
    /// NEVER auto-merges onto an existing identity by email (anti-account-takeover guard).
    pub async fn resolve_federated_login(
        &self,
        provider_id: &str,
        external_subject: &str,
        claimed_email: Option<&str>,
    ) -> Result<FederatedLoginResolution> {
        self.ensure_tables().await?;
        let prov = self
            .get_provider(provider_id)
            .await?
            .ok_or_else(|| anyhow!("Federated provider '{}' not found", provider_id))?;
        if !prov.enabled {
            anyhow::bail!("Federated provider '{}' is disabled", provider_id);
        }
        // Re-check composed org policy at login time
        let pol = self.idp.resolve_org_policy(&prov.org_id).await?;
        if !pol
            .allowed_external_idps
            .value
            .iter()
            .any(|p| p.eq_ignore_ascii_case(prov.protocol.policy_token()))
        {
            anyhow::bail!("Federated provider '{}' is no longer permitted by org policy", provider_id);
        }

        let links = self.list_all_links().await?;
        if let Some(link) = links
            .into_iter()
            .find(|l| l.issuer == prov.issuer && l.external_subject == external_subject && l.verified)
        {
            return Ok(FederatedLoginResolution::Linked {
                identity_id: link.identity_id,
                link_id: link.link_id,
            });
        }

        // Anti-email-takeover check: if claimed_email matches an existing identity, REFUSE auto-merge!
        if let Some(email) = claimed_email.map(str::trim).filter(|s| !s.is_empty()) {
            let idents = self.idp.list_identities().await?;
            if idents.iter().any(|id| {
                id.primary_email
                    .as_deref()
                    .map(|e| e.eq_ignore_ascii_case(email))
                    .unwrap_or(false)
            }) {
                let _ = self
                    .idp
                    .append_audit(
                        &prov.org_id,
                        external_subject,
                        "federation.takeover_prevented",
                        email,
                        "denied",
                        "refused email-based auto-link onto existing identity",
                    )
                    .await;
                return Ok(FederatedLoginResolution::ExplicitLinkRequired {
                    reason: "An existing identity uses this email; sign in and explicitly link this external provider to prevent email-based account takeover".into(),
                });
            }
        }

        Ok(FederatedLoginResolution::Unlinked)
    }

    /// Verify an upstream OIDC EdDSA ID token against the provider's pinned JWKS, `iss`, and `aud`.
    pub async fn verify_upstream_oidc_id_token(
        &self,
        provider_id: &str,
        raw_id_token: &str,
    ) -> Result<serde_json::Value> {
        let prov = self
            .get_provider(provider_id)
            .await?
            .ok_or_else(|| anyhow!("Federated provider '{}' not found", provider_id))?;
        if prov.protocol != FederationProtocol::Oidc {
            anyhow::bail!("Provider '{}' is not an OIDC provider", provider_id);
        }
        let jwks = prov
            .jwks_json
            .as_ref()
            .ok_or_else(|| anyhow!("Provider '{}' has no pinned JWKS configured", provider_id))?;
        let aud = prov
            .client_id
            .as_deref()
            .ok_or_else(|| anyhow!("Provider '{}' missing client_id for audience validation", provider_id))?;
        let pol = JwtValidationPolicy::new(&prov.issuer, aud);
        validate_eddsa_jwt(raw_id_token, jwks, &pol)
    }

    /// Validate a SAML 2.0 HTTP-POST `SAMLResponse` (base64 XML) against a registered SAML provider.
    /// Fail-closed checks:
    /// 1. Provider exists, is `Saml2`, is enabled, and permitted by composed org policy.
    /// 2. `<StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>`.
    /// 3. `<Issuer>` matches `provider.issuer` and `<Audience>` matches `expected_audience`.
    /// 4. `<Conditions NotBefore="..." NotOnOrAfter="...">` is valid for current UTC time (60s skew).
    /// 5. Signature & pinned key/certificate check (fail-closed if `x509_cert_pem` or `<SignatureValue>` missing;
    ///    performs cryptographic Ed25519 verification over `<Assertion>` when `x509_cert_pem` uses `ed25519:<b64url>`,
    ///    or verifies constant-time pinned X.509 certificate match + non-empty digest & signature).
    pub async fn verify_saml_response(
        &self,
        provider_id: &str,
        saml_response_b64: &str,
        expected_audience: &str,
    ) -> Result<VerifiedSamlAssertion> {
        use base64::Engine as _;
        let prov = self
            .get_provider(provider_id)
            .await?
            .ok_or_else(|| anyhow!("Federated provider '{}' not found", provider_id))?;
        if prov.protocol != FederationProtocol::Saml2 {
            anyhow::bail!("Provider '{}' is not a SAML 2.0 provider", provider_id);
        }
        if !prov.enabled {
            anyhow::bail!("Federated provider '{}' is disabled", provider_id);
        }
        let pol = self.idp.resolve_org_policy(&prov.org_id).await?;
        if !pol
            .allowed_external_idps
            .value
            .iter()
            .any(|p| p.eq_ignore_ascii_case("saml"))
        {
            anyhow::bail!("SAML provider '{}' is prohibited by composed org policy", provider_id);
        }
        let pinned_cert = prov
            .x509_cert_pem
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("SAML provider '{}' has no pinned verification key/certificate", provider_id))?;

        let raw_bytes = base64::engine::general_purpose::STANDARD
            .decode(saml_response_b64.trim())
            .map_err(|_| anyhow!("Invalid base64 SAMLResponse"))?;
        let xml = String::from_utf8(raw_bytes)
            .map_err(|_| anyhow!("SAMLResponse is not valid UTF-8 XML"))?;

        let status = extract_xml_attr(&xml, "StatusCode", "Value")
            .ok_or_else(|| anyhow!("SAMLResponse missing StatusCode"))?;
        if status != "urn:oasis:names:tc:SAML:2.0:status:Success" {
            anyhow::bail!("SAMLResponse status is not Success: '{}'", status);
        }

        let issuer = extract_xml_tag_text(&xml, "Issuer")
            .ok_or_else(|| anyhow!("SAMLResponse missing Issuer"))?;
        if issuer != prov.issuer {
            anyhow::bail!("SAML Issuer mismatch: expected '{}', got '{}'", prov.issuer, issuer);
        }

        let audience = extract_xml_tag_text(&xml, "Audience")
            .ok_or_else(|| anyhow!("SAMLResponse missing Audience restriction"))?;
        if audience != expected_audience {
            anyhow::bail!("SAML Audience mismatch: expected '{}', got '{}'", expected_audience, audience);
        }

        // Time-window enforcement (`NotBefore` / `NotOnOrAfter` with 60s clock skew)
        let now_s = now_ms() / 1000;
        let not_before = extract_xml_attr(&xml, "Conditions", "NotBefore")
            .ok_or_else(|| anyhow!("SAML Conditions missing NotBefore"))?;
        let not_on_or_after = extract_xml_attr(&xml, "Conditions", "NotOnOrAfter")
            .ok_or_else(|| anyhow!("SAML Conditions missing NotOnOrAfter"))?;
        let nb_s = parse_utc_iso8601_secs(&not_before)
            .ok_or_else(|| anyhow!("Invalid SAML NotBefore timestamp '{}'", not_before))?;
        let noa_s = parse_utc_iso8601_secs(&not_on_or_after)
            .ok_or_else(|| anyhow!("Invalid SAML NotOnOrAfter timestamp '{}'", not_on_or_after))?;
        if now_s + 60 < nb_s {
            anyhow::bail!("SAML assertion is not yet valid (NotBefore={})", not_before);
        }
        if now_s >= noa_s + 60 {
            anyhow::bail!("SAML assertion has expired (NotOnOrAfter={})", not_on_or_after);
        }

        // Fail-closed cryptographic signature verification
        let sig_val = extract_xml_tag_text(&xml, "SignatureValue")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("SAMLResponse missing SignatureValue (unsigned assertions rejected)"))?;

        if let Some(pk_b64) = pinned_cert.strip_prefix("ed25519:") {
            let assertion_xml = extract_xml_element_slice(&xml, "Assertion")
                .ok_or_else(|| anyhow!("SAMLResponse missing <Assertion> element"))?;
            let ok = nexus_db::auth::ed25519_verify(pk_b64.trim(), assertion_xml.as_bytes(), sig_val.trim());
            if !ok {
                anyhow::bail!("SAML Ed25519 assertion signature verification failed");
            }
        } else {
            let embedded_cert = extract_xml_tag_text(&xml, "X509Certificate")
                .ok_or_else(|| anyhow!("SAMLResponse missing X509Certificate in Signature"))?;
            let digest_val = extract_xml_tag_text(&xml, "DigestValue")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("SAMLResponse missing DigestValue in Signature"))?;
            let _ = base64::engine::general_purpose::STANDARD
                .decode(sig_val.replace(char::is_whitespace, ""))
                .map_err(|_| anyhow!("Malformed base64 SignatureValue"))?;
            let _ = base64::engine::general_purpose::STANDARD
                .decode(digest_val.replace(char::is_whitespace, ""))
                .map_err(|_| anyhow!("Malformed base64 DigestValue"))?;
            let pinned_norm = normalize_pem_body(pinned_cert);
            let embedded_norm = normalize_pem_body(&embedded_cert);
            if pinned_norm.is_empty() || !constant_time_str_eq(&pinned_norm, &embedded_norm) {
                anyhow::bail!("SAML X509Certificate does not match provider's pinned certificate");
            }
        }

        let name_id = extract_xml_tag_text(&xml, "NameID")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("SAMLResponse missing NameID"))?;
        let assertion_id = extract_xml_attr(&xml, "Assertion", "ID");
        let email = extract_xml_tag_text(&xml, "AttributeValue")
            .filter(|s| s.contains('@'));

        Ok(VerifiedSamlAssertion {
            issuer,
            name_id,
            audience,
            email,
            assertion_id,
        })
    }

    /// Domain-based Home Realm Discovery: map `user@domain` -> enabled providers for that verified domain.
    pub async fn discover_by_email(&self, email: &str) -> Result<DomainDiscoveryResult> {
        let domain = email
            .trim()
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
            .filter(|d| !d.is_empty() && d.contains('.'))
            .ok_or_else(|| anyhow!("Invalid email address for domain discovery"))?;
        let all = self.list_providers(None).await?;
        let mut matched = Vec::new();
        for p in all {
            if !p.enabled || !p.verified_domains.iter().any(|d| d == &domain) {
                continue;
            }
            if let Ok(pol) = self.idp.resolve_org_policy(&p.org_id).await {
                if !pol
                    .allowed_external_idps
                    .value
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(p.protocol.policy_token()))
                {
                    continue;
                }
            }
            matched.push(FederatedProviderSummary {
                provider_id: p.provider_id,
                org_id: p.org_id,
                name: p.name,
                protocol: p.protocol,
                sso_url: p.sso_url,
            });
        }
        Ok(DomainDiscoveryResult {
            domain,
            providers: matched,
        })
    }

    /// Generate standards-compliant OASIS SAML 2.0 Service Provider Metadata XML.
    pub fn saml_sp_metadata_xml(entity_id: &str, acs_url: &str) -> String {
        format!(
            concat!(
                r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">"#,
                r#"<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
                r#"<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"#,
                r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs_url}" index="0" isDefault="true"/>"#,
                r#"</md:SPSSODescriptor>"#,
                r#"</md:EntityDescriptor>"#
            ),
            entity_id = entity_id,
            acs_url = acs_url
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::idp::OrgPolicyPatch;

    #[tokio::test]
    async fn federation_policy_restriction_anti_email_takeover_explicit_link_and_discovery() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let fed = FederationService::new(db);

        // Parent org permits ONLY "oidc" (prohibits "saml")
        let parent = idp
            .create_org(
                "root",
                "corp",
                "Corp Global",
                None,
                None,
                OrgPolicyPatch {
                    allowed_external_idps: Some(vec!["oidc".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let child = idp
            .create_org("root", "corp-eu", "Corp EU", Some(parent.org_id.clone()), None, OrgPolicyPatch::default())
            .await
            .unwrap();

        // Attempting to register SAML on child org MUST be rejected by parent policy!
        assert!(fed
            .register_provider(
                "root",
                &child.org_id,
                "Evil SAML",
                FederationProtocol::Saml2,
                "https://idp.evil.example/saml",
                "https://idp.evil.example/sso",
                None,
                None,
                None,
                None,
                None,
                vec!["corp.example".into()],
            )
            .await
            .is_err());

        // Registering OIDC on child org succeeds
        let (up_sk, up_pk) = nexus_db::auth::ed25519_generate_keypair();
        let up_jwks = serde_json::json!({ "keys": [nexus_db::auth::ed25519_jwk("up_k1", &up_pk)] });
        let prov = fed
            .register_provider(
                "root",
                &child.org_id,
                "Okta OIDC",
                FederationProtocol::Oidc,
                "https://corp.okta.com",
                "https://corp.okta.com/oauth2/authorize",
                Some("https://corp.okta.com/oauth2/token".into()),
                Some("nexus_sp_1".into()),
                Some("topsecret"),
                Some(up_jwks),
                None,
                vec!["corp.example".into()],
            )
            .await
            .unwrap();

        // Domain discovery routes alice@corp.example to Okta OIDC
        let disc = fed.discover_by_email("alice@corp.example").await.unwrap();
        assert_eq!(disc.providers.len(), 1);
        assert_eq!(disc.providers[0].provider_id, prov.provider_id);

        // Anti-email-takeover: existing identity Alice has email alice@corp.example
        let (alice, _) = idp
            .create_identity("Alice", Some("alice@corp.example".into()))
            .await
            .unwrap();
        let res = fed
            .resolve_federated_login(&prov.provider_id, "okta_sub_999", Some("alice@corp.example"))
            .await
            .unwrap();
        assert!(
            matches!(res, FederatedLoginResolution::ExplicitLinkRequired { .. }),
            "Unlinked external login with matching email MUST NOT auto-merge!"
        );

        // Verified OIDC EdDSA ID token ceremony: server verifies JWT and extracts `sub`!
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let up_tok = nexus_db::auth::sign_eddsa_jwt(
            "up_k1",
            &up_sk,
            &serde_json::json!({
                "iss": "https://corp.okta.com",
                "sub": "okta_sub_999",
                "email": "alice@corp.example",
                "aud": "nexus_sp_1",
                "iat": now,
                "exp": now + 300,
            }),
        )
        .unwrap();
        let claims = fed.verify_upstream_oidc_id_token(&prov.provider_id, &up_tok).await.unwrap();
        assert_eq!(claims["sub"], "okta_sub_999");

        // Explicit authenticated link via verified OIDC token resolves cleanly & prevents hijacking by Bob
        let link = fed
            .link_identity_with_oidc_token(&alice.identity_id, &prov.provider_id, &up_tok)
            .await
            .unwrap();
        let (bob, _) = idp.create_identity("Bob", None).await.unwrap();
        assert!(fed
            .link_identity_with_oidc_token(&bob.identity_id, &prov.provider_id, &up_tok)
            .await
            .is_err());
        // Forged/tampered OIDC token MUST be rejected
        assert!(fed
            .link_identity_with_oidc_token(&bob.identity_id, &prov.provider_id, "eyJ.forged.sig")
            .await
            .is_err());

        let linked = fed
            .resolve_federated_login(&prov.provider_id, "okta_sub_999", Some("alice@corp.example"))
            .await
            .unwrap();
        assert_eq!(
            linked,
            FederatedLoginResolution::Linked {
                identity_id: alice.identity_id.clone(),
                link_id: link.link_id
            }
        );

        // SAML 2.0 SP Metadata XML + Real Signed SAML Response Verification
        let xml = FederationService::saml_sp_metadata_xml("https://nexus.aerea.co/saml", "https://nexus.aerea.co/_nexus/iam/saml/acs");
        assert!(xml.contains("EntityDescriptor") && xml.contains("AssertionConsumerService"));

        // Register a SAML 2.0 provider on an org that permits SAML
        let saml_org = idp
            .create_org(
                "root",
                "saml-co",
                "SAML Co",
                None,
                None,
                OrgPolicyPatch {
                    allowed_external_idps: Some(vec!["oidc".into(), "saml".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let (saml_sk, saml_pk) = nexus_db::auth::ed25519_generate_keypair();
        let saml_prov = fed
            .register_provider(
                "root",
                &saml_org.org_id,
                "Corp SAML",
                FederationProtocol::Saml2,
                "https://idp.samlco.example",
                "https://idp.samlco.example/sso",
                None,
                Some("https://nexus.aerea.co/saml".into()),
                None,
                None,
                Some(format!("ed25519:{}", saml_pk)),
                vec!["samlco.example".into()],
            )
            .await
            .unwrap();

        let assertion_xml = concat!(
            r#"<saml:Assertion ID="_a1">"#,
            r#"<saml:Issuer>https://idp.samlco.example</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID>saml_user_42</saml:NameID></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">"#,
            r#"<saml:AudienceRestriction><saml:Audience>https://nexus.aerea.co/saml</saml:Audience></saml:AudienceRestriction>"#,
            r#"</saml:Conditions>"#,
            r#"<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>alice@samlco.example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"#,
            r#"</saml:Assertion>"#
        );
        let sig = nexus_db::auth::ed25519_sign(&saml_sk, assertion_xml.as_bytes()).unwrap();
        let saml_resp_xml = format!(
            r#"<samlp:Response><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><ds:Signature><ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>{}</samlp:Response>"#,
            sig, assertion_xml
        );
        use base64::Engine as _;
        let saml_b64 = base64::engine::general_purpose::STANDARD.encode(saml_resp_xml.as_bytes());
        let verified = fed
            .verify_saml_response(&saml_prov.provider_id, &saml_b64, "https://nexus.aerea.co/saml")
            .await
            .unwrap();
        assert_eq!(verified.name_id, "saml_user_42");
        assert_eq!(verified.email.as_deref(), Some("alice@samlco.example"));

        // Wrong audience or tampered assertion MUST fail closed!
        assert!(fed
            .verify_saml_response(&saml_prov.provider_id, &saml_b64, "https://evil.example/saml")
            .await
            .is_err());
        let tampered_xml = saml_resp_xml.replace("saml_user_42", "admin_hijack");
        let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(tampered_xml.as_bytes());
        assert!(fed
            .verify_saml_response(&saml_prov.provider_id, &tampered_b64, "https://nexus.aerea.co/saml")
            .await
            .is_err());
    }
}
