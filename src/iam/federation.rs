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

    /// Explicitly link `(provider.issuer, external_subject)` to a verified `NEXUS-ID-v1` identity.
    /// Refuses hijacking an `(issuer, external_subject)` already linked to another identity.
    pub async fn link_identity(
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

        // Explicit authenticated link resolves cleanly & prevents hijacking by another identity
        let link = fed
            .link_identity(&alice.identity_id, &alice.identity_id, &prov.provider_id, "okta_sub_999", Some("alice@corp.example".into()))
            .await
            .unwrap();
        let (bob, _) = idp.create_identity("Bob", None).await.unwrap();
        assert!(fed
            .link_identity(&bob.identity_id, &bob.identity_id, &prov.provider_id, "okta_sub_999", None)
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

        // Upstream OIDC EdDSA ID token verification
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let up_tok = nexus_db::auth::sign_eddsa_jwt(
            "up_k1",
            &up_sk,
            &serde_json::json!({
                "iss": "https://corp.okta.com",
                "sub": "okta_sub_999",
                "aud": "nexus_sp_1",
                "iat": now,
                "exp": now + 300,
            }),
        )
        .unwrap();
        let claims = fed.verify_upstream_oidc_id_token(&prov.provider_id, &up_tok).await.unwrap();
        assert_eq!(claims["sub"], "okta_sub_999");

        // SAML 2.0 SP Metadata XML
        let xml = FederationService::saml_sp_metadata_xml("https://nexus.aerea.co/saml", "https://nexus.aerea.co/_nexus/iam/saml/acs");
        assert!(xml.contains("EntityDescriptor") && xml.contains("AssertionConsumerService"));
    }
}
