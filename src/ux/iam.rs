//! Canonical Nexus-IO Authentication & Authorization Middleware.
//!
//! Replaces legacy session-table queries with a single security boundary backed by
//! `nexus_db::auth::AuthContext`. Resolves credentials once, attaches `AuthContext` and a
//! correlation `request_id` (`X-Request-Id`) to Salvo's `Depot`, and fails closed by default.

use nexus_db::auth::{AuthContext, AuthLevel, Role};
use salvo::prelude::*;
use std::sync::Arc;

use crate::db::Database;
use crate::observability::global_metrics;
use crate::ux::surreal_http::{extract_ns_db, resolve_http_auth};

/// Unified HTTP authentication resolver fusing:
/// 1. Nexus-IDP OAuth 2.1 `nxat_*` tokens (via ZCZS hot cache) + `OrgMembership` permissions,
/// 2. RFC 8037 `EdDSA` JWTs verified against cluster JWKS (`validate_eddsa_jwt`), and
/// 3. Existing `nexus-db` `DEFINE USER` / HS256 JWT / `nxb_*` / Basic / session-cookie auth.
pub async fn resolve_unified_http_auth(
    req: &Request,
    db: &Arc<Database>,
    ns: &str,
    database: &str,
    allow_local_dev_bypass: bool,
) -> Result<Option<AuthContext>, String> {
    let bearer_opt = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
        .map(str::trim);

    // 1. Fast ZCZS path for Nexus-IDP OAuth 2.1 `nxat_*` tokens
    if let Some(bearer) = bearer_opt {
        if bearer.starts_with("nxat_") {
            let idp = crate::iam::idp::NexusIdp::new(db.clone());
            if let Ok(Some(rec)) = idp.introspect_token(bearer).await {
                let mut roles: Vec<Role> = rec
                    .roles
                    .iter()
                    .filter_map(|r| Role::parse(r))
                    .collect();
                if roles.is_empty() {
                    roles.push(Role::Viewer);
                }
                let is_admin = roles.contains(&Role::Owner);
                let perms = idp
                    .effective_permissions_for_org(&rec.subject, is_admin, &rec.org_id)
                    .await
                    .unwrap_or_default();
                return Ok(Some(AuthContext {
                    level: AuthLevel::Database(ns.to_string(), database.to_string()),
                    roles,
                    actor: Some(rec.subject),
                    access_name: Some(rec.client_id),
                    token_claims: Some(serde_json::json!({
                        "org_id": rec.org_id,
                        "scope": rec.scope,
                        "permissions": perms,
                    })),
                }));
            }
            return Err("Invalid, expired, or revoked Nexus-IDP access token".into());
        }
    }

    // 2. Existing nexus-db auth spine (DEFINE USER / HS256 JWT / Basic / nxb_* / session cookie)
    match resolve_http_auth(req, db, ns, database) {
        Ok(Some(ctx)) => return Ok(Some(ctx)),
        Ok(None) if allow_local_dev_bypass => return Ok(None),
        Ok(None) => return Ok(None),
        Err(first_err) => {
            // 3. Fallback: verify RFC 8037 EdDSA JWT issued by Nexus-IDP against cluster JWKS
            if let Some(bearer) = bearer_opt {
                if bearer.split('.').count() == 3 {
                    let idp = crate::iam::idp::NexusIdp::new(db.clone());
                    if let Ok(jwks) = idp.jwks().await {
                        // Extract aud from unverified payload to build policy, then validate fully
                        if let Some(payload_b64) = bearer.split('.').nth(1) {
                            use base64::Engine as _;
                            if let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) {
                                if let Ok(unverified) = serde_json::from_slice::<serde_json::Value>(&raw) {
                                    if let Some(aud) = unverified.get("aud").and_then(|v| v.as_str()) {
                                        let pol = crate::iam::idp::JwtValidationPolicy::new("nexus-idp", aud);
                                        if let Ok(claims) = crate::iam::idp::validate_eddsa_jwt(bearer, &jwks, &pol) {
                                            let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("authenticated").to_string();
                                            let org_id = claims.get("org_id").and_then(|v| v.as_str()).unwrap_or("default").to_string();
                                            let mut roles: Vec<Role> = claims
                                                .get("roles")
                                                .and_then(|v| v.as_array())
                                                .map(|a| a.iter().filter_map(|r| r.as_str().and_then(Role::parse)).collect())
                                                .unwrap_or_default();
                                            if roles.is_empty() {
                                                roles.push(Role::Viewer);
                                            }
                                            let is_admin = roles.contains(&Role::Owner);
                                            let perms = idp
                                                .effective_permissions_for_org(&sub, is_admin, &org_id)
                                                .await
                                                .unwrap_or_default();
                                            return Ok(Some(AuthContext {
                                                level: AuthLevel::Database(ns.to_string(), database.to_string()),
                                                roles,
                                                actor: Some(sub),
                                                access_name: Some(aud.to_string()),
                                                token_claims: Some(serde_json::json!({
                                                    "org_id": org_id,
                                                    "permissions": perms,
                                                })),
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(first_err)
        }
    }
}

pub const DEPOT_AUTH_KEY: &str = "nexus_auth_context";
pub const DEPOT_REQUEST_ID_KEY: &str = "nexus_request_id";

/// Explicit endpoint security classification enforced uniformly at the gateway boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointTier {
    /// Requires a valid `AuthContext` (or explicit local-dev loopback opt-in).
    Authenticated,
    /// Privileged administrative endpoint (e.g. WAL replication, runtime install) requiring `OWNER` / IAM admin.
    Admin,
}

/// Single canonical IAM middleware attaching `Option<AuthContext>` and `X-Request-Id` to `Depot`.
#[derive(Clone)]
pub struct IamMiddleware {
    pub db: Arc<Database>,
    pub tier: EndpointTier,
}

impl IamMiddleware {
    pub fn authenticated(db: Arc<Database>) -> Self {
        Self {
            db,
            tier: EndpointTier::Authenticated,
        }
    }

    pub fn admin(db: Arc<Database>) -> Self {
        Self {
            db,
            tier: EndpointTier::Admin,
        }
    }
}

/// Retrieve the canonical `AuthContext` attached by `IamMiddleware` (if present).
pub fn depot_auth_context(depot: &Depot) -> Option<AuthContext> {
    depot
        .get::<Option<AuthContext>>(DEPOT_AUTH_KEY)
        .ok()
        .cloned()
        .flatten()
}

/// Retrieve the correlation `X-Request-Id` attached by `IamMiddleware`.
pub fn depot_request_id(depot: &Depot) -> Option<String> {
    depot.get::<String>(DEPOT_REQUEST_ID_KEY).ok().cloned()
}

#[async_trait]
impl Handler for IamMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        global_metrics().inc_gateway_request();

        // Propagate or generate correlation ID (`X-Request-Id`)
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if let Ok(val) = salvo::http::header::HeaderValue::from_str(&request_id) {
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("x-request-id"),
                val,
            );
        }
        depot.insert(DEPOT_REQUEST_ID_KEY, request_id);

        let (ns, database) = extract_ns_db(req);
        let auth = match resolve_unified_http_auth(req, &self.db, &ns, &database, true).await {
            Ok(a) => a,
            Err(msg) => {
                global_metrics().inc_iam_auth_failure();
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(serde_json::json!({
                    "code": 401,
                    "details": msg
                })));
                ctrl.skip_rest();
                return;
            }
        };

        if self.tier == EndpointTier::Admin {
            let is_admin = match &auth {
                Some(ctx) => ctx.can_admin_iam(&ns, &database),
                // When `auth` is `None`, `resolve_http_auth` already verified explicit
                // `NEXUS_ALLOW_UNAUTH_LOCAL=1` + loopback dev mode.
                None => true,
            };
            if !is_admin {
                global_metrics().inc_iam_auth_denial();
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(serde_json::json!({
                    "code": 403,
                    "details": "Privileged administrative endpoint requires OWNER role"
                })));
                ctrl.skip_rest();
                return;
            }
        }

        depot.insert(DEPOT_AUTH_KEY, auth);
        ctrl.call_next(req, depot, res).await;
    }
}
