//! Canonical Nexus-IO Authentication & Authorization Middleware.
//!
//! Replaces legacy session-table queries with a single security boundary backed by
//! `nexus_db::auth::AuthContext`. Resolves credentials once, attaches `AuthContext` and a
//! correlation `request_id` (`X-Request-Id`) to Salvo's `Depot`, and fails closed by default.

use nexus_db::auth::AuthContext;
use salvo::prelude::*;
use std::sync::Arc;

use crate::db::Database;
use crate::observability::global_metrics;
use crate::ux::surreal_http::{extract_ns_db, resolve_http_auth};

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
        let auth = match resolve_http_auth(req, &self.db, &ns, &database) {
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
