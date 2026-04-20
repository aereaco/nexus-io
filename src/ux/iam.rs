// IAM Security Middleware - Session Validation
// Validates JWT tokens against SurrealDB session table

use salvo::prelude::*;
use std::sync::Arc;
use crate::db::Database;

/// Middleware that requires a valid session token
pub struct IamMiddleware {
    pub db: Arc<Database>,
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
        // 1. Extract token from Authorization header or Cookie
        let token = req.header::<String>("Authorization")
            .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()))
            .or_else(|| req.cookie("nexus_session").map(|c| c.value().to_string()));

        let token = match token {
            Some(t) => t,
            None => {
                // If no token, check if this is an public-allow-listed route
                // ForPoC, we'll allow /rpc and /s3 if we are in DEV mode, 
                // but usually we would return 401.
                println!("🔒 Nexus-IO IAM: No session token found, rejecting request");
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Text::Plain("Authentication Required"));
                ctrl.skip_rest();
                return;
            }
        };

        // 2. Validate token against SurrealDB
        // In a real implementation, we would call db.client.authenticate(token)
        // For now, we'll check if the token exists in a (simulated) session table
        match self.db.client.query("SELECT * FROM session WHERE token = $token")
            .bind(("token", token.to_string()))
            .await 
        {
            Ok(mut response) => {
                let session: Option<serde_json::Value> = response.take(0).unwrap_or(None);
                
                if let Some(s) = session {
                    // Success: Store session in depot for downstream handlers
                    depot.insert("session", s);
                    ctrl.call_next(req, depot, res).await;
                } else {
                    println!("🔒 IAM: Invalid or expired session token");
                    res.status_code(StatusCode::UNAUTHORIZED);
                    res.render(Text::Plain("Invalid Session"));
                    ctrl.skip_rest();
                }
            }
            Err(e) => {
                eprintln!("❌ IAM database error: {}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain("Internal Security Error"));
                ctrl.skip_rest();
            }
        }
    }
}
