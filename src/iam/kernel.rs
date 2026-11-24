use nexus_db::auth::{AuthContext, AuthLevel, Role};
use nexus_db::parser::{parse_surql, Statement};
use nexus_db::Value as DbValue;
use nu_protocol::{ShellError, Span};
use std::sync::Arc;

use crate::db::Database;

/// AST- & RBAC-backed SecurityKernel enforcing SurrealDB-compatible `OWNER` / `EDITOR` / `VIEWER`
/// policies across shell commands, SQL execution, and JS workloads.
pub struct SecurityKernel {
    db: Arc<Database>,
}

impl SecurityKernel {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Resolve a user's `AuthContext` from `nexus-db` (`user.active_role`).
    pub async fn resolve_auth_context(&self, username: &str, ns: &str, db_name: &str) -> AuthContext {
        let role_id = if let Ok(response) = self
            .db
            .client
            .query("SELECT VALUE active_role FROM user WHERE username = $user")
            .bind(("user", username.to_string()))
            .await
        {
            match response.take_values().into_iter().next() {
                Some(DbValue::RecordId { tb, id }) => format!("{}:{}", tb, id),
                Some(v) => v.display_compact(),
                None => "role:viewer".to_string(),
            }
        } else {
            "role:viewer".to_string()
        };

        let clean = role_id.replace('"', "").replace(' ', "").to_ascii_lowercase();
        let role = if clean.contains("owner") || clean.contains("admin") {
            Role::Owner
        } else if clean.contains("editor") {
            Role::Editor
        } else {
            Role::Viewer
        };

        AuthContext {
            level: AuthLevel::Database(ns.to_string(), db_name.to_string()),
            roles: vec![role],
            actor: Some(username.to_string()),
            access_name: None,
            token_claims: None,
        }
    }

    /// AST-based policy check for CLI/gateway command invocations.
    pub async fn check_policy(
        &self,
        username: String,
        command_name: &str,
        args: Vec<String>,
        span: Span,
    ) -> Result<(), ShellError> {
        let auth = self.resolve_auth_context(&username, "nexus", "system").await;

        if command_name == "sql" {
            for arg in &args {
                if let Ok(stmts) = parse_surql(arg) {
                    for stmt in &stmts {
                        match stmt {
                            Statement::Delete { .. }
                            | Statement::Remove { .. }
                            | Statement::DefineUser { .. }
                            | Statement::DefineAccess { .. } => {
                                if !auth.can_admin_iam("nexus", "system") {
                                    return Err(crate::shell_err(
                                        "Security Violation (RBAC)",
                                        format!(
                                            "Destructive/IAM SQL statement requires OWNER role (actor: {}, roles: {:?}).",
                                            username, auth.roles
                                        ),
                                        Some(span),
                                        Some("Authenticate with an OWNER account or JWT `rl: [\"Owner\"]`.".into()),
                                    ));
                                }
                            }
                            Statement::Create { .. }
                            | Statement::Insert { .. }
                            | Statement::Update { .. }
                            | Statement::Upsert { .. }
                            | Statement::Relate { .. } => {
                                if !auth.can_write_data("nexus", "system") {
                                    return Err(crate::shell_err(
                                        "Security Violation (RBAC)",
                                        format!(
                                            "Data mutation requires EDITOR or OWNER role (actor: {}, roles: {:?}).",
                                            username, auth.roles
                                        ),
                                        Some(span),
                                        None,
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if command_name == "js" && !auth.can_write_data("nexus", "system") {
            for arg in &args {
                let lower = arg.to_ascii_lowercase();
                if lower.contains("require") && lower.contains("fs") {
                    return Err(crate::shell_err(
                        "Security Violation (RBAC)",
                        format!(
                            "Filesystem access from JS requires EDITOR/OWNER role (actor: {}, roles: {:?}).",
                            username, auth.roles
                        ),
                        Some(span),
                        Some("Use --harden to run in an isolated Wasmtime Crystal cell.".into()),
                    ));
                }
            }
        }

        Ok(())
    }
}
