use nu_protocol::{ShellError, Span};
use std::sync::Arc;
use crate::db::Database;
use surrealdb::types::Value as SurValue;

pub struct SecurityKernel {
    db: Arc<Database>,
}

impl SecurityKernel {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Check if a command execution is allowed based on user, command, and arguments.
    /// This is the "Deep Granularity" interceptor.
    pub async fn check_policy(
        &self,
        username: String,
        command_name: &str,
        args: Vec<String>,
        _span: Span,
    ) -> Result<(), ShellError> {
        // 1. Fetch User and Role from DB
        let mut response = self.db.client.query("SELECT VALUE active_role FROM user WHERE username = $user")
            .bind(("user", username))
            .await
            .map_err(|e| crate::shell_err(
                "IAM Kernel Error",
                format!("Failed to fetch user policy: {}", e),
                Some(_span),
                None,
            ))?;

        let role_val: Option<SurValue> = response.take(0).map_err(|e| crate::shell_err(
            "IAM Kernel Error",
            format!("Data corruption in user table: {}", e),
            Some(_span),
            None,
        ))?;

        // Convert role_val to string for comparison (e.g. "role:admin")
        let role_id = match role_val {
            Some(SurValue::RecordId(rid)) => format!("{}:{:?}", rid.table.as_str(), rid.key),
            Some(v) => format!("{:?}", v), // Use debug format as fallback
            None => "role:guest".to_string(),
        };

        // Normalize string for comparison (remove quotes and variants if any)
        // RecordId formatter might return Table("role"):String("admin") or similar in debug
        // We want a clean "role:admin" or "role:guest"
        let role_id = role_id.replace("\"", "").replace(" ", "");

        // 2. Mock Policy Logic for Prototype
        
        // Example: Content-Based Blocking for SQL
        if command_name == "sql" {
            for arg in &args {
                let upper = arg.to_uppercase();
                // Check if it's admin. We handle various debug formats (e.g. role:String(admin) vs role:admin)
                let is_admin = role_id.contains("role:admin") || role_id.contains("admin");

                if (upper.contains("DROP") || upper.contains("DELETE")) && !is_admin {
                    return Err(crate::shell_err(
                        "Security Violation",
                        format!("Destructive SQL operations are restricted to Administrators. (Role Found: {})", role_id),
                        Some(_span),
                        Some("Contact your system administrator for elevation.".into()),
                    ));
                }
            }
        }

        // Example: Attribute-Based Blocking for JS (Resource isolation)
        if command_name == "js" {
            for arg in &args {
                let is_guest = role_id.contains("role:guest") || role_id.contains("guest");
                let lower_arg = arg.to_lowercase();
                if (lower_arg.contains("require") && lower_arg.contains("fs")) && is_guest {
                    return Err(crate::shell_err(
                        "Security Violation",
                        format!("Filesystem access from JS is restricted for Guest users. (Detected in: {}, Role: {})", arg, role_id),
                        Some(_span),
                        Some("Use --harden to run in an isolated scratchpad.".into()),
                    ));
                }
            }
        }

        Ok(())
    }
}
