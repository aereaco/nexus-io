//! Track A: Standards-Compliant SCIM 2.0 Provisioning (RFC 7643 / RFC 7644)
//!
//! Backed directly by `NexusIdp` (`NEXUS-ID-v1` identities) and `nexus-db` with zero extra crates:
//! - `/scim/v2/ServiceProviderConfig`
//! - `/scim/v2/Users` (GET/POST/PUT/PATCH/DELETE with `userName eq "..."` filtering)
//! - `/scim/v2/Groups` (GET/POST/PATCH/DELETE with member synchronization)
//! - Deprovisioning a SCIM user (`active: false` or `DELETE`) revokes org memberships and active
//!   sessions while preserving the underlying `NEXUS-ID-v1` audit record.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Database;
use crate::iam::idp::{IdentityStatus, NexusIdp};
use crate::iam::sessions::SessionService;

pub const SCIM_SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCIM_SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_SCHEMA_PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SCIM_SCHEMA_SPC: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(default)]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    pub active: bool,
    pub org_id: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupMember {
    pub value: String,
    #[serde(default)]
    pub display: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(default)]
    pub external_id: Option<String>,
    pub display_name: String,
    pub org_id: String,
    #[serde(default)]
    pub members: Vec<ScimGroupMember>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations", alias = "operations")]
    pub operations: Vec<ScimPatchOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: usize,
    pub start_index: usize,
    pub items_per_page: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

#[derive(Clone)]
pub struct ScimService {
    db: Arc<Database>,
    idp: NexusIdp,
    sessions: SessionService,
}

fn normalize_scim_id(id: &str, table_prefix: &str) -> String {
    id.strip_prefix(table_prefix)
        .unwrap_or(id)
        .trim_matches('⟨')
        .trim_matches('⟩')
        .to_string()
}

fn parse_scim_user(v: serde_json::Value) -> Option<ScimUser> {
    let mut u = serde_json::from_value::<ScimUser>(v).ok()?;
    u.id = normalize_scim_id(&u.id, "sys_iam_scim_user:");
    Some(u)
}

fn parse_scim_group(v: serde_json::Value) -> Option<ScimGroup> {
    let mut g = serde_json::from_value::<ScimGroup>(v).ok()?;
    g.id = normalize_scim_id(&g.id, "sys_iam_scim_group:");
    Some(g)
}

impl ScimService {
    pub fn new(db: Arc<Database>) -> Self {
        let idp = NexusIdp::new(db.clone());
        let sessions = SessionService::new(db.clone());
        Self { db, idp, sessions }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        self.idp.ensure_tables().await?;
        self.sessions.ensure_tables().await?;
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_iam_scim_user SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_iam_scim_group SCHEMALESS;";
        let _ = self.db.client.query(ddl).await;
        Ok(())
    }

    pub fn service_provider_config() -> serde_json::Value {
        serde_json::json!({
            "schemas": [SCIM_SCHEMA_SPC],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": 200 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Nexus-IDP EdDSA JWT or opaque bearer token",
                    "primary": true
                }
            ]
        })
    }

    /// Provision a SCIM 2.0 User backed by a real `NEXUS-ID-v1` identity.
    pub async fn create_user(
        &self,
        actor: &str,
        org_id: &str,
        user_name: &str,
        display_name: Option<String>,
        external_id: Option<String>,
        emails: Vec<ScimEmail>,
        active: bool,
    ) -> Result<ScimUser> {
        self.ensure_tables().await?;
        let uname = user_name.trim();
        if uname.is_empty() {
            anyhow::bail!("SCIM userName must be non-empty");
        }
        // Prevent duplicate userName within the same org
        let existing = self.list_users(Some(org_id), None).await?;
        if existing.resources.iter().any(|u| u.user_name.eq_ignore_ascii_case(uname)) {
            anyhow::bail!("SCIM user '{}' already exists in org '{}'", uname, org_id);
        }

        let primary_email = emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| emails.first())
            .map(|e| e.value.clone())
            .or_else(|| if uname.contains('@') { Some(uname.to_string()) } else { None });
        let disp = display_name.clone().unwrap_or_else(|| uname.to_string());
        let (ident, _) = self.idp.create_identity(&disp, primary_email).await?;

        let now = now_ms();
        let user = ScimUser {
            schemas: vec![SCIM_SCHEMA_USER.into()],
            id: ident.identity_id.clone(),
            external_id,
            user_name: uname.to_string(),
            display_name: Some(disp),
            emails,
            active,
            org_id: org_id.to_string(),
            created_at_ms: now,
            updated_at_ms: now,
        };
        let val = serde_json::to_value(&user)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_scim_user', $id) CONTENT $u;")
            .bind(("id", user.id.clone()))
            .bind(("u", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(org_id, actor, "scim.user.create", &user.id, "ok", &user.user_name)
            .await;
        Ok(user)
    }

    pub async fn get_user(&self, id: &str) -> Result<Option<ScimUser>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_scim_user', $id)")
            .bind(("id", id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows.into_iter().next().and_then(parse_scim_user))
    }

    /// List SCIM users with RFC 7644 `filter` support (`userName eq "..."` / `externalId eq "..."`).
    pub async fn list_users(
        &self,
        org_id: Option<&str>,
        filter: Option<&str>,
    ) -> Result<ScimListResponse<ScimUser>> {
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_scim_user").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut users: Vec<ScimUser> = rows
            .into_iter()
            .filter_map(parse_scim_user)
            .filter(|u| org_id.map(|o| u.org_id == o).unwrap_or(true))
            .collect();

        if let Some(raw_filter) = filter.map(str::trim).filter(|s| !s.is_empty()) {
            let lower = raw_filter.to_ascii_lowercase();
            if let Some(pos) = lower.find(" eq ") {
                let attr = raw_filter[..pos].trim().to_ascii_lowercase();
                let val = raw_filter[pos + 4..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                users.retain(|u| match attr.as_str() {
                    "username" => u.user_name.eq_ignore_ascii_case(val),
                    "externalid" => u.external_id.as_deref().map(|e| e == val).unwrap_or(false),
                    "id" => u.id == val,
                    _ => true,
                });
            }
        }
        let total = users.len();
        Ok(ScimListResponse {
            schemas: vec![SCIM_SCHEMA_LIST.into()],
            total_results: total,
            start_index: 1,
            items_per_page: total,
            resources: users,
        })
    }

    /// Apply RFC 7644 `PATCH` operations (`active`, `displayName`, `emails`).
    /// Setting `active = false` immediately revokes org memberships and org sessions!
    pub async fn patch_user(
        &self,
        actor: &str,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> Result<ScimUser> {
        let mut user = self
            .get_user(id)
            .await?
            .ok_or_else(|| anyhow!("SCIM user '{}' not found", id))?;

        let mut deactivated = false;
        for op in &patch.operations {
            let path = op.path.as_deref().unwrap_or("").to_ascii_lowercase();
            match path.as_str() {
                "active" => {
                    if let Some(b) = op.value.as_bool() {
                        if user.active && !b {
                            deactivated = true;
                        }
                        user.active = b;
                    }
                }
                "displayname" => {
                    if let Some(s) = op.value.as_str() {
                        user.display_name = Some(s.to_string());
                    }
                }
                "emails" => {
                    if let Ok(emails) = serde_json::from_value::<Vec<ScimEmail>>(op.value.clone()) {
                        user.emails = emails;
                    }
                }
                "" => {
                    if let Some(obj) = op.value.as_object() {
                        if let Some(b) = obj.get("active").and_then(|v| v.as_bool()) {
                            if user.active && !b {
                                deactivated = true;
                            }
                            user.active = b;
                        }
                        if let Some(s) = obj.get("displayName").and_then(|v| v.as_str()) {
                            user.display_name = Some(s.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        user.updated_at_ms = now_ms();
        let val = serde_json::to_value(&user)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_scim_user', $id) CONTENT $u;")
            .bind(("id", user.id.clone()))
            .bind(("u", val))
            .await?
            .check()?;

        if deactivated {
            let _ = self.idp.revoke_membership(actor, &user.org_id, &user.id).await;
            let _ = self.sessions.revoke_org_sessions(actor, &user.id, &user.org_id).await;
        }
        let _ = self
            .idp
            .append_audit(
                &user.org_id,
                actor,
                "scim.user.patch",
                &user.id,
                "ok",
                &format!("active={}", user.active),
            )
            .await;
        Ok(user)
    }

    /// Deprovision a SCIM user: removes SCIM directory record, revokes org memberships & org
    /// sessions, and preserves the personal `NEXUS-ID-v1` identity (Identity-First invariant!).
    pub async fn delete_user(&self, actor: &str, id: &str) -> Result<bool> {
        let Some(user) = self.get_user(id).await? else {
            return Ok(false);
        };
        let _ = self.idp.revoke_membership(actor, &user.org_id, &user.id).await;
        let _ = self.sessions.revoke_org_sessions(actor, &user.id, &user.org_id).await;
        self.db
            .client
            .query("DELETE type::record('sys_iam_scim_user', $id);")
            .bind(("id", id.to_string()))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(&user.org_id, actor, "scim.user.delete", id, "ok", &user.user_name)
            .await;
        Ok(true)
    }

    pub async fn create_group(
        &self,
        actor: &str,
        org_id: &str,
        display_name: &str,
        external_id: Option<String>,
        members: Vec<ScimGroupMember>,
    ) -> Result<ScimGroup> {
        self.ensure_tables().await?;
        let name = display_name.trim();
        if name.is_empty() {
            anyhow::bail!("SCIM group displayName must be non-empty");
        }
        let now = now_ms();
        let group = ScimGroup {
            schemas: vec![SCIM_SCHEMA_GROUP.into()],
            id: format!("sgrp_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
            external_id,
            display_name: name.to_string(),
            org_id: org_id.to_string(),
            members,
            created_at_ms: now,
            updated_at_ms: now,
        };
        let val = serde_json::to_value(&group)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_scim_group', $id) CONTENT $g;")
            .bind(("id", group.id.clone()))
            .bind(("g", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(org_id, actor, "scim.group.create", &group.id, "ok", &group.display_name)
            .await;
        Ok(group)
    }

    pub async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>> {
        self.ensure_tables().await?;
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_iam_scim_group', $id)")
            .bind(("id", id.to_string()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows.into_iter().next().and_then(parse_scim_group))
    }

    pub async fn list_groups(&self, org_id: Option<&str>) -> Result<ScimListResponse<ScimGroup>> {
        self.ensure_tables().await?;
        let mut resp = self.db.client.query("SELECT * FROM sys_iam_scim_group").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let groups: Vec<ScimGroup> = rows
            .into_iter()
            .filter_map(parse_scim_group)
            .filter(|g| org_id.map(|o| g.org_id == o).unwrap_or(true))
            .collect();
        let total = groups.len();
        Ok(ScimListResponse {
            schemas: vec![SCIM_SCHEMA_LIST.into()],
            total_results: total,
            start_index: 1,
            items_per_page: total,
            resources: groups,
        })
    }

    pub async fn patch_group(
        &self,
        actor: &str,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> Result<ScimGroup> {
        let mut group = self
            .get_group(id)
            .await?
            .ok_or_else(|| anyhow!("SCIM group '{}' not found", id))?;
        for op in &patch.operations {
            let verb = op.op.to_ascii_lowercase();
            let path = op.path.as_deref().unwrap_or("").to_ascii_lowercase();
            if path.starts_with("members") {
                if verb == "add" {
                    if let Ok(added) = serde_json::from_value::<Vec<ScimGroupMember>>(op.value.clone()) {
                        for m in added {
                            if !group.members.iter().any(|x| x.value == m.value) {
                                group.members.push(m);
                            }
                        }
                    }
                } else if verb == "remove" {
                    if let Some(target_id) = op.value.as_str() {
                        group.members.retain(|m| m.value != target_id);
                    } else if let Ok(rem) = serde_json::from_value::<Vec<ScimGroupMember>>(op.value.clone()) {
                        let rem_ids: Vec<String> = rem.into_iter().map(|m| m.value).collect();
                        group.members.retain(|m| !rem_ids.contains(&m.value));
                    }
                }
            } else if path == "displayname" {
                if let Some(s) = op.value.as_str() {
                    group.display_name = s.to_string();
                }
            }
        }
        group.updated_at_ms = now_ms();
        let val = serde_json::to_value(&group)?;
        self.db
            .client
            .query("UPSERT type::record('sys_iam_scim_group', $id) CONTENT $g;")
            .bind(("id", group.id.clone()))
            .bind(("g", val))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(&group.org_id, actor, "scim.group.patch", &group.id, "ok", &group.display_name)
            .await;
        Ok(group)
    }

    pub async fn delete_group(&self, actor: &str, id: &str) -> Result<bool> {
        let Some(group) = self.get_group(id).await? else {
            return Ok(false);
        };
        self.db
            .client
            .query("DELETE type::record('sys_iam_scim_group', $id);")
            .bind(("id", id.to_string()))
            .await?
            .check()?;
        let _ = self
            .idp
            .append_audit(&group.org_id, actor, "scim.group.delete", id, "ok", &group.display_name)
            .await;
        Ok(true)
    }

    /// Helper verifying that SCIM deprovisioning never destroys the underlying personal identity.
    pub async fn identity_is_active(&self, id: &str) -> bool {
        matches!(
            self.idp.get_identity(id).await,
            Ok(Some(ident)) if ident.status == IdentityStatus::Active
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::flows::{AuthAuthority, AuthResult};
    use crate::iam::idp::{DelegationScope, OrgPolicyPatch};
    use crate::iam::sessions::SessionScope;

    #[tokio::test]
    async fn scim2_user_group_lifecycle_and_deprovision_preserves_personal_identity() {
        let db = Arc::new(Database::open_mem());
        let idp = NexusIdp::new(db.clone());
        let sessions = SessionService::new(db.clone());
        let scim = ScimService::new(db);

        let org = idp
            .create_org("root", "acme", "Acme Corp", None, None, OrgPolicyPatch::default())
            .await
            .unwrap();

        // Provision SCIM user
        let u = scim
            .create_user(
                "okta-scim",
                &org.org_id,
                "carol@acme.example",
                Some("Carol Danvers".into()),
                Some("ext-carol-1".into()),
                vec![ScimEmail { value: "carol@acme.example".into(), primary: true }],
                true,
            )
            .await
            .unwrap();

        // Filter query `userName eq "carol@acme.example"`
        let found = scim
            .list_users(Some(&org.org_id), Some(r#"userName eq "carol@acme.example""#))
            .await
            .unwrap();
        assert_eq!(found.total_results, 1);
        assert_eq!(found.resources[0].id, u.id);

        // Grant org membership + create both personal and org-scoped sessions
        idp.grant_membership("root", &org.org_id, &u.id, vec![], vec!["iam.read".into()], DelegationScope::SelfOnly, None)
            .await
            .unwrap();
        let auth = AuthResult {
            execution_id: "fex_scim".into(),
            flow_id: "login".into(),
            flow_version: 1,
            identity_id: u.id.clone(),
            org_id: Some(org.org_id.clone()),
            amr: vec!["pwd".into()],
            authorities: vec![AuthAuthority::IdentityControlled],
            acr: "aal1".into(),
            completed_at_ms: now_ms(),
        };
        let (_, personal_tok) = sessions.issue_session(&auth, SessionScope::IdentityWide, None, 3600).await.unwrap();
        let (_, org_tok) = sessions
            .issue_session(&auth, SessionScope::Organization { org_id: org.org_id.clone() }, None, 3600)
            .await
            .unwrap();

        // SCIM Group create + PATCH add/remove member
        let grp = scim
            .create_group("okta-scim", &org.org_id, "Engineering", Some("ext-eng".into()), vec![])
            .await
            .unwrap();
        let grp = scim
            .patch_group(
                "okta-scim",
                &grp.id,
                &ScimPatchRequest {
                    schemas: vec![SCIM_SCHEMA_PATCH.into()],
                    operations: vec![ScimPatchOperation {
                        op: "add".into(),
                        path: Some("members".into()),
                        value: serde_json::json!([{ "value": u.id, "display": "Carol Danvers" }]),
                    }],
                },
            )
            .await
            .unwrap();
        assert_eq!(grp.members.len(), 1);

        // SCIM Deactivate (`active: false`) MUST revoke org session & org membership
        // while keeping personal IdentityWide session & personal identity alive!
        let patched = scim
            .patch_user(
                "okta-scim",
                &u.id,
                &ScimPatchRequest {
                    schemas: vec![SCIM_SCHEMA_PATCH.into()],
                    operations: vec![ScimPatchOperation {
                        op: "replace".into(),
                        path: Some("active".into()),
                        value: serde_json::json!(false),
                    }],
                },
            )
            .await
            .unwrap();
        assert!(!patched.active);
        assert!(sessions.validate_session(&org_tok).await.unwrap().is_none());
        assert!(sessions.validate_session(&personal_tok).await.unwrap().is_some());
        assert!(scim.identity_is_active(&u.id).await);
    }
}
