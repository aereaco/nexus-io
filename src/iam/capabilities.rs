use nexus_db::auth::{AuthContext, Role};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::js::cell::{CellDbConfig, CellDbMode, MeshDbRole};

/// Formal capability tokens enforced at the Nexus-IO microkernel boundary (`nexus_host` syscalls,
/// gateway endpoints, and cell lifecycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    #[serde(rename = "db.read")]
    DbRead,
    #[serde(rename = "db.write")]
    DbWrite,
    #[serde(rename = "db.admin")]
    DbAdmin,
    #[serde(rename = "blob.read")]
    BlobRead,
    #[serde(rename = "blob.write")]
    BlobWrite,
    #[serde(rename = "network.connect")]
    NetworkConnect,
    #[serde(rename = "network.listen")]
    NetworkListen,
    #[serde(rename = "cell.spawn")]
    CellSpawn,
    #[serde(rename = "cell.manage")]
    CellManage,
    #[serde(rename = "runtime.install")]
    RuntimeInstall,
    #[serde(rename = "secrets.read")]
    SecretsRead,
    #[serde(rename = "metrics.read")]
    MetricsRead,
}

impl Capability {
    pub fn from_str_token(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "db.read" | "nexus_db_read" => Some(Self::DbRead),
            "db.write" | "nexus_db_write" => Some(Self::DbWrite),
            "db.admin" | "nexus_db_admin" => Some(Self::DbAdmin),
            "blob.read" | "nexus_blob_get" => Some(Self::BlobRead),
            "blob.write" | "nexus_blob_put" => Some(Self::BlobWrite),
            "network.connect" => Some(Self::NetworkConnect),
            "network.listen" => Some(Self::NetworkListen),
            "cell.spawn" => Some(Self::CellSpawn),
            "cell.manage" => Some(Self::CellManage),
            "runtime.install" => Some(Self::RuntimeInstall),
            "secrets.read" => Some(Self::SecretsRead),
            "metrics.read" => Some(Self::MetricsRead),
            _ => None,
        }
    }
}

/// Effective capability set granted to a workload after intersecting:
/// `requested ∩ operator_policy ∩ iam_roles ∩ cell_db_policy`.
///
/// SECURITY INVARIANT: A package or guest workload can *request* capabilities,
/// but can NEVER grant itself any capability not authorized by BOTH operator policy AND IAM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub caps: BTreeSet<Capability>,
}

impl CapabilitySet {
    pub fn empty() -> Self {
        Self {
            caps: BTreeSet::new(),
        }
    }

    pub fn from_iter(iter: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            caps: iter.into_iter().collect(),
        }
    }

    pub fn from_tokens(tokens: &[String]) -> Self {
        let mut set = BTreeSet::new();
        for tok in tokens {
            if tok.eq_ignore_ascii_case("nexus_db_query") {
                set.insert(Capability::DbRead);
                set.insert(Capability::DbWrite);
            } else if let Some(cap) = Capability::from_str_token(tok) {
                set.insert(cap);
            }
        }
        Self { caps: set }
    }

    /// Standard operator ceiling for regular app cells (read/write DB + blobs, no admin/install).
    pub fn standard_cell() -> Self {
        Self::from_iter([
            Capability::DbRead,
            Capability::DbWrite,
            Capability::BlobRead,
            Capability::BlobWrite,
        ])
    }

    /// Read-only cell ceiling (e.g. `VIEWER` role or read-replica cell).
    pub fn read_only_cell() -> Self {
        Self::from_iter([Capability::DbRead, Capability::BlobRead])
    }

    /// Full administrative capability set (`OWNER` role).
    pub fn admin_all() -> Self {
        Self::from_iter([
            Capability::DbRead,
            Capability::DbWrite,
            Capability::DbAdmin,
            Capability::BlobRead,
            Capability::BlobWrite,
            Capability::NetworkConnect,
            Capability::NetworkListen,
            Capability::CellSpawn,
            Capability::CellManage,
            Capability::RuntimeInstall,
            Capability::SecretsRead,
            Capability::MetricsRead,
        ])
    }

    pub fn has(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            caps: self.caps.intersection(&other.caps).copied().collect(),
        }
    }

    /// Derive the maximum capability set permitted by an IAM `AuthContext`.
    pub fn from_auth_context(auth: Option<&AuthContext>) -> Self {
        let Some(ctx) = auth else {
            return Self::standard_cell();
        };
        if ctx.roles.contains(&Role::Owner) {
            Self::admin_all()
        } else if ctx.roles.contains(&Role::Editor) {
            Self::from_iter([
                Capability::DbRead,
                Capability::DbWrite,
                Capability::BlobRead,
                Capability::BlobWrite,
                Capability::CellSpawn,
                Capability::MetricsRead,
            ])
        } else {
            // Viewer / Record-level identity: strictly read-only
            Self::read_only_cell()
        }
    }

    /// Compute the effective capability set:
    /// `requested ∩ operator_policy ∩ iam_caps ∩ cell_db_caps`.
    pub fn resolve_effective(
        requested: &CapabilitySet,
        operator_policy: &CapabilitySet,
        auth: Option<&AuthContext>,
        db_cfg: &CellDbConfig,
    ) -> Self {
        let iam_caps = Self::from_auth_context(auth);
        let mut effective = requested.intersect(operator_policy).intersect(&iam_caps);

        // Enforce CellDbConfig topology constraints
        match &db_cfg.mode {
            CellDbMode::None => {
                effective.caps.remove(&Capability::DbRead);
                effective.caps.remove(&Capability::DbWrite);
                effective.caps.remove(&Capability::DbAdmin);
            }
            CellDbMode::Reference { read_only: true, .. } => {
                effective.caps.remove(&Capability::DbWrite);
                effective.caps.remove(&Capability::DbAdmin);
            }
            CellDbMode::Mesh { role, .. } if !matches!(role, MeshDbRole::Leader) => {
                effective.caps.remove(&Capability::DbWrite);
                effective.caps.remove(&Capability::DbAdmin);
            }
            _ => {}
        }
        effective
    }
}

/// Conservative check for whether a query string attempts a mutating / administrative operation.
pub fn is_mutating_query(query: &str) -> bool {
    let up = query.trim_start().to_ascii_uppercase();
    [
        "CREATE ", "INSERT ", "UPDATE ", "UPSERT ", "DELETE ", "REMOVE ", "DEFINE ", "ALTER ",
        "DROP ", "RELATE ", "MUTATION",
    ]
    .iter()
    .any(|kw| up.starts_with(kw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_db::auth::AuthLevel;

    #[test]
    fn effective_capabilities_never_allow_self_escalation() {
        // Malicious package requests admin + runtime.install + db.write
        let requested = CapabilitySet::from_iter([
            Capability::DbRead,
            Capability::DbWrite,
            Capability::DbAdmin,
            Capability::RuntimeInstall,
            Capability::BlobRead,
        ]);
        let operator = CapabilitySet::standard_cell();
        let viewer_auth = AuthContext {
            level: AuthLevel::Database("demo".into(), "c1".into()),
            roles: vec![Role::Viewer],
            actor: Some("viewer_user".into()),
            access_name: None,
            token_claims: None,
        };

        let eff = CapabilitySet::resolve_effective(
            &requested,
            &operator,
            Some(&viewer_auth),
            &CellDbConfig::dedicated_full(),
        );
        // Viewer gets ONLY DbRead + BlobRead; DbWrite, DbAdmin, RuntimeInstall are all stripped
        assert!(eff.has(Capability::DbRead));
        assert!(eff.has(Capability::BlobRead));
        assert!(!eff.has(Capability::DbWrite));
        assert!(!eff.has(Capability::DbAdmin));
        assert!(!eff.has(Capability::RuntimeInstall));

        // Stateless cell strips even DbRead
        let stateless_eff = CapabilitySet::resolve_effective(
            &requested,
            &operator,
            None,
            &CellDbConfig::stateless(),
        );
        assert!(!stateless_eff.has(Capability::DbRead));
        assert!(stateless_eff.has(Capability::BlobRead));
    }
}
