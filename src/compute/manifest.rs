//! Declarative Application Manifest (`AppManifest`), Typed `Chart` Packaging, and
//! Desired-State Reconciler (`validate()` / `plan()` / `apply()`) for Nexus-IO.
//!
//! Design invariants:
//! 1. **Wasmtime is implicit** — manifests never declare a host runtime engine.
//! 2. **Zero parallel abstractions** — compiles directly into existing `Capability`,
//!    `CapabilitySet`, `CellDbConfig`, `CellPolicy`, `CellResourceLimits`, `CellManager`,
//!    and `CasStore`.
//! 3. **Separation of authorization from declaration** — a manifest may *request* capabilities,
//!    never grant them; effective capabilities are always `requested ∩ operator_policy ∩ iam_caps ∩ cell_db_caps`.
//! 4. **Deterministic typed charts** — no string templating; typed overrides resolve into a
//!    validated, reproducible `AppManifest` with a canonical BLAKE3 digest.
//! 5. **Strict stateful safety** — stateful single-writer cells reject `replicas > 1`, and
//!    unimplemented `MigrationPolicy::Replicated` fails validation rather than silently degrading.

use anyhow::{anyhow, Context, Result};
use nexus_db::auth::AuthContext;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::iam::capabilities::{Capability, CapabilitySet};
use crate::js::cell::{
    CellDbConfig, CellDbMode, CellLifecycleState, CellManager, CellPolicy, CellResourceLimits,
    CellWorkload,
};
use crate::storage::cas_store::CasStore;
use crate::storage::BlobBridge;

pub const MANIFEST_API_VERSION: &str = "nexus.io/v1";
pub const DEPLOYMENTS_BUCKET: &str = "nexus-deployments";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

// =============================================================================
// 1. Authoritative `AppManifest` Schema (`api_version = "nexus.io/v1"`)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppManifest {
    pub api_version: String,
    pub kind: String,
    pub metadata: AppMetadata,
    #[serde(default)]
    pub topology: TopologySpec,
    #[serde(default)]
    pub defaults: CellDefaults,
    #[serde(default)]
    pub gateway: Option<GatewaySpec>,
    #[serde(default)]
    pub cells: BTreeMap<String, CellSpec>,
}

/// Declarative gateway & service activation specification.
/// **Zero-trust default:** every service defaults to `false` (strictly opt-in).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySpec {
    /// Listen address for the primary gateway (e.g. `"127.0.0.1:8443"`).
    #[serde(default)]
    pub bind: Option<String>,
    /// Enable the port 80/8080 HTTP→HTTPS redirect listener (default: `false`).
    #[serde(default)]
    pub enable_http_redirect: bool,
    /// Opt-in service flags (`rpc`, `cells`, `s3`, `graphql`, `pgwire`, `mysqlwire`, `sqlite`, `metrics`).
    #[serde(default)]
    pub services: GatewayServicesSpec,
    /// Opt-in static web application & SPA serving (requires `serve-web` feature + explicit `root`).
    #[serde(default)]
    pub web: Option<WebServiceSpec>,
    /// Opt-in reverse proxy routes (requires `serve-proxy` feature).
    #[serde(default)]
    pub proxy: Option<ProxyServiceSpec>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayServicesSpec {
    #[serde(default)]
    pub rpc: bool,
    #[serde(default)]
    pub cells: bool,
    #[serde(default)]
    pub s3: bool,
    #[serde(default)]
    pub graphql: bool,
    #[serde(default)]
    pub sqlite: bool,
    #[serde(default)]
    pub pgwire: bool,
    #[serde(default)]
    pub pgwire_port: Option<u16>,
    #[serde(default)]
    pub mysqlwire: bool,
    #[serde(default)]
    pub mysqlwire_port: Option<u16>,
    #[serde(default)]
    pub metrics: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebServiceSpec {
    #[serde(default)]
    pub enabled: bool,
    /// Explicit web bundle root directory (resolved relative to the manifest file if relative).
    #[serde(default)]
    pub root: Option<String>,
    /// Optional framework dist bundle directory (mounted at `/dist/*`).
    #[serde(default)]
    pub dist: Option<String>,
    /// Enable HTML-only SPA fallback to `index.html` (default: `true`).
    #[serde(default = "default_true")]
    pub spa_fallback: bool,
    /// `Cross-Origin-Opener-Policy` header (`"none"` disables).
    #[serde(default)]
    pub coop: Option<String>,
    /// `Cross-Origin-Embedder-Policy` header (`"none"` disables).
    #[serde(default)]
    pub coep: Option<String>,
}

impl Default for WebServiceSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            root: None,
            dist: None,
            spa_fallback: true,
            coop: None,
            coep: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyServiceSpec {
    #[serde(default)]
    pub enabled: bool,
    /// Named upstream targets (`/proxy/<name>/*` -> upstream URL).
    #[serde(default)]
    pub upstreams: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppMetadata {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Evolvable deployment topology preset (authoritative per-cell placement may override).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    Monolith,
    #[default]
    Modular,
    Mesh,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologySpec {
    #[serde(default)]
    pub mode: DeploymentMode,
}

/// Application-wide resource & lifecycle defaults inherited by cells unless overridden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellDefaults {
    #[serde(default = "default_max_fuel")]
    pub max_fuel: u64,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default = "default_max_concurrent_execs")]
    pub max_concurrent_execs: usize,
    #[serde(default = "default_deadline_ms")]
    pub deadline_ms: u64,
}

fn default_max_fuel() -> u64 {
    CellResourceLimits::default().max_fuel
}
fn default_max_output_bytes() -> usize {
    CellResourceLimits::default().max_output_bytes
}
fn default_max_concurrent_execs() -> usize {
    CellResourceLimits::default().max_concurrent_execs
}
fn default_deadline_ms() -> u64 {
    CellResourceLimits::default().deadline_ms
}

impl Default for CellDefaults {
    fn default() -> Self {
        Self {
            max_fuel: default_max_fuel(),
            max_output_bytes: default_max_output_bytes(),
            max_concurrent_execs: default_max_concurrent_execs(),
            deadline_ms: default_deadline_ms(),
        }
    }
}

/// Per-cell logical contract + evolvable placement/lifecycle/migration intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellSpec {
    /// Immutable content-addressed artifact: `blake3:<64-hex>` or digest-pinned
    /// `oci://<registry>/<repo>@sha256:<64-hex>`.
    pub artifact: String,
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    #[serde(default)]
    pub wasi: WasiSpec,
    #[serde(default)]
    pub resources: ResourceOverrides,
    #[serde(default = "CellDbConfig::stateless")]
    pub database: CellDbConfig,
    #[serde(default)]
    pub capabilities: CapabilitiesSpec,
    #[serde(default)]
    pub placement: Option<PlacementSpec>,
    #[serde(default)]
    pub lifecycle: LifecycleSpec,
    #[serde(default)]
    pub migration: Option<MigrationPolicy>,
}

fn default_replicas() -> u32 {
    1
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasiSpec {
    #[serde(default)]
    pub args: Vec<String>,
    /// Named secret references resolved by the host IAM/secrets layer (never inline secret values).
    #[serde(default)]
    pub secret_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceOverrides {
    pub max_fuel: Option<u64>,
    pub max_output_bytes: Option<usize>,
    pub max_concurrent_execs: Option<usize>,
    pub deadline_ms: Option<u64>,
}

/// Default-deny capability request block. Never grants authority on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSpec {
    #[serde(default)]
    pub allow: Vec<Capability>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementTarget {
    #[default]
    Local,
    Mesh,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementSpec {
    #[serde(default)]
    pub target: PlacementTarget,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HibernationMode {
    Pinned,
    #[default]
    Elastic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSpec {
    #[serde(default)]
    pub hibernation: HibernationMode,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
}

fn default_ttl_seconds() -> u64 {
    60
}

impl Default for LifecycleSpec {
    fn default() -> Self {
        Self {
            hibernation: HibernationMode::Elastic,
            ttl_seconds: default_ttl_seconds(),
        }
    }
}

/// Explicit cell migration strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPolicy {
    /// Stateful handoff using monotonic CAS fencing tokens (`WasmDbCellRecord` / `ExecutionLease`).
    FencedCheckpoint,
    /// Stateless restart on destination without transferring state.
    StatelessRestart,
    /// Never automatically relocate.
    Pinned,
    /// Multi-writer replicated consistency (explicitly rejected until implemented).
    Replicated,
}

// =============================================================================
// 2. Validation & Compilation Into Existing Runtime Primitives
// =============================================================================

/// Validated, immutable manifest with canonical BLAKE3 digest.
#[derive(Debug, Clone)]
pub struct ValidatedManifest {
    pub manifest: AppManifest,
    pub canonical_digest: String,
}

/// Compiled per-cell runtime configuration ready for `CellManager`.
#[derive(Debug, Clone)]
pub struct CompiledCellConfig {
    pub cell_id: String,
    pub artifact: String,
    pub policy: CellPolicy,
    pub limits: CellResourceLimits,
    pub db_config: CellDbConfig,
    pub effective_capabilities: CapabilitySet,
    pub effective_placement: PlacementTarget,
    pub migration_policy: MigrationPolicy,
    pub replicas: u32,
}

fn validate_artifact_ref(cell_name: &str, artifact: &str) -> Result<()> {
    let trimmed = artifact.trim();
    if let Some(hex) = trimmed.strip_prefix("blake3:") {
        if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(());
        }
        anyhow::bail!(
            "Cell '{}' has invalid blake3 artifact digest '{}' (expected 64 hex chars)",
            cell_name,
            artifact
        );
    }
    if let Some(rest) = trimmed.strip_prefix("oci://") {
        if let Some((_, digest)) = rest.split_once("@sha256:") {
            if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(());
            }
        }
        anyhow::bail!(
            "Cell '{}' OCI artifact '{}' must be digest-pinned (`oci://registry/repo@sha256:<64-hex>`); mutable tags are forbidden",
            cell_name,
            artifact
        );
    }
    anyhow::bail!(
        "Cell '{}' artifact '{}' must be `blake3:<64-hex>` or digest-pinned `oci://...@sha256:<64-hex>`",
        cell_name,
        artifact
    )
}

impl AppManifest {
    pub fn from_toml(src: &str) -> Result<Self> {
        toml::from_str(src).context("Failed to parse AppManifest TOML")
    }

    pub fn from_json(src: &str) -> Result<Self> {
        serde_json::from_str(src).context("Failed to parse AppManifest JSON")
    }

    pub fn from_yaml(src: &str) -> Result<Self> {
        #[cfg(feature = "ops-k8s")]
        {
            serde_norway::from_str(src).context("Failed to parse AppManifest YAML")
        }
        #[cfg(not(feature = "ops-k8s"))]
        {
            let _ = src;
            anyhow::bail!("YAML manifests require compiling with the 'ops-k8s' feature (use TOML or JSON)")
        }
    }

    /// Load an `AppManifest` from a `.toml`, `.json`, or `.yaml`/`.yml` file.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest '{}'", path.display()))?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "json" => Self::from_json(&raw),
            "yaml" | "yml" => Self::from_yaml(&raw),
            _ => {
                let trimmed = raw.trim_start();
                if trimmed.starts_with('{') {
                    Self::from_json(&raw)
                } else {
                    Self::from_toml(&raw)
                }
            }
        }
    }

    /// Compile the declared `[gateway]` section into a validated, strictly opt-in `GatewayConfig`.
    /// Fails fast if any declared service requires a Cargo feature not compiled into this binary
    /// or if a declared web root/dist path does not exist.
    pub fn compile_gateway_config(
        &self,
        manifest_dir: &std::path::Path,
    ) -> Result<crate::ux::GatewayConfig> {
        let Some(ref gw) = self.gateway else {
            anyhow::bail!("Manifest '{}' does not declare a [gateway] section", self.metadata.name);
        };

        let mut cfg = crate::ux::GatewayConfig {
            enable_https: true,
            enable_http: gw.enable_http_redirect,
            bind_addr: gw.bind.clone(),
            enable_rpc: gw.services.rpc,
            enable_cells: gw.services.cells,
            enable_s3: gw.services.s3,
            enable_graphql: gw.services.graphql,
            enable_sqlite: gw.services.sqlite,
            enable_pgwire: gw.services.pgwire,
            pgwire_port: gw.services.pgwire_port.unwrap_or(5432),
            enable_mysqlwire: gw.services.mysqlwire,
            mysqlwire_port: gw.services.mysqlwire_port.unwrap_or(3306),
            enable_metrics: gw.services.metrics,
            ..crate::ux::GatewayConfig::default()
        };

        // Compile-time feature parity checks (fail fast instead of silently ignoring)
        #[cfg(not(feature = "db-graphql"))]
        if cfg.enable_graphql {
            anyhow::bail!("Manifest enables gateway.services.graphql, but this binary was compiled without the 'db-graphql' feature");
        }
        #[cfg(not(feature = "db-sqlite"))]
        if cfg.enable_sqlite {
            anyhow::bail!("Manifest enables gateway.services.sqlite, but this binary was compiled without the 'db-sqlite' feature");
        }
        #[cfg(not(feature = "db-pgwire"))]
        if cfg.enable_pgwire {
            anyhow::bail!("Manifest enables gateway.services.pgwire, but this binary was compiled without the 'db-pgwire' feature");
        }
        #[cfg(not(feature = "db-mysqlwire"))]
        if cfg.enable_mysqlwire {
            anyhow::bail!("Manifest enables gateway.services.mysqlwire, but this binary was compiled without the 'db-mysqlwire' feature");
        }

        if let Some(ref web) = gw.web {
            if web.enabled {
                #[cfg(not(feature = "serve-web"))]
                anyhow::bail!("Manifest enables gateway.web, but this binary was compiled without the 'serve-web' feature");

                let Some(ref raw_root) = web.root else {
                    anyhow::bail!("gateway.web.enabled = true requires an explicit gateway.web.root path");
                };
                let resolved_root = {
                    let p = std::path::PathBuf::from(raw_root);
                    if p.is_absolute() { p } else { manifest_dir.join(p) }
                };
                if !resolved_root.is_dir() {
                    anyhow::bail!(
                        "Declared gateway.web.root '{}' (resolved to '{}') does not exist or is not a directory",
                        raw_root,
                        resolved_root.display()
                    );
                }
                cfg.enable_web = true;
                cfg.web_root = Some(resolved_root);
                cfg.spa_fallback = web.spa_fallback;

                if let Some(ref raw_dist) = web.dist {
                    let resolved_dist = {
                        let p = std::path::PathBuf::from(raw_dist);
                        if p.is_absolute() { p } else { manifest_dir.join(p) }
                    };
                    if !resolved_dist.is_dir() {
                        anyhow::bail!(
                            "Declared gateway.web.dist '{}' (resolved to '{}') does not exist or is not a directory",
                            raw_dist,
                            resolved_dist.display()
                        );
                    }
                    cfg.dist_root = Some(resolved_dist);
                }

                let normalize_hdr = |opt: &Option<String>, default_val: &str| -> Option<String> {
                    match opt {
                        Some(v) => {
                            let t = v.trim();
                            if t.is_empty()
                                || t.eq_ignore_ascii_case("none")
                                || t.eq_ignore_ascii_case("off")
                                || t.eq_ignore_ascii_case("false")
                            {
                                None
                            } else {
                                Some(t.to_string())
                            }
                        }
                        None => Some(default_val.to_string()),
                    }
                };
                cfg.coop_header = normalize_hdr(&web.coop, "same-origin");
                cfg.coep_header = normalize_hdr(&web.coep, "credentialless");
            }
        }

        if let Some(ref proxy) = gw.proxy {
            if proxy.enabled {
                #[cfg(not(feature = "serve-proxy"))]
                {
                    anyhow::bail!("Manifest enables gateway.proxy, but this binary was compiled without the 'serve-proxy' feature");
                }
                #[cfg(feature = "serve-proxy")]
                {
                    cfg.enable_proxy = true;
                }
            }
        }

        Ok(cfg)
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("Failed to serialize AppManifest to TOML")
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("Failed to serialize AppManifest to JSON")
    }

    /// Canonical BLAKE3 digest of this manifest's normalized JSON representation.
    pub fn canonical_digest(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// Validate schema version, identifiers, immutable artifacts, secret hygiene, and stateful/migration invariants.
    pub fn validate(&self) -> Result<ValidatedManifest> {
        if self.api_version != MANIFEST_API_VERSION {
            anyhow::bail!(
                "Unsupported api_version '{}' (expected '{}')",
                self.api_version,
                MANIFEST_API_VERSION
            );
        }
        if self.kind != "Application" {
            anyhow::bail!("Unsupported kind '{}' (expected 'Application')", self.kind);
        }
        if !valid_ident(&self.metadata.name) {
            anyhow::bail!(
                "Invalid metadata.name '{}' (use lowercase alphanumeric, '-', '_')",
                self.metadata.name
            );
        }
        if self.metadata.version.trim().is_empty() {
            anyhow::bail!("metadata.version must not be empty");
        }
        if self.cells.is_empty() && self.gateway.is_none() {
            anyhow::bail!("AppManifest must declare at least one cell or a [gateway] section");
        }

        for (cell_id, spec) in &self.cells {
            if !valid_ident(cell_id) {
                anyhow::bail!("Invalid cell name '{}'", cell_id);
            }
            validate_artifact_ref(cell_id, &spec.artifact)?;
            if spec.replicas == 0 {
                anyhow::bail!("Cell '{}' replicas must be >= 1", cell_id);
            }
            for sref in &spec.wasi.secret_refs {
                if sref.contains('=') || sref.trim().is_empty() {
                    anyhow::bail!(
                        "Cell '{}' secret_ref '{}' must reference a secret identity, never an inline value",
                        cell_id,
                        sref
                    );
                }
            }

            let is_stateful = !matches!(spec.database.mode, CellDbMode::None);
            let migration = spec.migration.unwrap_or(if is_stateful {
                MigrationPolicy::FencedCheckpoint
            } else {
                MigrationPolicy::StatelessRestart
            });

            if migration == MigrationPolicy::Replicated {
                anyhow::bail!(
                    "Cell '{}' requested MigrationPolicy::Replicated, which is not yet implemented",
                    cell_id
                );
            }
            if is_stateful && spec.replicas > 1 {
                anyhow::bail!(
                    "Stateful cell '{}' cannot set replicas={} under {:?} (single-writer fencing permits at most 1 active writer)",
                    cell_id,
                    spec.replicas,
                    migration
                );
            }
            if is_stateful && migration == MigrationPolicy::StatelessRestart {
                anyhow::bail!(
                    "Stateful cell '{}' cannot use MigrationPolicy::StatelessRestart (use fenced_checkpoint or pinned)",
                    cell_id
                );
            }
        }

        let canonical_digest = self.canonical_digest()?;
        Ok(ValidatedManifest {
            manifest: self.clone(),
            canonical_digest,
        })
    }

    /// Compile a single cell's manifest specification into existing Nexus-IO runtime types,
    /// enforcing `effective = requested ∩ operator_policy ∩ iam_caps ∩ cell_db_caps`.
    pub fn compile_cell(
        &self,
        cell_id: &str,
        operator_policy: &CapabilitySet,
        deployer_auth: Option<&AuthContext>,
    ) -> Result<CompiledCellConfig> {
        let spec = self
            .cells
            .get(cell_id)
            .ok_or_else(|| anyhow!("Cell '{}' not found in manifest", cell_id))?;

        let limits = CellResourceLimits {
            max_fuel: spec.resources.max_fuel.unwrap_or(self.defaults.max_fuel),
            max_output_bytes: spec
                .resources
                .max_output_bytes
                .unwrap_or(self.defaults.max_output_bytes),
            max_concurrent_execs: spec
                .resources
                .max_concurrent_execs
                .unwrap_or(self.defaults.max_concurrent_execs),
            deadline_ms: spec
                .resources
                .deadline_ms
                .unwrap_or(self.defaults.deadline_ms),
        };

        let policy = match spec.lifecycle.hibernation {
            HibernationMode::Pinned => CellPolicy::Pinned,
            HibernationMode::Elastic => CellPolicy::Elastic {
                idle_timeout: Duration::from_secs(spec.lifecycle.ttl_seconds),
                lease_bucket: "nexus-cells".to_string(),
            },
        };

        let requested = CapabilitySet::from_iter(spec.capabilities.allow.iter().copied());
        let effective_capabilities = CapabilitySet::resolve_effective(
            &requested,
            operator_policy,
            deployer_auth,
            &spec.database,
        );

        let default_target = match self.topology.mode {
            DeploymentMode::Monolith | DeploymentMode::Modular => PlacementTarget::Local,
            DeploymentMode::Mesh => PlacementTarget::Mesh,
        };
        let effective_placement = spec
            .placement
            .as_ref()
            .map(|p| p.target)
            .unwrap_or(default_target);

        let is_stateful = !matches!(spec.database.mode, CellDbMode::None);
        let migration_policy = spec.migration.unwrap_or(if is_stateful {
            MigrationPolicy::FencedCheckpoint
        } else {
            MigrationPolicy::StatelessRestart
        });

        Ok(CompiledCellConfig {
            cell_id: cell_id.to_string(),
            artifact: spec.artifact.clone(),
            policy,
            limits,
            db_config: spec.database.clone(),
            effective_capabilities,
            effective_placement,
            migration_policy,
            replicas: spec.replicas,
        })
    }
}

// =============================================================================
// 3. Deterministic Typed `Chart` Packaging (No String Templating)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChartMeta {
    pub api_version: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellValueOverride {
    pub artifact: Option<String>,
    pub replicas: Option<u32>,
    pub resources: Option<ResourceOverrides>,
    pub placement: Option<PlacementSpec>,
    pub lifecycle: Option<LifecycleSpec>,
    pub migration: Option<MigrationPolicy>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChartValues {
    pub topology_mode: Option<DeploymentMode>,
    pub defaults: Option<CellDefaults>,
    #[serde(default)]
    pub cells: BTreeMap<String, CellValueOverride>,
}

/// Reusable, versioned application package resolving deterministically into a `ValidatedManifest`.
#[derive(Debug, Clone)]
pub struct ChartPackage {
    pub meta: ChartMeta,
    pub base_manifest: AppManifest,
    pub default_values: ChartValues,
}

impl ChartPackage {
    /// Deterministic resolution with explicit precedence:
    /// `base_manifest` -> `default_values` -> `caller_overrides` -> `validate()`.
    pub fn resolve(&self, caller_overrides: Option<&ChartValues>) -> Result<ValidatedManifest> {
        if self.meta.api_version != MANIFEST_API_VERSION {
            anyhow::bail!("Unsupported Chart api_version '{}'", self.meta.api_version);
        }
        if !valid_ident(&self.meta.name) || self.meta.version.trim().is_empty() {
            anyhow::bail!("Invalid Chart metadata name or version");
        }
        let mut resolved = self.base_manifest.clone();
        Self::apply_values(&mut resolved, &self.default_values)?;
        if let Some(ov) = caller_overrides {
            Self::apply_values(&mut resolved, ov)?;
        }
        resolved.validate()
    }

    fn apply_values(manifest: &mut AppManifest, values: &ChartValues) -> Result<()> {
        if let Some(mode) = values.topology_mode {
            manifest.topology.mode = mode;
        }
        if let Some(ref defs) = values.defaults {
            manifest.defaults = defs.clone();
        }
        for (cell_id, ov) in &values.cells {
            let cell = manifest.cells.get_mut(cell_id).ok_or_else(|| {
                anyhow!(
                    "Chart value override references unknown cell '{}'",
                    cell_id
                )
            })?;
            if let Some(ref art) = ov.artifact {
                cell.artifact = art.clone();
            }
            if let Some(r) = ov.replicas {
                cell.replicas = r;
            }
            if let Some(ref res) = ov.resources {
                if let Some(v) = res.max_fuel {
                    cell.resources.max_fuel = Some(v);
                }
                if let Some(v) = res.max_output_bytes {
                    cell.resources.max_output_bytes = Some(v);
                }
                if let Some(v) = res.max_concurrent_execs {
                    cell.resources.max_concurrent_execs = Some(v);
                }
                if let Some(v) = res.deadline_ms {
                    cell.resources.deadline_ms = Some(v);
                }
            }
            if let Some(ref p) = ov.placement {
                cell.placement = Some(p.clone());
            }
            if let Some(ref l) = ov.lifecycle {
                cell.lifecycle = l.clone();
            }
            if let Some(m) = ov.migration {
                cell.migration = Some(m);
            }
        }
        Ok(())
    }
}

// =============================================================================
// 4. Desired-State Planning & Durable CAS-Backed Local Reconciliation
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellActionKind {
    Create,
    Update,
    Unchanged,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellPlanAction {
    pub cell_id: String,
    pub action: CellActionKind,
    pub placement: PlacementTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub app_name: String,
    pub manifest_digest: String,
    pub topology_mode: DeploymentMode,
    pub actions: Vec<CellPlanAction>,
}

impl DeploymentPlan {
    pub fn has_changes(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.action != CellActionKind::Unchanged)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Pending,
    Reconciling,
    Succeeded,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentOperation {
    pub operation_id: String,
    pub app_name: String,
    pub manifest_digest: String,
    pub status: OperationStatus,
    pub plan: DeploymentPlan,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedCellState {
    pub cell_id: String,
    pub artifact: String,
    pub cell_digest: String,
    pub effective_capabilities: CapabilitySet,
    pub lifecycle_state: CellLifecycleState,
    pub placement: PlacementTarget,
    pub migration_policy: MigrationPolicy,
    pub replicas: u32,
    #[serde(default)]
    pub assigned_nodes: Vec<String>,
    #[serde(default)]
    pub mesh_endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub app_name: String,
    pub app_version: String,
    pub manifest_digest: String,
    pub topology_mode: DeploymentMode,
    pub cells: BTreeMap<String, DeployedCellState>,
    pub updated_at_ms: u64,
}

/// Desired-state reconciler orchestrating existing `CellManager`, `WasmRuntimeRegistry`, and `CasStore`.
pub struct ManifestReconciler;

impl ManifestReconciler {
    fn app_record_key(app_name: &str) -> String {
        format!("apps/{}/deployment.json", app_name)
    }

    fn op_record_key(op_id: &str) -> String {
        format!("ops/{}.json", op_id)
    }

    /// Side-effect-free desired-state diff against the durable `DeploymentRecord` in `CasStore`.
    pub async fn plan(
        blobs: &Arc<BlobBridge>,
        validated: &ValidatedManifest,
    ) -> Result<DeploymentPlan> {
        let cas = CasStore::new(blobs.clone());
        let app = &validated.manifest.metadata.name;
        let existing = cas
            .read_manifest::<DeploymentRecord>(DEPLOYMENTS_BUCKET, &Self::app_record_key(app))
            .await?
            .map(|(r, _)| r);

        let default_target = match validated.manifest.topology.mode {
            DeploymentMode::Monolith | DeploymentMode::Modular => PlacementTarget::Local,
            DeploymentMode::Mesh => PlacementTarget::Mesh,
        };

        let mut actions = Vec::new();
        for (cell_id, spec) in &validated.manifest.cells {
            let cell_digest = blake3::hash(&serde_json::to_vec(spec)?).to_hex().to_string();
            let placement = spec
                .placement
                .as_ref()
                .map(|p| p.target)
                .unwrap_or(default_target);

            let kind = match existing.as_ref().and_then(|r| r.cells.get(cell_id)) {
                None => CellActionKind::Create,
                Some(prev) if prev.cell_digest == cell_digest && prev.placement == placement => {
                    CellActionKind::Unchanged
                }
                Some(_) => CellActionKind::Update,
            };
            actions.push(CellPlanAction {
                cell_id: cell_id.clone(),
                action: kind,
                placement,
            });
        }

        if let Some(prev_rec) = existing {
            for prev_cell in prev_rec.cells.keys() {
                if !validated.manifest.cells.contains_key(prev_cell) {
                    actions.push(CellPlanAction {
                        cell_id: prev_cell.clone(),
                        action: CellActionKind::Remove,
                        placement: PlacementTarget::Local,
                    });
                }
            }
        }

        Ok(DeploymentPlan {
            app_name: app.clone(),
            manifest_digest: validated.canonical_digest.clone(),
            topology_mode: validated.manifest.topology.mode,
            actions,
        })
    }

    /// Transactional, idempotent local reconciliation (`Monolith` & `Modular` local placements).
    /// Persists `DeploymentOperation` intent BEFORE mutating cells, activates new/updated cells
    /// BEFORE removing old cells, and commits `DeploymentRecord` via CAS.
    pub async fn apply(
        cells: &CellManager,
        blobs: &Arc<BlobBridge>,
        validated: &ValidatedManifest,
        operator_policy: &CapabilitySet,
        deployer_auth: Option<&AuthContext>,
    ) -> Result<DeploymentOperation> {
        let cas = CasStore::new(blobs.clone());
        let app = &validated.manifest.metadata.name;
        let plan = Self::plan(blobs, validated).await?;

        // Pre-validate mesh placement against live 4D MeshScheduler (`peer_registry` + `NodeResources`)
        let mut scheduled_mesh_targets: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
        let has_mesh_actions = plan
            .actions
            .iter()
            .any(|a| a.action != CellActionKind::Remove && a.placement == PlacementTarget::Mesh);
        if has_mesh_actions {
            let (_records, peer_configs, grid_state) =
                crate::storage::mesh::MeshReactor::load_mesh_snapshot(blobs.db()).await?;
            let scheduler = crate::compute::InferenceRouter::from_snapshot(grid_state);
            let empty_labels: Vec<String> = Vec::new();
            for a in &plan.actions {
                if a.action == CellActionKind::Remove || a.placement != PlacementTarget::Mesh {
                    continue;
                }
                let spec = &validated.manifest.cells[&a.cell_id];
                let (requires, labels) = match &spec.placement {
                    Some(p) => (p.requires.as_slice(), &p.labels),
                    None => (&[][..], &empty_labels),
                };
                let min_ram_mb = 64u64;
                let replicas = (spec.replicas.max(1)) as usize;
                let req = crate::compute::ComputeRequirements::from_placement(
                    requires,
                    labels,
                    min_ram_mb,
                    Some(format!("{}/{}", app, a.cell_id)),
                );
                let winners = scheduler.select_ranked_nodes(&peer_configs, &req, replicas);
                if winners.len() < replicas {
                    anyhow::bail!(
                        "Cell '{}/{}' targets `placement = mesh`, but no eligible mesh peers in peer_registry satisfy its 4D resource/capability requirements (needed {}, found {})",
                        app,
                        a.cell_id,
                        replicas,
                        winners.len()
                    );
                }
                let node_ids: Vec<String> = winners.iter().map(|(p, _)| p.public_key.clone()).collect();
                let endpoints: Vec<String> = winners
                    .iter()
                    .map(|(p, _)| p.endpoint.clone().unwrap_or_else(|| p.mesh_ipv4()))
                    .collect();
                scheduled_mesh_targets.insert(a.cell_id.clone(), (node_ids, endpoints));
            }
        }

        let op_id = uuid::Uuid::new_v4().simple().to_string();
        let mut op = DeploymentOperation {
            operation_id: op_id.clone(),
            app_name: app.clone(),
            manifest_digest: validated.canonical_digest.clone(),
            status: OperationStatus::Reconciling,
            plan: plan.clone(),
            started_at_ms: now_ms(),
            finished_at_ms: None,
        };
        let op_key = Self::op_record_key(&op_id);
        let op_etag = cas
            .commit_manifest_cas(DEPLOYMENTS_BUCKET, &op_key, &op, None)
            .await?;

        let existing_rec = cas
            .read_manifest::<DeploymentRecord>(DEPLOYMENTS_BUCKET, &Self::app_record_key(app))
            .await?;
        let (mut next_cells, prev_rec_etag) = match existing_rec {
            Some((r, e)) => (r.cells, Some(e)),
            None => (BTreeMap::new(), None),
        };

        // Phase 1: Create / Update cells FIRST (existing removed cells stay alive until replacements succeed!)
        let reconcile_res: Result<()> = async {
            for act in &plan.actions {
                if !matches!(act.action, CellActionKind::Create | CellActionKind::Update) {
                    continue;
                }
                let compiled = validated.manifest.compile_cell(
                    &act.cell_id,
                    operator_policy,
                    deployer_auth,
                )?;
                let spec = &validated.manifest.cells[&act.cell_id];
                let cell_digest = blake3::hash(&serde_json::to_vec(spec)?).to_hex().to_string();

                // Persist declarative CellDbConfig first
                cells
                    .set_db_config(app, &act.cell_id, compiled.db_config.clone())
                    .await?;

                // Resolve verified module bytes if present in registry; otherwise keep declarative artifact ref
                let module_bytes = if let Some(cid) = compiled.artifact.strip_prefix("blake3:") {
                    match cells.runtimes().resolve_runtime(cid).await {
                        Ok(crate::compute::wasm_registry::ResolvedRuntime::Wasm(b))
                        | Ok(crate::compute::wasm_registry::ResolvedRuntime::Aot(b)) => b,
                        Err(_) => Vec::new(),
                    }
                } else {
                    Vec::new()
                };

                cells
                    .wake_workload(
                        app,
                        &act.cell_id,
                        compiled.policy.clone(),
                        CellWorkload::WasiModule {
                            module_bytes,
                            args: spec.wasi.args.clone(),
                            env: vec![],
                            preopen_dirs: vec![],
                            fuel_limit: compiled.limits.max_fuel,
                        },
                    )
                    .await?;

                let live_state = cells.cell_state(app, &act.cell_id).await;
                let (assigned_nodes, mesh_endpoints) = scheduled_mesh_targets
                    .get(&act.cell_id)
                    .cloned()
                    .unwrap_or_else(|| (vec![blobs.node_id().to_string()], vec!["127.0.0.1".to_string()]));
                next_cells.insert(
                    act.cell_id.clone(),
                    DeployedCellState {
                        cell_id: act.cell_id.clone(),
                        artifact: compiled.artifact,
                        cell_digest,
                        effective_capabilities: compiled.effective_capabilities,
                        lifecycle_state: live_state,
                        placement: compiled.effective_placement,
                        migration_policy: compiled.migration_policy,
                        replicas: compiled.replicas,
                        assigned_nodes,
                        mesh_endpoints,
                    },
                );
            }

            // Phase 2: Only AFTER all Create/Update cells succeeded, hibernate removed cells
            for act in &plan.actions {
                if act.action == CellActionKind::Remove {
                    let _ = cells.hibernate(app, &act.cell_id).await;
                    next_cells.remove(&act.cell_id);
                }
            }

            // Phase 3: Commit durable DeploymentRecord via CAS
            let record = DeploymentRecord {
                app_name: app.clone(),
                app_version: validated.manifest.metadata.version.clone(),
                manifest_digest: validated.canonical_digest.clone(),
                topology_mode: validated.manifest.topology.mode,
                cells: next_cells,
                updated_at_ms: now_ms(),
            };
            cas.commit_manifest_cas(
                DEPLOYMENTS_BUCKET,
                &Self::app_record_key(app),
                &record,
                prev_rec_etag.as_deref(),
            )
            .await?;
            Ok(())
        }
        .await;

        op.finished_at_ms = Some(now_ms());
        match reconcile_res {
            Ok(()) => op.status = OperationStatus::Succeeded,
            Err(ref e) => op.status = OperationStatus::Failed(e.to_string()),
        }
        let _ = cas
            .commit_manifest_cas(DEPLOYMENTS_BUCKET, &op_key, &op, Some(&op_etag))
            .await;

        reconcile_res?;
        Ok(op)
    }

    pub async fn get_operation(
        blobs: &Arc<BlobBridge>,
        op_id: &str,
    ) -> Result<Option<DeploymentOperation>> {
        let cas = CasStore::new(blobs.clone());
        Ok(cas
            .read_manifest::<DeploymentOperation>(DEPLOYMENTS_BUCKET, &Self::op_record_key(op_id))
            .await?
            .map(|(op, _)| op))
    }

    pub async fn get_app(
        blobs: &Arc<BlobBridge>,
        app_name: &str,
    ) -> Result<Option<DeploymentRecord>> {
        let cas = CasStore::new(blobs.clone());
        Ok(cas
            .read_manifest::<DeploymentRecord>(DEPLOYMENTS_BUCKET, &Self::app_record_key(app_name))
            .await?
            .map(|(rec, _)| rec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use nexus_db::auth::{AuthLevel, Role};

    fn sample_cid() -> String {
        format!("blake3:{}", "a".repeat(64))
    }

    fn sample_manifest_toml(mode: &str) -> String {
        format!(
            r#"
api_version = "nexus.io/v1"
kind = "Application"

[metadata]
name = "shop"
version = "1.0.0"

[topology]
mode = "{mode}"

[defaults]
max_fuel = 10000000

[cells.api]
artifact = "{cid}"
replicas = 2

[cells.api.database]
mode = "none"
flavors = []
transports = []

[cells.api.capabilities]
allow = ["blob.read", "db.admin", "runtime.install"]

[cells.ledger]
artifact = "{cid}"
replicas = 1

[cells.ledger.database]
mode = "dedicated"
flavors = ["surql"]
transports = ["internal"]

[cells.ledger.capabilities]
allow = ["db.read", "db.write"]
"#,
            mode = mode,
            cid = sample_cid()
        )
    }

    #[test]
    fn manifest_round_trips_toml_json_and_enforces_strict_validation() {
        let m = AppManifest::from_toml(&sample_manifest_toml("modular")).unwrap();
        let validated = m.validate().unwrap();

        // Round-trip through JSON & TOML produces identical canonical digest
        let json = m.to_json().unwrap();
        let from_json = AppManifest::from_json(&json).unwrap().validate().unwrap();
        assert_eq!(validated.canonical_digest, from_json.canonical_digest);

        // Unknown fields fail loudly (deny_unknown_fields)
        let bad_field = format!("{}\nunknown_top_field = 123\n", sample_manifest_toml("modular"));
        assert!(AppManifest::from_toml(&bad_field).is_err());

        // Mutable OCI tags are rejected
        let mut mutable_oci = m.clone();
        mutable_oci.cells.get_mut("api").unwrap().artifact =
            "oci://ghcr.io/aereaco/quickjs:latest".into();
        assert!(mutable_oci.validate().is_err());

        // Inline secret value rejected
        let mut bad_secret = m.clone();
        bad_secret.cells.get_mut("api").unwrap().wasi.secret_refs = vec!["API_KEY=leaked".into()];
        assert!(bad_secret.validate().is_err());

        // Stateful cell with replicas > 1 rejected
        let mut bad_stateful = m.clone();
        bad_stateful.cells.get_mut("ledger").unwrap().replicas = 2;
        assert!(bad_stateful.validate().is_err());

        // Unimplemented MigrationPolicy::Replicated rejected
        let mut bad_repl = m.clone();
        bad_repl.cells.get_mut("ledger").unwrap().migration = Some(MigrationPolicy::Replicated);
        assert!(bad_repl.validate().is_err());
    }

    #[test]
    fn manifest_cannot_self_escalate_capabilities_past_deployer_iam() {
        let m = AppManifest::from_toml(&sample_manifest_toml("modular")).unwrap();
        let viewer = AuthContext {
            level: AuthLevel::Database("shop".into(), "api".into()),
            roles: vec![Role::Viewer],
            actor: Some("viewer1".into()),
            access_name: None,
            token_claims: None,
        };
        let compiled = m
            .compile_cell("api", &CapabilitySet::admin_all(), Some(&viewer))
            .unwrap();
        // Viewer deployer cannot grant db.admin or runtime.install even though manifest requested them!
        assert!(compiled.effective_capabilities.has(Capability::BlobRead));
        assert!(!compiled.effective_capabilities.has(Capability::DbAdmin));
        assert!(!compiled.effective_capabilities.has(Capability::RuntimeInstall));
    }

    #[test]
    fn chart_resolution_is_deterministic_and_applies_typed_overrides() {
        let base = AppManifest::from_toml(&sample_manifest_toml("monolith")).unwrap();
        let chart = ChartPackage {
            meta: ChartMeta {
                api_version: MANIFEST_API_VERSION.into(),
                name: "shop-chart".into(),
                version: "1.0.0".into(),
                description: Some("Shop app".into()),
            },
            base_manifest: base,
            default_values: ChartValues {
                topology_mode: Some(DeploymentMode::Modular),
                ..Default::default()
            },
        };
        let mut overrides = ChartValues::default();
        overrides.cells.insert(
            "api".into(),
            CellValueOverride {
                replicas: Some(4),
                ..Default::default()
            },
        );
        let r1 = chart.resolve(Some(&overrides)).unwrap();
        let r2 = chart.resolve(Some(&overrides)).unwrap();
        assert_eq!(r1.canonical_digest, r2.canonical_digest);
        assert_eq!(r1.manifest.topology.mode, DeploymentMode::Modular);
        assert_eq!(r1.manifest.cells["api"].replicas, 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reconciler_deploys_monolith_and_modular_idempotently_and_rejects_mesh() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
        let cells = CellManager::new(db, blobs.clone());

        // 1. Deploy in `monolith` mode
        let mono = AppManifest::from_toml(&sample_manifest_toml("monolith"))
            .unwrap()
            .validate()
            .unwrap();
        let op1 = ManifestReconciler::apply(
            &cells,
            &blobs,
            &mono,
            &CapabilitySet::standard_cell(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(op1.status, OperationStatus::Succeeded);
        assert_eq!(op1.plan.actions.len(), 2);

        // 2. Re-applying identical manifest is a pure idempotent no-op
        let plan_noop = ManifestReconciler::plan(&blobs, &mono).await.unwrap();
        assert!(!plan_noop.has_changes());

        // 3. Evolve same app to `modular` mode + remove `api` cell
        let mut modular = AppManifest::from_toml(&sample_manifest_toml("modular")).unwrap();
        modular.cells.remove("api");
        let modular_val = modular.validate().unwrap();
        let op2 = ManifestReconciler::apply(
            &cells,
            &blobs,
            &modular_val,
            &CapabilitySet::standard_cell(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(op2.status, OperationStatus::Succeeded);
        let rec = ManifestReconciler::get_app(&blobs, "shop")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.cells.len(), 1);
        assert!(rec.cells.contains_key("ledger"));

        // 4. Mesh placement is explicitly rejected locally until mesh scheduler lands
        let mesh = AppManifest::from_toml(&sample_manifest_toml("mesh"))
            .unwrap()
            .validate()
            .unwrap();
        assert!(ManifestReconciler::apply(
            &cells,
            &blobs,
            &mesh,
            &CapabilitySet::standard_cell(),
            None,
        )
        .await
        .is_err());
    }
}
