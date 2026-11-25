use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::compute::crystal::CrystalEngine;
use crate::observability::global_metrics;
use crate::storage::{BlobBridge, CasStore};

pub const RUNTIMES_BUCKET: &str = "nexus-runtimes";
const CATALOG_INDEX_KEY: &str = "index.json";

/// Runtime compatibility key binding AOT `.cwasm` artifacts to the exact Wasmtime major version,
/// target OS, and CPU architecture so incompatible pre-compiled machine code is never loaded.
pub fn current_aot_compat_key() -> String {
    format!(
        "wasmtime-51-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Explicit trust mode distinguishing development vs. production registry policies.
/// In `AllowlistOnly` mode, an empty `allowed_registries` list fails closed (never silently allows any host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Production default: ONLY registries in `allowed_registries` (plus loopback in dev) are accepted.
    AllowlistOnly,
    /// Explicit development opt-in: allows pulling from any HTTPS registry.
    AllowAnyDev,
}

impl Default for TrustMode {
    fn default() -> Self {
        if std::env::var("NEXUS_ENV").as_deref() == Ok("dev") {
            Self::AllowAnyDev
        } else {
            Self::AllowlistOnly
        }
    }
}

/// Operator trust policy governing which OCI registries/publishers may be installed and
/// whether installed runtime names are immutable (must be explicitly uninstalled before replacing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTrustPolicy {
    pub mode: TrustMode,
    /// Allowed OCI registry hostnames (e.g. `["ghcr.io"]`). Empty + `AllowlistOnly` fails closed!
    pub allowed_registries: Vec<String>,
    /// When true, registering an already-installed runtime name with a different CID is rejected
    /// until `uninstall_runtime()` is explicitly called.
    pub immutable_versions: bool,
}

impl Default for RuntimeTrustPolicy {
    fn default() -> Self {
        Self {
            mode: TrustMode::default(),
            allowed_registries: vec!["ghcr.io".to_string()],
            immutable_versions: false,
        }
    }
}

/// Strict validation of runtime names/aliases (prevents path traversal, control chars, or empty keys).
pub fn validate_runtime_name(name: &str) -> Result<String> {
    let norm = name.trim().to_ascii_lowercase();
    if norm.is_empty() || norm.len() > 64 {
        anyhow::bail!("Invalid runtime name '{}': must be 1..=64 characters", name);
    }
    if norm.contains("..") || norm.starts_with('.') || norm.starts_with('-') {
        anyhow::bail!("Invalid runtime name '{}': illegal leading char or '..'", name);
    }
    if !norm
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        anyhow::bail!(
            "Invalid runtime name '{}': only [a-z0-9._-] characters are allowed",
            name
        );
    }
    Ok(norm)
}

pub const OCI_WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";
pub const OCI_NEXUS_POLICY_MEDIA_TYPE: &str = "application/vnd.nexus.policy.v1+json";
pub const SUPPORTED_WASM_MEDIA_TYPES: &[&str] = &[
    OCI_WASM_LAYER_MEDIA_TYPE,
    "application/wasm",
    "application/vnd.oci.image.layer.v1.tar+wasm",
];

#[cfg(feature = "oci-registry")]
pub const MAX_OCI_MANIFEST_BYTES: usize = 1024 * 1024; // 1 MiB
#[cfg(feature = "oci-registry")]
pub const MAX_OCI_POLICY_BYTES: usize = 256 * 1024; // 256 KiB
#[cfg(feature = "oci-registry")]
pub const DEFAULT_MAX_OCI_WASM_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Optional Nexus-specific capability & policy manifest embedded in an OCI Wasm artifact
/// (`application/vnd.nexus.policy.v1+json`).
///
/// SECURITY CONTRACT: Treated strictly as *requested* capabilities — never self-granted authority.
/// The local microkernel IAM and operator policy always cap or approve actual runtime grants.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NexusPackagePolicy {
    pub default_cell_policy: Option<String>,
    pub max_fuel: Option<u64>,
    pub max_memory_mb: Option<u32>,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    #[serde(default)]
    pub db_flavors: Vec<String>,
    pub wit_world: Option<String>,
}

/// Metadata for a registered WASI guest runtime (e.g. `quickjs`, `php-cgi`, `sqlite`, `pglite`, `duckdb`, `nexus-db`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRecord {
    pub name: String,
    pub cid: String,
    pub size_bytes: usize,
    pub aot_cached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aot_compat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oci_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_policy: Option<NexusPackagePolicy>,
}

/// Parsed OCI Distribution v2 artifact reference.
/// Supports `@aerea/<pkg>[:tag]` -> `ghcr.io/aereaco/<pkg>:<tag>`, `@org/<pkg>[:tag]` -> `ghcr.io/org/<pkg>:<tag>`,
/// `oci://registry/repo:tag`, `http://127.0.0.1:5000/repo:tag`, and `ghcr.io/org/pkg:tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRef {
    pub scheme: String,
    pub registry: String,
    pub repository: String,
    pub reference: String,
    pub default_name: String,
}

impl OciRef {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("OCI reference cannot be empty");
        }

        let expanded = if let Some(rest) = trimmed.strip_prefix('@') {
            if let Some(pkg) = rest.strip_prefix("aerea/") {
                format!("https://ghcr.io/aereaco/{}", pkg)
            } else {
                format!("https://ghcr.io/{}", rest)
            }
        } else if let Some(rest) = trimmed.strip_prefix("oci://") {
            format!("https://{}", rest)
        } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let (scheme, after_scheme) = expanded
            .split_once("://")
            .ok_or_else(|| anyhow!("Invalid OCI reference '{}'", raw))?;
        let (registry, repo_and_ref) = after_scheme
            .split_once('/')
            .ok_or_else(|| anyhow!("OCI reference '{}' missing repository path", raw))?;

        let (repository, reference) = if let Some((repo, digest)) = repo_and_ref.split_once('@') {
            (repo.to_string(), digest.to_string())
        } else if let Some((repo, tag)) = repo_and_ref.rsplit_once(':') {
            (repo.to_string(), tag.to_string())
        } else {
            (repo_and_ref.to_string(), "latest".to_string())
        };

        let default_name = repository
            .rsplit('/')
            .next()
            .unwrap_or(&repository)
            .to_ascii_lowercase();

        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            registry: registry.to_string(),
            repository,
            reference,
            default_name,
        })
    }

    pub fn canonical(&self) -> String {
        format!("{}/{}:{}", self.registry, self.repository, self.reference)
    }

    /// True if the registry host is a local loopback address (`127.0.0.1`, `localhost`, `[::1]`).
    pub fn is_loopback(&self) -> bool {
        let host = self
            .registry
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
            .unwrap_or_else(|| self.registry.split(':').next().unwrap_or(&self.registry));
        matches!(host, "127.0.0.1" | "localhost" | "::1")
    }
}

/// Resolved executable artifact ready for `CrystalEngine`.
#[derive(Debug, Clone)]
pub enum ResolvedRuntime {
    /// Pre-compiled native `.cwasm` artifact (sub-millisecond instantiation, iOS `W^X` safe).
    Aot(Vec<u8>),
    /// Raw `.wasm` or `.wat` module bytes (compiled via Cranelift on non-iOS).
    Wasm(Vec<u8>),
}

/// Content-addressed, restart-persistent registry of WASI guest runtimes stored in `BlobBridge`
/// with automatic AOT `.cwasm` precompilation and optional hardened OCI Distribution v2 pull support
/// (`oci-registry` feature).
#[derive(Clone)]
pub struct WasmRuntimeRegistry {
    blobs: Arc<BlobBridge>,
    cas: CasStore,
    index: Arc<RwLock<BTreeMap<String, RuntimeRecord>>>,
    index_etag: Arc<RwLock<Option<String>>>,
    trust_policy: Arc<RwLock<RuntimeTrustPolicy>>,
    hydrated: Arc<RwLock<bool>>,
}

impl WasmRuntimeRegistry {
    pub fn new(blobs: Arc<BlobBridge>) -> Self {
        let cas = CasStore::new(blobs.clone());
        Self {
            blobs,
            cas,
            index: Arc::new(RwLock::new(BTreeMap::new())),
            index_etag: Arc::new(RwLock::new(None)),
            trust_policy: Arc::new(RwLock::new(RuntimeTrustPolicy::default())),
            hydrated: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn set_trust_policy(&self, policy: RuntimeTrustPolicy) {
        *self.trust_policy.write().await = policy;
    }

    /// Lazily hydrate the durable catalog index (`index.json`) and its CAS ETag from `BlobBridge`.
    async fn ensure_hydrated(&self) -> Result<()> {
        if *self.hydrated.read().await {
            return Ok(());
        }
        let mut h = self.hydrated.write().await;
        if *h {
            return Ok(());
        }
        if let Some((persisted, etag)) = self
            .cas
            .read_manifest::<BTreeMap<String, RuntimeRecord>>(RUNTIMES_BUCKET, CATALOG_INDEX_KEY)
            .await?
        {
            let mut idx = self.index.write().await;
            for (k, v) in persisted {
                idx.entry(k).or_insert(v);
            }
            *self.index_etag.write().await = Some(etag);
        }
        *h = true;
        Ok(())
    }

    /// Atomically persist the durable catalog index (`index.json`) via CAS `commit_manifest_cas`.
    async fn persist_index(&self) -> Result<()> {
        let snapshot = self.index.read().await.clone();
        let expected = self.index_etag.read().await.clone();
        let new_etag = self
            .cas
            .commit_manifest_cas(RUNTIMES_BUCKET, CATALOG_INDEX_KEY, &snapshot, expected.as_deref())
            .await
            .with_context(|| "Atomic CAS commit failed for WasmRuntimeRegistry index.json")?;
        *self.index_etag.write().await = Some(new_etag);
        Ok(())
    }

    /// Crash-safe runtime uninstall:
    /// 1. Atomically commits the updated catalog index FIRST via CAS (restoring in-memory state if CAS fails).
    /// 2. Only AFTER the durable catalog transition succeeds, deletes alias keys and any unreferenced
    ///    content-addressed CID blobs (preserving blobs still referenced by another runtime alias).
    pub async fn uninstall_runtime(&self, name: &str) -> Result<bool> {
        self.ensure_hydrated().await?;
        let norm = validate_runtime_name(name)?;
        let removed_rec = self.index.write().await.remove(&norm);
        let Some(rec) = removed_rec else {
            return Ok(false);
        };

        // Step 1: Persist durable catalog transition FIRST
        if let Err(e) = self.persist_index().await {
            // Roll back in-memory removal on CAS/storage failure
            self.index.write().await.insert(norm, rec);
            return Err(e);
        }

        // Step 2: Reclaim name aliases and unreferenced CID blobs ONLY after durable commit succeeded
        let compat = current_aot_compat_key();
        let _ = self
            .blobs
            .delete_object(RUNTIMES_BUCKET, &format!("raw/{}.wasm", norm))
            .await;
        let _ = self
            .blobs
            .delete_object(RUNTIMES_BUCKET, &format!("aot/{}/{}.cwasm", compat, norm))
            .await;

        let cid_still_referenced = self
            .index
            .read()
            .await
            .values()
            .any(|other| other.cid == rec.cid);
        if !cid_still_referenced {
            let _ = self
                .blobs
                .delete_object(RUNTIMES_BUCKET, &format!("cid/{}", rec.cid))
                .await;
            let _ = self
                .blobs
                .delete_object(RUNTIMES_BUCKET, &format!("aot-cid/{}/{}.cwasm", compat, rec.cid))
                .await;
        }
        Ok(true)
    }

    /// Register a `.wasm` or `.wat` guest runtime under `name` (e.g. `"quickjs"`, `"php-cgi"`, `"sqlite"`),
    /// store it content-addressed in `BlobBridge`, pre-compile an AOT `.cwasm` artifact on non-iOS,
    /// and persist the updated catalog index.
    pub async fn register_runtime(&self, name: &str, wasm_or_wat: &[u8]) -> Result<RuntimeRecord> {
        self.register_runtime_with_meta(name, wasm_or_wat, None, None, None)
            .await
    }

    async fn register_runtime_with_meta(
        &self,
        name: &str,
        wasm_or_wat: &[u8],
        oci_source: Option<String>,
        sha256_digest: Option<String>,
        requested_policy: Option<NexusPackagePolicy>,
    ) -> Result<RuntimeRecord> {
        self.ensure_hydrated().await?;
        let norm = validate_runtime_name(name)?;
        let _ = self.blobs.create_bucket(RUNTIMES_BUCKET).await;

        let cid = blake3::hash(wasm_or_wat).to_hex().to_string();

        // Enforce immutable version policy if enabled
        let policy = self.trust_policy.read().await.clone();
        if policy.immutable_versions {
            if let Some(existing) = self.index.read().await.get(&norm) {
                if existing.cid != cid {
                    anyhow::bail!(
                        "Runtime '{}' is immutable (installed CID {}). Uninstall first or publish under a new versioned name.",
                        norm,
                        existing.cid
                    );
                }
            }
        }

        // Compile AOT first (before writing to catalog) so invalid Wasm fails cleanly without polluting state
        #[cfg(not(target_os = "ios"))]
        let compiled_aot = {
            let input = wasm_or_wat.to_vec();
            match tokio::task::spawn_blocking(move || {
                let crystal = CrystalEngine::new()?;
                crystal.compile_aot(&input)
            })
            .await?
            {
                Ok(b) => b,
                Err(e) => {
                    global_metrics().inc_registry_aot_failure();
                    return Err(e);
                }
            }
        };

        let raw_bytes = Bytes::copy_from_slice(wasm_or_wat);
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("raw/{}.wasm", norm), raw_bytes.clone())
            .await?;
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("cid/{}", cid), raw_bytes)
            .await?;

        let compat = current_aot_compat_key();
        #[cfg(not(target_os = "ios"))]
        let (aot_cached, aot_compat) = {
            let aot_bytes = Bytes::from(compiled_aot);
            self.blobs
                .put_object(RUNTIMES_BUCKET, &format!("aot/{}/{}.cwasm", compat, norm), aot_bytes.clone())
                .await?;
            self.blobs
                .put_object(RUNTIMES_BUCKET, &format!("aot-cid/{}/{}.cwasm", compat, cid), aot_bytes)
                .await?;
            (true, Some(compat))
        };

        #[cfg(target_os = "ios")]
        let (aot_cached, aot_compat) = (false, None);

        let rec = RuntimeRecord {
            name: norm.clone(),
            cid,
            size_bytes: wasm_or_wat.len(),
            aot_cached,
            aot_compat,
            oci_source,
            sha256_digest,
            requested_policy,
        };
        self.index.write().await.insert(norm, rec.clone());
        self.persist_index().await?;
        global_metrics().inc_registry_register();
        Ok(rec)
    }

    /// Pull a Wasm guest runtime from any OCI Distribution v2 registry (GHCR, Docker Hub, Zot,
    /// Wasm Directory / `wkg`, or local OCI mirror) with full transport & artifact hardening:
    /// - Enforces HTTPS for remote registries (unless `NEXUS_OCI_ALLOW_INSECURE=1` or loopback).
    /// - Strips `Authorization` Bearer credentials on cross-origin redirects & blocks HTTPS→HTTP downgrade.
    /// - Verifies manifest SHA-256 when pinned by `@sha256:...` digest.
    /// - Requires an explicitly supported Wasm media type (no blind fallback).
    /// - Enforces streaming byte caps on manifests (1 MiB), policies (256 KiB), and Wasm blobs (64 MiB default).
    /// - Verifies SHA-256 digest of both Wasm and policy layers before AOT compilation & durable catalog commit.
    #[cfg(feature = "oci-registry")]
    pub async fn pull_oci(
        &self,
        alias_name: Option<&str>,
        oci_ref_str: &str,
    ) -> Result<RuntimeRecord> {
        let max_wasm = std::env::var("NEXUS_OCI_MAX_WASM_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|mb| mb.saturating_mul(1024 * 1024))
            .unwrap_or(DEFAULT_MAX_OCI_WASM_BYTES);
        self.pull_oci_with_limits(
            alias_name,
            oci_ref_str,
            MAX_OCI_MANIFEST_BYTES,
            MAX_OCI_POLICY_BYTES,
            max_wasm,
        )
        .await
    }

    #[cfg(feature = "oci-registry")]
    pub async fn pull_oci_with_limits(
        &self,
        alias_name: Option<&str>,
        oci_ref_str: &str,
        max_manifest_bytes: usize,
        max_policy_bytes: usize,
        max_wasm_bytes: usize,
    ) -> Result<RuntimeRecord> {
        let oci = OciRef::parse(oci_ref_str)?;

        // Enforce operator registry trust policy (explicit dev vs. production fail-closed)
        {
            let policy = self.trust_policy.read().await;
            if policy.mode == TrustMode::AllowlistOnly && !oci.is_loopback() {
                let allowed = policy
                    .allowed_registries
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(&oci.registry));
                if !allowed {
                    global_metrics().inc_iam_auth_denial();
                    anyhow::bail!(
                        "Registry '{}' denied by RuntimeTrustPolicy (mode=AllowlistOnly, allowed={:?})",
                        oci.registry,
                        policy.allowed_registries
                    );
                }
            }
        }
        global_metrics().inc_registry_pull();

        // Transport security: require HTTPS for non-loopback registries unless explicitly opted in
        if oci.scheme != "https" {
            let allow_insecure = std::env::var("NEXUS_OCI_ALLOW_INSECURE").as_deref() == Ok("1");
            if !oci.is_loopback() && !allow_insecure {
                anyhow::bail!(
                    "Refusing insecure HTTP OCI pull from remote host '{}'. Use https:// or set NEXUS_OCI_ALLOW_INSECURE=1.",
                    oci.registry
                );
            }
        }

        let install_name = alias_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&oci.default_name)
            .to_ascii_lowercase();

        let manifest_url = format!(
            "{}://{}/v2/{}/manifests/{}",
            oci.scheme, oci.registry, oci.repository, oci.reference
        );
        let accept = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
        let (manifest_bytes, bearer) =
            oci_client::oci_http_get(&manifest_url, Some(accept), None, max_manifest_bytes).await?;

        // If pinned by digest (`@sha256:...`), verify manifest bytes against the digest
        if oci.reference.starts_with("sha256:") {
            oci_client::verify_sha256(&manifest_bytes, &oci.reference)?;
        }

        #[derive(Deserialize)]
        struct OciDescriptor {
            #[serde(rename = "mediaType")]
            media_type: Option<String>,
            digest: String,
        }
        #[derive(Deserialize)]
        struct OciManifest {
            #[serde(default)]
            layers: Vec<OciDescriptor>,
        }

        let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("Failed to parse OCI manifest from {}", manifest_url))?;

        // Strict Wasm media-type allowlist (no blind fallback to arbitrary layers)
        let wasm_layer = manifest
            .layers
            .iter()
            .find(|l| {
                l.media_type
                    .as_deref()
                    .map(|mt| SUPPORTED_WASM_MEDIA_TYPES.contains(&mt))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                anyhow!(
                    "OCI manifest '{}' contains no supported Wasm layer (expected one of: {})",
                    oci.canonical(),
                    SUPPORTED_WASM_MEDIA_TYPES.join(", ")
                )
            })?;

        let wasm_url = format!(
            "{}://{}/v2/{}/blobs/{}",
            oci.scheme, oci.registry, oci.repository, wasm_layer.digest
        );
        let (wasm_bytes, _) =
            oci_client::oci_http_get(&wasm_url, None, bearer.as_deref(), max_wasm_bytes).await?;
        oci_client::verify_sha256(&wasm_bytes, &wasm_layer.digest)?;

        let mut requested_policy = None;
        if let Some(policy_layer) = manifest
            .layers
            .iter()
            .find(|l| l.media_type.as_deref() == Some(OCI_NEXUS_POLICY_MEDIA_TYPE))
        {
            let policy_url = format!(
                "{}://{}/v2/{}/blobs/{}",
                oci.scheme, oci.registry, oci.repository, policy_layer.digest
            );
            let (policy_bytes, _) =
                oci_client::oci_http_get(&policy_url, None, bearer.as_deref(), max_policy_bytes)
                    .await?;
            oci_client::verify_sha256(&policy_bytes, &policy_layer.digest)?;
            let parsed: NexusPackagePolicy = serde_json::from_slice(&policy_bytes)
                .with_context(|| "Failed to parse NexusPackagePolicy OCI layer")?;
            requested_policy = Some(parsed);
        }

        self.register_runtime_with_meta(
            &install_name,
            &wasm_bytes,
            Some(oci.canonical()),
            Some(wasm_layer.digest.clone()),
            requested_policy,
        )
        .await
    }

    /// Register a pre-compiled AOT `.cwasm` runtime directly (used on iOS or when shipping pre-compiled artifacts).
    pub async fn register_aot_runtime(&self, name: &str, aot_bytes: &[u8]) -> Result<RuntimeRecord> {
        self.ensure_hydrated().await?;
        let norm = validate_runtime_name(name)?;
        let _ = self.blobs.create_bucket(RUNTIMES_BUCKET).await;
        let cid = blake3::hash(aot_bytes).to_hex().to_string();
        let compat = current_aot_compat_key();
        let bytes = Bytes::copy_from_slice(aot_bytes);
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("aot/{}/{}.cwasm", compat, norm), bytes.clone())
            .await?;
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("aot-cid/{}/{}.cwasm", compat, cid), bytes)
            .await?;

        let rec = RuntimeRecord {
            name: norm.clone(),
            cid,
            size_bytes: aot_bytes.len(),
            aot_cached: true,
            aot_compat: Some(compat),
            oci_source: None,
            sha256_digest: None,
            requested_policy: None,
        };
        self.index.write().await.insert(norm, rec.clone());
        self.persist_index().await?;
        Ok(rec)
    }

    /// Resolve a runtime by logical name (e.g. `"quickjs"`, `"sqlite"`) or BLAKE3 CID.
    /// Only loads AOT `.cwasm` artifacts matching `current_aot_compat_key()`.
    pub async fn resolve_runtime(&self, name_or_cid: &str) -> Result<ResolvedRuntime> {
        let key = name_or_cid.trim().to_ascii_lowercase();
        let compat = current_aot_compat_key();

        for aot_key in [
            format!("aot/{}/{}.cwasm", compat, key),
            format!("aot-cid/{}/{}.cwasm", compat, key),
        ] {
            if let Some(bytes) = self.blobs.get_object(RUNTIMES_BUCKET, &aot_key).await? {
                return Ok(ResolvedRuntime::Aot(bytes.to_vec()));
            }
        }

        for raw_key in [format!("raw/{}.wasm", key), format!("cid/{}", key)] {
            if let Some(bytes) = self.blobs.get_object(RUNTIMES_BUCKET, &raw_key).await? {
                return Ok(ResolvedRuntime::Wasm(bytes.to_vec()));
            }
        }

        let base_dir = std::env::var("NEXUS_RUNTIMES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("runtimes"));
        let disk_cwasm = base_dir.join(format!("{}.cwasm", key));
        if let Ok(bytes) = tokio::fs::read(&disk_cwasm).await {
            return Ok(ResolvedRuntime::Aot(bytes));
        }
        let disk_wasm = base_dir.join(format!("{}.wasm", key));
        if let Ok(bytes) = tokio::fs::read(&disk_wasm).await {
            return Ok(ResolvedRuntime::Wasm(bytes));
        }

        Err(anyhow!(
            "WASI runtime '{}' is not registered. Pull via `POST /cells/_runtimes/pull` or upload via `PUT /cells/_runtimes/{}`.",
            name_or_cid,
            key
        ))
    }

    /// List all installed runtimes (hydrating from durable `BlobBridge` catalog if needed).
    pub async fn list_runtimes(&self) -> Vec<RuntimeRecord> {
        let _ = self.ensure_hydrated().await;
        self.index.read().await.values().cloned().collect()
    }

    /// Lookup a specific installed runtime record by name (restart-aware).
    pub async fn get_runtime(&self, name: &str) -> Option<RuntimeRecord> {
        let _ = self.ensure_hydrated().await;
        self.index
            .read()
            .await
            .get(&name.trim().to_ascii_lowercase())
            .cloned()
    }
}

#[cfg(feature = "oci-registry")]
mod oci_client {
    use anyhow::{anyhow, Context, Result};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, LOCATION, USER_AGENT, WWW_AUTHENTICATE};
    use hyper::{Request, StatusCode, Uri};
    use hyper_util::rt::TokioIo;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::net::TcpStream;

    pub(super) fn verify_sha256(bytes: &[u8], expected_digest: &str) -> Result<()> {
        let expected = expected_digest
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("Unsupported OCI digest algorithm '{}'", expected_digest))?;
        let actual = hex::encode(Sha256::digest(bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            anyhow::bail!(
                "OCI blob SHA-256 mismatch: expected {}, got {}",
                expected,
                actual
            );
        }
        Ok(())
    }

    fn origin_tuple(url: &str) -> Result<(String, String, u16)> {
        let uri: Uri = url.parse().with_context(|| format!("Invalid URI '{}'", url))?;
        let scheme = uri.scheme_str().unwrap_or("https").to_ascii_lowercase();
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("Missing host in URI '{}'", url))?
            .to_ascii_lowercase();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok((scheme, host, port))
    }

    /// Hardened OCI Distribution v2 HTTP/HTTPS GET client:
    /// - Strips Bearer credentials on cross-origin redirects & blocks HTTPS→HTTP downgrades.
    /// - Enforces hard streaming size cap `max_bytes` before buffering into memory.
    /// - Handles RFC-compliant `WWW-Authenticate: Bearer` token exchange with percent-encoding.
    pub(super) async fn oci_http_get(
        url: &str,
        accept: Option<&str>,
        initial_bearer: Option<&str>,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Option<String>)> {
        let mut bearer = initial_bearer.map(ToString::to_string);
        let mut current_url = url.to_string();
        let mut current_origin = origin_tuple(&current_url)?;

        for _ in 0..5 {
            let (status, headers, body) =
                raw_http_get(&current_url, accept, bearer.as_deref(), max_bytes).await?;

            if status.is_success() {
                return Ok((body, bearer));
            }
            if status.is_redirection() {
                if let Some(loc) = headers.get(LOCATION).and_then(|v| v.to_str().ok()) {
                    let next_url = if loc.starts_with("http://") || loc.starts_with("https://") {
                        loc.to_string()
                    } else if loc.starts_with('/') {
                        format!(
                            "{}://{}:{}{}",
                            current_origin.0, current_origin.1, current_origin.2, loc
                        )
                    } else {
                        anyhow::bail!("Unsupported relative redirect location '{}'", loc);
                    };
                    let next_origin = origin_tuple(&next_url)?;
                    // Block HTTPS -> HTTP downgrade
                    if current_origin.0 == "https" && next_origin.0 != "https" {
                        anyhow::bail!(
                            "Refusing insecure HTTPS->HTTP redirect from '{}' to '{}'",
                            current_url,
                            next_url
                        );
                    }
                    // Strip Authorization Bearer credentials on any cross-origin redirect
                    if next_origin != current_origin {
                        bearer = None;
                    }
                    current_origin = next_origin;
                    current_url = next_url;
                    continue;
                }
            }
            if status == StatusCode::UNAUTHORIZED && bearer.is_none() {
                if let Some(challenge) = headers
                    .get(WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok())
                {
                    if let Some(token_url) = build_bearer_token_url(challenge) {
                        // Prevent HTTPS registry from redirecting auth to insecure HTTP token endpoint
                        if current_origin.0 == "https" && !token_url.starts_with("https://") {
                            anyhow::bail!(
                                "Refusing insecure HTTP Bearer realm '{}' from HTTPS registry",
                                token_url
                            );
                        }
                        let (tok_status, _, tok_body) =
                            raw_http_get(&token_url, None, None, 256 * 1024).await?;
                        if tok_status.is_success() {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&tok_body) {
                                if let Some(tok) = v
                                    .get("token")
                                    .or_else(|| v.get("access_token"))
                                    .and_then(|t| t.as_str())
                                {
                                    bearer = Some(tok.to_string());
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            anyhow::bail!("OCI HTTP GET '{}' failed with status {}", current_url, status);
        }

        anyhow::bail!("Too many redirects/auth challenges fetching '{}'", url)
    }

    /// RFC 6750 / RFC 7235-aware Bearer challenge parser with percent-encoded query parameters.
    /// Correctly handles quoted values containing commas or escaped quotes (`\"`).
    pub(super) fn build_bearer_token_url(www_auth: &str) -> Option<String> {
        let trimmed = www_auth.trim();
        let rest = if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            &trimmed[7..]
        } else {
            return None;
        };

        let mut params: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            let k_start = i;
            while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'=' {
                break;
            }
            let key = rest[k_start..i].trim().to_ascii_lowercase();
            i += 1; // skip '='
            while i < bytes.len() && bytes[i] == b' ' {
                i += 1;
            }
            let val = if i < bytes.len() && bytes[i] == b'"' {
                i += 1; // skip opening quote
                let mut buf = String::new();
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        buf.push(bytes[i + 1] as char);
                        i += 2;
                    } else if bytes[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        buf.push(bytes[i] as char);
                        i += 1;
                    }
                }
                buf
            } else {
                let v_start = i;
                while i < bytes.len() && bytes[i] != b',' {
                    i += 1;
                }
                rest[v_start..i].trim().to_string()
            };
            params.insert(key, val);
        }

        let mut url = params.remove("realm")?;
        let mut sep = if url.contains('?') { '&' } else { '?' };
        if let Some(s) = params.get("service") {
            url.push_str(&format!("{}service={}", sep, percent_encode(s)));
            sep = '&';
        }
        if let Some(sc) = params.get("scope") {
            url.push_str(&format!("{}scope={}", sep, percent_encode(sc)));
        }
        Some(url)
    }

    fn percent_encode(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for b in input.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }

    async fn raw_http_get(
        url: &str,
        accept: Option<&str>,
        bearer: Option<&str>,
        max_bytes: usize,
    ) -> Result<(StatusCode, hyper::HeaderMap, Vec<u8>)> {
        let uri: Uri = url.parse().with_context(|| format!("Invalid URI '{}'", url))?;
        let is_https = uri.scheme_str() == Some("https");
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("Missing host in URI '{}'", url))?
            .to_string();
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let host_header = if uri.port_u16().is_some() {
            format!("{}:{}", host, port)
        } else {
            host.clone()
        };

        let mut req_builder = Request::builder()
            .method("GET")
            .uri(path_and_query)
            .header(hyper::header::HOST, host_header)
            .header(USER_AGENT, "nexus-io/0.1 (oci-v2)");
        if let Some(a) = accept {
            req_builder = req_builder.header(ACCEPT, a);
        }
        if let Some(tok) = bearer {
            req_builder = req_builder.header(AUTHORIZATION, format!("Bearer {}", tok));
        }
        let req = req_builder.body(Empty::<Bytes>::new())?;

        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("Failed to connect to {}:{}", host, port))?;

        let mut resp = if is_https {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls_cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
            let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| anyhow!("Invalid TLS server name '{}'", host))?;
            let tls = connector.connect(server_name, tcp).await?;
            let io = TokioIo::new(tls);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await?
        } else {
            let io = TokioIo::new(tcp);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await?
        };

        let status = resp.status();
        let headers = resp.headers().clone();

        // Fast-fail if Content-Length exceeds cap before reading body
        if let Some(cl) = headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
        {
            if cl > max_bytes {
                anyhow::bail!(
                    "OCI response from '{}' exceeds max size limit ({} > {} bytes)",
                    url,
                    cl,
                    max_bytes
                );
            }
        }

        // Stream frames while strictly enforcing `max_bytes`
        let mut out = Vec::new();
        while let Some(frame_res) = resp.body_mut().frame().await {
            let frame = frame_res?;
            if let Some(data) = frame.data_ref() {
                if out.len().saturating_add(data.len()) > max_bytes {
                    anyhow::bail!(
                        "OCI response stream from '{}' exceeded max size limit ({} bytes)",
                        url,
                        max_bytes
                    );
                }
                out.extend_from_slice(data);
            }
        }

        Ok((status, headers, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn parses_aerea_shorthand_and_standard_oci_refs() {
        let r1 = OciRef::parse("@aerea/postgres:16").unwrap();
        assert_eq!(r1.registry, "ghcr.io");
        assert_eq!(r1.repository, "aereaco/postgres");
        assert_eq!(r1.reference, "16");
        assert_eq!(r1.default_name, "postgres");
        assert!(!r1.is_loopback());

        let r2 = OciRef::parse("@aerea/quickjs").unwrap();
        assert_eq!(r2.canonical(), "ghcr.io/aereaco/quickjs:latest");

        let r3 = OciRef::parse("oci://registry.example.com/team/pglite:0.2").unwrap();
        assert_eq!(r3.registry, "registry.example.com");
        assert_eq!(r3.repository, "team/pglite");
        assert_eq!(r3.reference, "0.2");

        let r4 = OciRef::parse("http://127.0.0.1:5000/aereaco/test:1.0").unwrap();
        assert!(r4.is_loopback());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_catalog_persists_and_recovers_across_restart() {
        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let reg1 = WasmRuntimeRegistry::new(blobs.clone());

        let wat = br#"(module (func (export "_start")))"#;
        let rec = reg1.register_runtime("quickjs", wat).await.unwrap();
        assert!(rec.aot_cached);

        // Invalid Wasm fails AOT compilation cleanly and does NOT pollute the catalog
        assert!(reg1.register_runtime("broken", b"not-valid-wasm").await.is_err());
        assert!(reg1.get_runtime("broken").await.is_none());

        // Simulate full process restart: brand-new WasmRuntimeRegistry over the same BlobBridge
        let reg2 = WasmRuntimeRegistry::new(blobs);
        let listed = reg2.list_runtimes().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "quickjs");
        assert_eq!(listed[0].cid, rec.cid);
    }

    #[cfg(feature = "oci-registry")]
    mod oci_security_tests {
        use super::*;
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        #[test]
        fn parses_quoted_bearer_challenge_and_percent_encodes_params() {
            let hdr = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:aereaco/quickjs:pull,push""#;
            let url = oci_client::build_bearer_token_url(hdr).unwrap();
            assert_eq!(
                url,
                "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aaereaco%2Fquickjs%3Apull%2Cpush"
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn rejects_insecure_http_for_remote_registries_by_default() {
            let db = Arc::new(Database::open_mem());
            let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
            let registry = WasmRuntimeRegistry::new(blobs);

            // 1. Untrusted registry rejected by default TrustMode::AllowlistOnly
            let err_trust = registry
                .pull_oci(None, "https://evil.example.com/org/pkg:1.0")
                .await
                .unwrap_err();
            assert!(err_trust.to_string().contains("denied by RuntimeTrustPolicy"));

            // 2. Allowlisted registry over insecure http:// still rejected by transport guard
            let err_http = registry
                .pull_oci(None, "http://ghcr.io/org/pkg:1.0")
                .await
                .unwrap_err();
            assert!(err_http.to_string().contains("Refusing insecure HTTP OCI pull"));
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn pulls_with_bearer_auth_verifies_manifest_and_layer_digests_and_persists() {
            let wasm_payload = br#"(module (func (export "_start")))"#.to_vec();
            let wasm_digest = format!("sha256:{}", hex::encode(Sha256::digest(&wasm_payload)));

            let policy = NexusPackagePolicy {
                default_cell_policy: Some("elastic".to_string()),
                max_fuel: Some(10_000_000),
                max_memory_mb: Some(64),
                requested_capabilities: vec!["nexus_db_query".to_string()],
                db_flavors: vec!["surql".to_string()],
                wit_world: Some("nexus:cell/handler@0.1.0".to_string()),
            };
            let policy_bytes = serde_json::to_vec(&policy).unwrap();
            let policy_digest = format!("sha256:{}", hex::encode(Sha256::digest(&policy_bytes)));

            let manifest_json = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [
                    { "mediaType": OCI_WASM_LAYER_MEDIA_TYPE, "digest": wasm_digest, "size": wasm_payload.len() },
                    { "mediaType": OCI_NEXUS_POLICY_MEDIA_TYPE, "digest": policy_digest, "size": policy_bytes.len() }
                ]
            });
            let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();
            let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let m_bytes = manifest_bytes.clone();
            let w_bytes = wasm_payload.clone();
            let p_bytes = policy_bytes.clone();
            let w_dig = wasm_digest.clone();
            let p_dig = policy_digest.clone();
            tokio::spawn(async move {
                for _ in 0..6 {
                    let Ok((mut sock, _)) = listener.accept().await else { break };
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");
                    let has_auth = req.contains("authorization: Bearer secret-tok")
                        || req.contains("Authorization: Bearer secret-tok");

                    if path.starts_with("/token") {
                        let body = br#"{"token":"secret-tok"}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.write_all(body).await;
                    } else if !has_auth {
                        let resp = format!(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"http://{}/token\",service=\"local\",scope=\"repository:aereaco/quickjs:pull\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            addr
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else {
                        let body = if path.contains("/manifests/") {
                            m_bytes.as_slice()
                        } else if path.ends_with(&w_dig) {
                            w_bytes.as_slice()
                        } else if path.ends_with(&p_dig) {
                            p_bytes.as_slice()
                        } else {
                            b""
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.write_all(body).await;
                    }
                }
            });

            let db = Arc::new(Database::open_mem());
            let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
            let registry = WasmRuntimeRegistry::new(blobs.clone());

            // Pull pinned by manifest SHA-256 digest through 401 Bearer challenge
            let rec = registry
                .pull_oci(None, &format!("http://{}/aereaco/quickjs@{}", addr, manifest_digest))
                .await
                .unwrap();
            assert_eq!(rec.name, "quickjs");
            assert!(rec.aot_cached);
            assert_eq!(rec.requested_policy, Some(policy));

            // Restart recovery: fresh registry reads durable index.json with OCI metadata intact
            let fresh = WasmRuntimeRegistry::new(blobs);
            let recovered = fresh.get_runtime("quickjs").await.unwrap();
            assert_eq!(recovered.sha256_digest.as_deref(), Some(wasm_digest.as_str()));
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn strips_bearer_token_on_cross_origin_redirect_and_enforces_size_and_media_type() {
            // 1. Cross-origin redirect test: server A redirects to server B (different port = different origin).
            //    Server B asserts NO Authorization header was forwarded!
            let server_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr_b = server_b.local_addr().unwrap();
            let b_saw_auth = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let b_flag = b_saw_auth.clone();
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = server_b.accept().await {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                    if req.contains("authorization:") {
                        b_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    let body = b"redirected-ok";
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(hdr.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                }
            });

            let server_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr_a = server_a.local_addr().unwrap();
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = server_a.accept().await {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let hdr = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{}/blob\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        addr_b
                    );
                    let _ = sock.write_all(hdr.as_bytes()).await;
                }
            });

            let (body, remaining_bearer) = oci_client::oci_http_get(
                &format!("http://{}/start", addr_a),
                None,
                Some("super-secret-token"),
                1024,
            )
            .await
            .unwrap();
            assert_eq!(body, b"redirected-ok");
            assert!(remaining_bearer.is_none());
            assert!(!b_saw_auth.load(std::sync::atomic::Ordering::SeqCst));

            // 2. Unsupported media type + oversized payload + malformed manifest tests
            let bad_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bad_addr = bad_srv.local_addr().unwrap();
            tokio::spawn(async move {
                for _ in 0..3 {
                    let Ok((mut sock, _)) = bad_srv.accept().await else { break };
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");
                    let body: Vec<u8> = if path.contains("bad-media") {
                        serde_json::to_vec(&serde_json::json!({
                            "schemaVersion": 2,
                            "layers": [{ "mediaType": "application/octet-stream", "digest": "sha256:0000" }]
                        })).unwrap()
                    } else if path.contains("malformed") {
                        b"{not-json".to_vec()
                    } else {
                        vec![b'A'; 2048]
                    };
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(hdr.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                }
            });

            let db = Arc::new(Database::open_mem());
            let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
            let registry = WasmRuntimeRegistry::new(blobs);

            // Unsupported media type rejected
            let err_media = registry
                .pull_oci(None, &format!("http://{}/org/bad-media:1", bad_addr))
                .await
                .unwrap_err();
            assert!(err_media.to_string().contains("no supported Wasm layer"));

            // Malformed manifest JSON rejected
            assert!(registry
                .pull_oci(None, &format!("http://{}/org/malformed:1", bad_addr))
                .await
                .is_err());

            // Oversized manifest rejected before buffering
            let err_size = registry
                .pull_oci_with_limits(
                    None,
                    &format!("http://{}/org/oversized:1", bad_addr),
                    512,
                    512,
                    512,
                )
                .await
                .unwrap_err();
            assert!(err_size.to_string().contains("exceeds max size limit"));
        }
    }
}
