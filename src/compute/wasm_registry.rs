use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{ACCEPT, AUTHORIZATION, LOCATION, USER_AGENT, WWW_AUTHENTICATE};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::compute::crystal::CrystalEngine;
use crate::storage::BlobBridge;

pub const RUNTIMES_BUCKET: &str = "nexus-runtimes";
pub const OCI_WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";
pub const OCI_NEXUS_POLICY_MEDIA_TYPE: &str = "application/vnd.nexus.policy.v1+json";

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeRecord {
    pub name: String,
    pub cid: String,
    pub size_bytes: usize,
    pub aot_cached: bool,
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

        // Shorthand `@aerea/postgres:16` -> `ghcr.io/aereaco/postgres:16`
        // Shorthand `@org/pkg[:tag]` -> `ghcr.io/org/pkg[:tag]`
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
            scheme: scheme.to_string(),
            registry: registry.to_string(),
            repository,
            reference,
            default_name,
        })
    }

    pub fn canonical(&self) -> String {
        format!("{}/{}:{}", self.registry, self.repository, self.reference)
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

/// Content-addressed registry of WASI guest runtimes stored in `BlobBridge` with automatic
/// AOT `.cwasm` precompilation and standard OCI Distribution v2 (`wkg` / GHCR) pull support.
#[derive(Clone)]
pub struct WasmRuntimeRegistry {
    blobs: Arc<BlobBridge>,
    index: Arc<RwLock<BTreeMap<String, RuntimeRecord>>>,
}

impl WasmRuntimeRegistry {
    pub fn new(blobs: Arc<BlobBridge>) -> Self {
        Self {
            blobs,
            index: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Register a `.wasm` or `.wat` guest runtime under `name` (e.g. `"quickjs"`, `"php-cgi"`, `"sqlite"`),
    /// store it content-addressed in `BlobBridge`, and pre-compile an AOT `.cwasm` artifact on non-iOS.
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
        let norm = name.trim().to_ascii_lowercase();
        if norm.is_empty() {
            anyhow::bail!("Runtime name cannot be empty");
        }
        let _ = self.blobs.create_bucket(RUNTIMES_BUCKET).await;

        let cid = blake3::hash(wasm_or_wat).to_hex().to_string();
        let raw_bytes = Bytes::copy_from_slice(wasm_or_wat);
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("raw/{}.wasm", norm), raw_bytes.clone())
            .await?;
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("cid/{}", cid), raw_bytes)
            .await?;

        #[cfg(not(target_os = "ios"))]
        let aot_cached = {
            let input = wasm_or_wat.to_vec();
            let compiled = tokio::task::spawn_blocking(move || {
                let crystal = CrystalEngine::new()?;
                crystal.compile_aot(&input)
            })
            .await??;
            let aot_bytes = Bytes::from(compiled);
            self.blobs
                .put_object(RUNTIMES_BUCKET, &format!("aot/{}.cwasm", norm), aot_bytes.clone())
                .await?;
            self.blobs
                .put_object(RUNTIMES_BUCKET, &format!("aot-cid/{}.cwasm", cid), aot_bytes)
                .await?;
            true
        };

        #[cfg(target_os = "ios")]
        let aot_cached = false;

        let rec = RuntimeRecord {
            name: norm.clone(),
            cid,
            size_bytes: wasm_or_wat.len(),
            aot_cached,
            oci_source,
            sha256_digest,
            requested_policy,
        };
        self.index.write().await.insert(norm, rec.clone());
        Ok(rec)
    }

    /// Pull a Wasm guest runtime from any OCI Distribution v2 registry (GHCR, Docker Hub, Zot,
    /// Wasm Directory / `wkg`, or local OCI mirror), verify its SHA-256 digest, parse any optional
    /// `application/vnd.nexus.policy.v1+json` requested-capability layer, store it in `BlobBridge`,
    /// and pre-compile an AOT `.cwasm` artifact.
    pub async fn pull_oci(
        &self,
        alias_name: Option<&str>,
        oci_ref_str: &str,
    ) -> Result<RuntimeRecord> {
        let oci = OciRef::parse(oci_ref_str)?;
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
        let (manifest_bytes, bearer) = oci_http_get(&manifest_url, Some(accept), None).await?;

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

        let wasm_layer = manifest
            .layers
            .iter()
            .find(|l| {
                matches!(
                    l.media_type.as_deref(),
                    Some(OCI_WASM_LAYER_MEDIA_TYPE) | Some("application/wasm")
                )
            })
            .or_else(|| {
                manifest
                    .layers
                    .iter()
                    .find(|l| l.media_type.as_deref() != Some(OCI_NEXUS_POLICY_MEDIA_TYPE))
            })
            .ok_or_else(|| anyhow!("OCI manifest '{}' contains no Wasm layer", oci.canonical()))?;

        let wasm_url = format!(
            "{}://{}/v2/{}/blobs/{}",
            oci.scheme, oci.registry, oci.repository, wasm_layer.digest
        );
        let (wasm_bytes, _) = oci_http_get(&wasm_url, None, bearer.as_deref()).await?;
        verify_sha256(&wasm_bytes, &wasm_layer.digest)?;

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
            let (policy_bytes, _) = oci_http_get(&policy_url, None, bearer.as_deref()).await?;
            verify_sha256(&policy_bytes, &policy_layer.digest)?;
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
        let norm = name.trim().to_ascii_lowercase();
        let _ = self.blobs.create_bucket(RUNTIMES_BUCKET).await;
        let cid = blake3::hash(aot_bytes).to_hex().to_string();
        let bytes = Bytes::copy_from_slice(aot_bytes);
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("aot/{}.cwasm", norm), bytes.clone())
            .await?;
        self.blobs
            .put_object(RUNTIMES_BUCKET, &format!("aot-cid/{}.cwasm", cid), bytes)
            .await?;

        let rec = RuntimeRecord {
            name: norm.clone(),
            cid,
            size_bytes: aot_bytes.len(),
            aot_cached: true,
            oci_source: None,
            sha256_digest: None,
            requested_policy: None,
        };
        self.index.write().await.insert(norm, rec.clone());
        Ok(rec)
    }

    /// Resolve a runtime by logical name (e.g. `"quickjs"`, `"sqlite"`) or BLAKE3 CID.
    /// Prefers pre-compiled AOT `.cwasm` from `BlobBridge`, falling back to raw `.wasm` in `BlobBridge`
    /// or local disk (`NEXUS_RUNTIMES_DIR` / `./runtimes/<name>.wasm`).
    pub async fn resolve_runtime(&self, name_or_cid: &str) -> Result<ResolvedRuntime> {
        let key = name_or_cid.trim().to_ascii_lowercase();

        for aot_key in [format!("aot/{}.cwasm", key), format!("aot-cid/{}.cwasm", key)] {
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

    pub async fn list_runtimes(&self) -> Vec<RuntimeRecord> {
        self.index.read().await.values().cloned().collect()
    }
}

fn verify_sha256(bytes: &[u8], expected_digest: &str) -> Result<()> {
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

/// Minimal zero-bloat HTTP/HTTPS GET client for OCI Distribution v2 supporting
/// standard `WWW-Authenticate: Bearer` token exchange and CDN redirects.
async fn oci_http_get(
    url: &str,
    accept: Option<&str>,
    initial_bearer: Option<&str>,
) -> Result<(Vec<u8>, Option<String>)> {
    let mut bearer = initial_bearer.map(ToString::to_string);
    let mut current_url = url.to_string();

    for _ in 0..5 {
        let (status, headers, body) = raw_http_get(&current_url, accept, bearer.as_deref()).await?;

        if status.is_success() {
            return Ok((body, bearer));
        }
        if status.is_redirection() {
            if let Some(loc) = headers.get(LOCATION).and_then(|v| v.to_str().ok()) {
                current_url = loc.to_string();
                continue;
            }
        }
        if status == StatusCode::UNAUTHORIZED && bearer.is_none() {
            if let Some(challenge) = headers.get(WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()) {
                if let Some(token_url) = build_bearer_token_url(challenge) {
                    let (tok_status, _, tok_body) = raw_http_get(&token_url, None, None).await?;
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

fn build_bearer_token_url(www_auth: &str) -> Option<String> {
    let rest = www_auth.trim().strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        let val = v.trim().trim_matches('"');
        match k.trim().to_ascii_lowercase().as_str() {
            "realm" => realm = Some(val.to_string()),
            "service" => service = Some(val.to_string()),
            "scope" => scope = Some(val.to_string()),
            _ => {}
        }
    }
    let mut url = realm?;
    let mut sep = if url.contains('?') { '&' } else { '?' };
    if let Some(s) = service {
        url.push_str(&format!("{}service={}", sep, s));
        sep = '&';
    }
    if let Some(sc) = scope {
        url.push_str(&format!("{}scope={}", sep, sc));
    }
    Some(url)
}

async fn raw_http_get(
    url: &str,
    accept: Option<&str>,
    bearer: Option<&str>,
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

    let resp = if is_https {
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
    let collected = resp.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, headers, collected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parses_aerea_shorthand_and_standard_oci_refs() {
        let r1 = OciRef::parse("@aerea/postgres:16").unwrap();
        assert_eq!(r1.registry, "ghcr.io");
        assert_eq!(r1.repository, "aereaco/postgres");
        assert_eq!(r1.reference, "16");
        assert_eq!(r1.default_name, "postgres");

        let r2 = OciRef::parse("@aerea/quickjs").unwrap();
        assert_eq!(r2.canonical(), "ghcr.io/aereaco/quickjs:latest");

        let r3 = OciRef::parse("oci://registry.example.com/team/pglite:0.2").unwrap();
        assert_eq!(r3.registry, "registry.example.com");
        assert_eq!(r3.repository, "team/pglite");
        assert_eq!(r3.reference, "0.2");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pulls_wasm_and_nexus_policy_from_oci_v2_registry_and_verifies_sha256() {
        let wasm_payload = br#"(module (func (export "_start")))"#.to_vec();
        let wasm_digest = format!("sha256:{}", hex::encode(Sha256::digest(&wasm_payload)));

        let policy = NexusPackagePolicy {
            default_cell_policy: Some("elastic".to_string()),
            max_fuel: Some(10_000_000),
            max_memory_mb: Some(64),
            requested_capabilities: vec!["nexus_db_query".to_string()],
            db_flavors: vec!["surql".to_string(), "sqlite".to_string()],
            wit_world: Some("nexus:cell/handler@0.1.0".to_string()),
        };
        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        let policy_digest = format!("sha256:{}", hex::encode(Sha256::digest(&policy_bytes)));

        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                {
                    "mediaType": OCI_WASM_LAYER_MEDIA_TYPE,
                    "digest": wasm_digest,
                    "size": wasm_payload.len()
                },
                {
                    "mediaType": OCI_NEXUS_POLICY_MEDIA_TYPE,
                    "digest": policy_digest,
                    "size": policy_bytes.len()
                }
            ]
        });
        let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let m_bytes = manifest_bytes.clone();
        let w_bytes = wasm_payload.clone();
        let p_bytes = policy_bytes.clone();
        let w_dig = wasm_digest.clone();
        let p_dig = policy_digest.clone();
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req_line = String::from_utf8_lossy(&buf[..n]);
                let path = req_line
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, body) = if path.contains("/manifests/") {
                    ("200 OK", m_bytes.as_slice())
                } else if path.ends_with(&w_dig) {
                    ("200 OK", w_bytes.as_slice())
                } else if path.ends_with(&p_dig) {
                    ("200 OK", p_bytes.as_slice())
                } else {
                    ("404 Not Found", b"not found".as_slice())
                };
                let header = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
        });

        let db = Arc::new(Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db).await.unwrap());
        let registry = WasmRuntimeRegistry::new(blobs);

        let rec = registry
            .pull_oci(None, &format!("http://{}/aereaco/quickjs:1.0", addr))
            .await
            .unwrap();
        assert_eq!(rec.name, "quickjs");
        assert!(rec.aot_cached);
        assert_eq!(rec.sha256_digest.as_deref(), Some(wasm_digest.as_str()));
        assert_eq!(rec.requested_policy, Some(policy));

        // Verify SHA-256 verification catches tampered blobs
        assert!(verify_sha256(b"tampered", &wasm_digest).is_err());
    }
}
