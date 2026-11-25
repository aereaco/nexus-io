//! Hardened HTTP/1.1 Reverse Proxy (`serve-proxy` feature) with shared SSRF & DNS-pinning policy.
//!
//! Security properties:
//! - Startup-validated `UpstreamRegistry` parsed from `NEXUS_PROXY_UPSTREAMS` (`name=url,...`).
//! - Never accepts arbitrary client-supplied upstream URLs; disabled by default when unconfigured.
//! - Shared `DestinationPolicy` validates every resolved IP address (rejecting loopback, RFC1918
//!   private, link-local / cloud metadata `169.254.0.0/16`, CGNAT `100.64.0.0/10`, multicast,
//!   unspecified, and IPv4-mapped IPv6 ranges by default) and connects directly to the validated
//!   `SocketAddr` to prevent DNS rebinding between check and connect.
//! - Strips RFC 9110 hop-by-hop headers, enforces explicit request/response body & header limits,
//!   enforces connect & total request timeouts, and NEVER blindly follows upstream redirects.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::{Method, Request as HyperRequest, Uri};
use hyper_util::rt::TokioIo;
use salvo::prelude::*;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{lookup_host, TcpStream};

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_HEADERS: usize = 64;
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// Reusable destination-validation policy shared across gateway outbound features.
#[derive(Debug, Clone)]
pub struct DestinationPolicy {
    pub allow_loopback: bool,
    pub allow_private_ips: bool,
    pub allow_insecure_http: bool,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub max_headers: usize,
}

impl Default for DestinationPolicy {
    fn default() -> Self {
        Self {
            allow_loopback: std::env::var("NEXUS_PROXY_ALLOW_LOOPBACK").as_deref() == Ok("1"),
            allow_private_ips: std::env::var("NEXUS_PROXY_ALLOW_PRIVATE").as_deref() == Ok("1"),
            allow_insecure_http: std::env::var("NEXUS_PROXY_ALLOW_HTTP").as_deref() == Ok("1"),
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            max_headers: DEFAULT_MAX_HEADERS,
        }
    }
}

/// Returns `true` if `ip` belongs to a prohibited internal/SSRF range under `policy`.
pub fn is_prohibited_ip(ip: IpAddr, policy: &DestinationPolicy) -> bool {
    match ip {
        IpAddr::V4(v4) => is_prohibited_v4(v4, policy),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_prohibited_v4(mapped, policy);
            }
            if v6.is_loopback() {
                return !policy.allow_loopback;
            }
            if v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
            if is_link_local {
                return true;
            }
            if is_ula && !policy.allow_private_ips {
                return true;
            }
            false
        }
    }
}

fn is_prohibited_v4(v4: Ipv4Addr, policy: &DestinationPolicy) -> bool {
    let octets = v4.octets();
    if v4.is_loopback() {
        return !policy.allow_loopback;
    }
    // Unspecified, broadcast, multicast, link-local / cloud metadata (169.254.0.0/16)
    if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() || v4.is_link_local() {
        return true;
    }
    // 0.0.0.0/8 ("this network")
    if octets[0] == 0 {
        return true;
    }
    // RFC 6598 CGNAT (100.64.0.0/10)
    let is_cgnat = octets[0] == 100 && (octets[1] & 0xc0) == 64;
    if (v4.is_private() || is_cgnat) && !policy.allow_private_ips {
        return true;
    }
    false
}

/// Validated upstream entry parsed at startup.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    pub name: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub base_path: String,
}

impl UpstreamTarget {
    pub fn host_header(&self) -> String {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Startup-validated registry of allowlisted proxy upstreams.
#[derive(Debug, Clone, Default)]
pub struct UpstreamRegistry {
    targets: BTreeMap<String, UpstreamTarget>,
}

impl UpstreamRegistry {
    /// Parse `NEXUS_PROXY_UPSTREAMS` (`name=https://host:port/base,other=http://...`).
    /// Rejects malformed URLs, embedded credentials, duplicate names, or disallowed schemes.
    pub fn parse_spec(spec: &str, policy: &DestinationPolicy) -> Result<Self> {
        let mut targets = BTreeMap::new();
        for raw_entry in spec.split(',') {
            let entry = raw_entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (raw_name, raw_url) = entry
                .split_once('=')
                .ok_or_else(|| anyhow!("Malformed upstream entry '{}' (expected name=url)", entry))?;
            let name = raw_name.trim().to_ascii_lowercase();
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            {
                anyhow::bail!("Invalid upstream name '{}'", raw_name);
            }
            if targets.contains_key(&name) {
                anyhow::bail!("Duplicate upstream name '{}'", name);
            }
            let target = validate_upstream_url(&name, raw_url.trim(), policy)?;
            targets.insert(name, target);
        }
        Ok(Self { targets })
    }

    pub fn from_env(policy: &DestinationPolicy) -> Result<Self> {
        match std::env::var("NEXUS_PROXY_UPSTREAMS") {
            Ok(spec) if !spec.trim().is_empty() => Self::parse_spec(&spec, policy),
            _ => Ok(Self::default()),
        }
    }

    pub fn get(&self, name: &str) -> Option<&UpstreamTarget> {
        self.targets.get(&name.trim().to_ascii_lowercase())
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

pub fn validate_upstream_url(
    name: &str,
    url: &str,
    policy: &DestinationPolicy,
) -> Result<UpstreamTarget> {
    if url.contains('@') {
        anyhow::bail!("Upstream '{}' URL must not embed credentials", name);
    }
    let uri: Uri = url
        .parse()
        .with_context(|| format!("Invalid upstream URL '{}' for '{}'", url, name))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow!("Upstream '{}' URL missing scheme", name))?
        .to_ascii_lowercase();
    match scheme.as_str() {
        "https" => {}
        "http" => {
            if !policy.allow_insecure_http {
                anyhow::bail!(
                    "Upstream '{}' uses insecure http:// (set NEXUS_PROXY_ALLOW_HTTP=1 to permit)",
                    name
                );
            }
        }
        other => anyhow::bail!("Upstream '{}' uses unsupported scheme '{}'", name, other),
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("Upstream '{}' URL missing host", name))?
        .to_ascii_lowercase();
    if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        if is_prohibited_ip(ip, policy) {
            anyhow::bail!("Upstream '{}' resolves to prohibited IP '{}'", name, ip);
        }
    }
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let base_path = uri.path().trim_end_matches('/').to_string();
    Ok(UpstreamTarget {
        name: name.to_string(),
        scheme,
        host,
        port,
        base_path,
    })
}

/// Resolve DNS once, validate EVERY returned IP against `DestinationPolicy`, and return the
/// pinned `SocketAddr` so connecting cannot suffer DNS rebinding.
pub async fn resolve_and_pin(
    host: &str,
    port: u16,
    policy: &DestinationPolicy,
) -> Result<SocketAddr> {
    let clean_host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        if is_prohibited_ip(ip, policy) {
            anyhow::bail!("Destination IP '{}' denied by SSRF policy", ip);
        }
        return Ok(SocketAddr::new(ip, port));
    }

    let addrs: Vec<SocketAddr> = lookup_host((clean_host, port))
        .await
        .with_context(|| format!("DNS lookup failed for '{}:{}'", clean_host, port))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("DNS returned no addresses for '{}:{}'", clean_host, port);
    }
    for addr in &addrs {
        if is_prohibited_ip(addr.ip(), policy) {
            anyhow::bail!(
                "Destination '{}' resolved to prohibited IP '{}' (SSRF blocked)",
                clean_host,
                addr.ip()
            );
        }
    }
    Ok(addrs[0])
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

/// Hardened Salvo reverse-proxy handler backed by Hyper HTTP/1.1.
#[derive(Clone)]
pub struct ReverseProxyHandler {
    registry: Arc<UpstreamRegistry>,
    policy: Arc<DestinationPolicy>,
}

impl ReverseProxyHandler {
    pub fn new(registry: UpstreamRegistry, policy: DestinationPolicy) -> Self {
        Self {
            registry: Arc::new(registry),
            policy: Arc::new(policy),
        }
    }

    pub fn from_env() -> Self {
        let policy = DestinationPolicy::default();
        let registry = UpstreamRegistry::from_env(&policy).unwrap_or_else(|e| {
            eprintln!("⚠️ Invalid NEXUS_PROXY_UPSTREAMS config (proxy disabled): {}", e);
            UpstreamRegistry::default()
        });
        Self::new(registry, policy)
    }

    async fn forward_request(
        &self,
        target: &UpstreamTarget,
        method: Method,
        rel_path: &str,
        query: Option<&str>,
        req_headers: &salvo::http::HeaderMap,
        req_body: Bytes,
    ) -> std::result::Result<(StatusCode, Vec<(String, String)>, Bytes), (StatusCode, &'static str)>
    {
        if req_body.len() > self.policy.max_request_body_bytes {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "Request body exceeds proxy limit"));
        }
        if req_headers.len() > self.policy.max_headers {
            return Err((StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "Too many request headers"));
        }

        let pinned = resolve_and_pin(&target.host, target.port, &self.policy)
            .await
            .map_err(|_| (StatusCode::FORBIDDEN, "Upstream destination denied by policy"))?;

        let mut path_and_query = format!(
            "{}/{}",
            target.base_path,
            rel_path.trim_start_matches('/')
        );
        if !path_and_query.starts_with('/') {
            path_and_query.insert(0, '/');
        }
        if let Some(q) = query {
            if !q.is_empty() {
                path_and_query.push('?');
                path_and_query.push_str(q);
            }
        }

        let mut builder = HyperRequest::builder()
            .method(method)
            .uri(&path_and_query)
            .header(HOST, target.host_header());

        // Copy non-hop-by-hop headers (stripping Connection-nominated headers too)
        let extra_hop: Vec<String> = req_headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').map(|h| h.trim().to_ascii_lowercase()).collect())
            .unwrap_or_default();

        for (k, v) in req_headers.iter() {
            let ks = k.as_str().to_ascii_lowercase();
            if is_hop_by_hop_header(&ks) || extra_hop.iter().any(|h| h == &ks) {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(k.as_str().as_bytes()),
                HeaderValue::from_bytes(v.as_bytes()),
            ) {
                builder = builder.header(hn, hv);
            }
        }
        builder = builder.header("x-forwarded-proto", &target.scheme);

        let hyper_req = builder
            .body(Full::new(req_body))
            .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to construct upstream request"))?;

        let tcp = tokio::time::timeout(self.policy.connect_timeout, TcpStream::connect(pinned))
            .await
            .map_err(|_| (StatusCode::GATEWAY_TIMEOUT, "Upstream connect timed out"))?
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Failed to connect to upstream"))?;

        let max_resp = self.policy.max_response_body_bytes;
        let is_https = target.scheme == "https";
        let host_for_tls = target.host.clone();

        let fut = async move {
            let mut resp = if is_https {
                let mut root_store = rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let tls_cfg = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
                let server_name = rustls::pki_types::ServerName::try_from(host_for_tls)
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Invalid TLS server name"))?;
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream TLS handshake failed"))?;
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                    .await
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream HTTP handshake failed"))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sender
                    .send_request(hyper_req)
                    .await
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream request failed"))?
            } else {
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                    .await
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream HTTP handshake failed"))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sender
                    .send_request(hyper_req)
                    .await
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream request failed"))?
            };

            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);

            // Fast-fail oversized Content-Length before buffering
            if let Some(cl) = resp
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
            {
                if cl > max_resp {
                    return Err((StatusCode::BAD_GATEWAY, "Upstream response exceeds size limit"));
                }
            }

            let mut out_headers = Vec::new();
            for (k, v) in resp.headers().iter() {
                if is_hop_by_hop_header(k.as_str()) {
                    continue;
                }
                if let Ok(vs) = v.to_str() {
                    out_headers.push((k.as_str().to_string(), vs.to_string()));
                }
            }

            let mut body_buf = Vec::new();
            while let Some(frame_res) = resp.frame().await {
                let frame = frame_res
                    .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream body stream error"))?;
                if let Some(data) = frame.data_ref() {
                    if body_buf.len().saturating_add(data.len()) > max_resp {
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            "Upstream response exceeds size limit",
                        ));
                    }
                    body_buf.extend_from_slice(data);
                }
            }
            Ok((status, out_headers, Bytes::from(body_buf)))
        };

        tokio::time::timeout(self.policy.request_timeout, fut)
            .await
            .map_err(|_| (StatusCode::GATEWAY_TIMEOUT, "Upstream request timed out"))?
    }
}

#[async_trait]
impl Handler for ReverseProxyHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let upstream = req.param::<String>("upstream").unwrap_or_default();
        let Some(target) = self.registry.get(&upstream) else {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({
                "error": "Upstream is not allowlisted"
            })));
            return;
        };

        let rel_path = req.param::<String>("path").unwrap_or_default();
        if rel_path.contains("..") {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "Invalid path traversal" })));
            return;
        }

        let method = Method::from_bytes(req.method().as_str().as_bytes()).unwrap_or(Method::GET);
        let query = req.uri().query().map(ToString::to_string);
        let headers = req.headers().clone();
        let body_bytes = match req.payload_with_max_size(self.policy.max_request_body_bytes).await {
            Ok(b) => Bytes::copy_from_slice(b),
            Err(_) => {
                res.status_code(StatusCode::PAYLOAD_TOO_LARGE);
                res.render(Json(serde_json::json!({ "error": "Request body exceeds proxy limit" })));
                return;
            }
        };

        match self
            .forward_request(target, method, &rel_path, query.as_deref(), &headers, body_bytes)
            .await
        {
            Ok((status, resp_headers, body)) => {
                res.status_code(status);
                for (k, v) in resp_headers {
                    if let (Ok(hn), Ok(hv)) = (
                        salvo::http::header::HeaderName::from_bytes(k.as_bytes()),
                        salvo::http::header::HeaderValue::from_str(&v),
                    ) {
                        res.headers_mut().append(hn, hv);
                    }
                }
                res.body(body);
            }
            Err((code, msg)) => {
                res.status_code(code);
                res.render(Json(serde_json::json!({ "error": msg })));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::{ResponseExt, TestClient};
    use salvo::Service;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn ssrf_policy_blocks_loopback_private_metadata_and_mapped_v6() {
        let strict = DestinationPolicy {
            allow_loopback: false,
            allow_private_ips: false,
            allow_insecure_http: false,
            ..Default::default()
        };
        assert!(is_prohibited_ip("127.0.0.1".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("::1".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("10.0.0.5".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("172.16.1.1".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("192.168.1.1".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("169.254.169.254".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("100.64.0.1".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("::ffff:127.0.0.1".parse().unwrap(), &strict));
        assert!(is_prohibited_ip("::ffff:169.254.169.254".parse().unwrap(), &strict));
        assert!(!is_prohibited_ip("93.184.216.34".parse().unwrap(), &strict));

        // Malformed / credential-bearing / insecure / duplicate upstream configs rejected
        assert!(UpstreamRegistry::parse_spec("bad-entry-no-equals", &strict).is_err());
        assert!(UpstreamRegistry::parse_spec("api=https://user:pass@example.com", &strict).is_err());
        assert!(UpstreamRegistry::parse_spec("api=http://example.com", &strict).is_err());
        assert!(UpstreamRegistry::parse_spec("api=https://127.0.0.1:8080", &strict).is_err());
        assert!(UpstreamRegistry::parse_spec("api=https://example.com,api=https://b.com", &strict).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reverse_proxy_forwards_enforces_allowlist_redirects_limits_timeouts_and_concurrency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    if first_line.contains("/echo") {
                        let body = "proxied-ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Upstream: yes\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else if first_line.contains("/redirect") {
                        let resp = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else if first_line.contains("/huge") {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n";
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else if first_line.contains("/slow") {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                    }
                });
            }
        });

        let policy = DestinationPolicy {
            allow_loopback: true,
            allow_private_ips: false,
            allow_insecure_http: true,
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_millis(150),
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            max_headers: 32,
        };
        let reg = UpstreamRegistry::parse_spec(
            &format!("backend=http://127.0.0.1:{}", addr.port()),
            &policy,
        )
        .unwrap();
        let handler = ReverseProxyHandler::new(reg, policy);
        let router = Router::with_path("/proxy/{upstream}/{**path}")
            .get(handler.clone())
            .post(handler);
        let service = Service::new(router);

        // 1. Unlisted upstream -> 403 Forbidden (allowlist bypass blocked)
        let r_forbid = TestClient::get("http://127.0.0.1/proxy/evil/echo")
            .send(&service)
            .await;
        assert_eq!(r_forbid.status_code, Some(StatusCode::FORBIDDEN));

        // 2. Valid upstream forwarding -> 200 OK + body preserved
        let mut r_ok = TestClient::get("http://127.0.0.1/proxy/backend/echo")
            .send(&service)
            .await;
        assert_eq!(r_ok.status_code, Some(StatusCode::OK));
        assert_eq!(r_ok.take_string().await.unwrap(), "proxied-ok");

        // 3. Redirect NOT followed (302 returned verbatim, preventing redirect SSRF)
        let r_redir = TestClient::get("http://127.0.0.1/proxy/backend/redirect")
            .send(&service)
            .await;
        assert_eq!(r_redir.status_code, Some(StatusCode::FOUND));

        // 4. Oversized response -> 502 Bad Gateway
        let r_huge = TestClient::get("http://127.0.0.1/proxy/backend/huge")
            .send(&service)
            .await;
        assert_eq!(r_huge.status_code, Some(StatusCode::BAD_GATEWAY));

        // 5. Slow upstream -> 504 Gateway Timeout
        let r_slow = TestClient::get("http://127.0.0.1/proxy/backend/slow")
            .send(&service)
            .await;
        assert_eq!(r_slow.status_code, Some(StatusCode::GATEWAY_TIMEOUT));

        // 6. Concurrent requests (10 simultaneous)
        let futs = (0..10).map(|_| {
            let svc = &service;
            async move {
                let r = TestClient::get("http://127.0.0.1/proxy/backend/echo")
                    .send(svc)
                    .await;
                assert_eq!(r.status_code, Some(StatusCode::OK));
            }
        });
        futures::future::join_all(futs).await;
    }
}
