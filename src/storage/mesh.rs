use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use crate::compute::{InferenceRouter, NodeResources, PeerRecord};
use crate::db::Database;
use crate::storage::wireguard::{derive_mesh_ipv4, derive_mesh_ipv6, PeerConfig, WireGuardInterface};
use crate::storage::BlobBridge;

/// Canonical P2P Mesh Gossip & Heartbeat Descriptor exchanged across nodes over WireGuard/HTTP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshGossipPayload {
    #[serde(alias = "node_id")]
    pub pubkey: String,
    #[serde(default, alias = "wg_endpoint")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub wg_ipv4: String,
    #[serde(default)]
    pub wg_ipv6: String,
    pub resources: NodeResources,
    #[serde(default)]
    pub peers: Vec<PeerRecord>,
}

/// MeshReactor: Actively reconciles the state of the P2P Decentralized Mesh Fabric.
///
/// Unifies `peer_registry`, `sys::node`, and `sys::gpu` in `nexus::system` (`nexus-db`),
/// synchronizes deterministic WireGuard overlay IPs (`100.64.0.0/10` + `fd00:6e78::/32`),
/// and updates the 4D `InferenceRouter` (`CPU + GPU/VRAM + Memory + Storage/HRW Locality`).
pub struct MeshReactor {
    db: Arc<Database>,
    interface: Arc<WireGuardInterface>,
    bridge: Arc<BlobBridge>,
    pub router: Arc<std::sync::RwLock<InferenceRouter>>,
}

impl MeshReactor {
    pub fn new(
        db: Arc<Database>,
        interface: Arc<WireGuardInterface>,
        bridge: Arc<BlobBridge>,
    ) -> Self {
        Self {
            db,
            interface,
            bridge,
            router: Arc::new(std::sync::RwLock::new(InferenceRouter::new())),
        }
    }

    /// Start the reactor loop in the background.
    pub async fn start(self: Arc<Self>) {
        println!("🕸️  Mesh Reactor: Online (Watching peer_registry & sys::node)");

        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            // 1. Scan 4D Local Telemetry (CPU, GPU/VRAM, Memory, Storage)
            let stats = NodeResources::scan();
            let db = self.db.clone();
            let node_id = self.bridge.node_id().to_string();
            tokio::spawn(async move {
                let _ = stats.project_to_state(&*db, &node_id).await;
                if let Ok(stats_val) = serde_json::to_value(&stats) {
                    let _ = db
                        .client
                        .query("UPDATE peer_registry SET resources = $stats WHERE is_local = true")
                        .bind(("stats", stats_val))
                        .await;
                }
            });

            // 2. Reconcile Mesh Topology & WireGuard UAPI
            if let Err(e) = self.reconcile().await {
                eprintln!("⚠️  Mesh Reactor: Reconciliation failure: {}", e);
            }
        }
    }

    /// Ingest a P2P gossip payload from a remote peer using Last-Write-Wins (LWW by `resources.timestamp`)
    /// and synchronize both `peer_registry` and `sys::node` (for `BlobBridge` HRW storage placement).
    pub async fn ingest_gossip(
        db: &Arc<Database>,
        bridge: &Arc<BlobBridge>,
        payload: MeshGossipPayload,
    ) -> Result<usize> {
        let mut merged = 0usize;
        let mut all_records = payload.peers;
        all_records.push(PeerRecord {
            pubkey: payload.pubkey.clone(),
            endpoint: payload.endpoint.clone(),
            resources: Some(payload.resources),
            is_local: false,
        });

        db.client.use_ns("nexus").use_db("system").await?;
        let _ = db
            .client
            .query(
                "DEFINE TABLE IF NOT EXISTS peer_registry SCHEMALESS;
                 DEFINE TABLE IF NOT EXISTS `sys::node` SCHEMALESS;",
            )
            .await;

        for rec in all_records {
            if rec.pubkey.trim().is_empty() {
                continue;
            }
            let wg_v4 = derive_mesh_ipv4(&rec.pubkey);
            let wg_v6 = derive_mesh_ipv6(&rec.pubkey);
            let incoming_ts = rec.resources.as_ref().map(|r| r.timestamp).unwrap_or(0);

            // Check existing record timestamp for CRDT LWW merge
            let mut existing_resp = db
                .client
                .query("SELECT resources, is_local FROM type::record('peer_registry', $id)")
                .bind(("id", rec.pubkey.clone()))
                .await?;
            let existing_rows: Vec<serde_json::Value> = existing_resp.take(0).unwrap_or_default();
            if let Some(first) = existing_rows.first() {
                let existing_ts = first
                    .get("resources")
                    .and_then(|r| r.get("timestamp"))
                    .and_then(|t| t.as_i64())
                    .unwrap_or(0);
                if existing_ts > incoming_ts && incoming_ts > 0 {
                    continue;
                }
            }

            let res_json = serde_json::to_value(&rec.resources).unwrap_or(serde_json::Value::Null);
            db.client
                .query(
                    "UPSERT type::record('peer_registry', $id) SET
                        pubkey = $pubkey,
                        endpoint = $endpoint,
                        wg_ipv4 = $wg_v4,
                        wg_ipv6 = $wg_v6,
                        resources = $resources,
                        status = 'active',
                        is_local = $is_local,
                        updated_at = time::now();",
                )
                .bind(("id", rec.pubkey.clone()))
                .bind(("pubkey", rec.pubkey.clone()))
                .bind(("endpoint", rec.endpoint.clone()))
                .bind(("wg_v4", wg_v4.clone()))
                .bind(("wg_v6", wg_v6.clone()))
                .bind(("resources", res_json.clone()))
                .bind(("is_local", rec.is_local))
                .await?
                .check()?;

            if let Some(ref ep) = rec.endpoint {
                let _ = bridge.connect_peer(&rec.pubkey, ep).await;
            } else {
                let _ = bridge.connect_peer(&rec.pubkey, &wg_v4).await;
            }
            merged += 1;
        }

        Ok(merged)
    }

    /// Snapshot all registered mesh peers and build a live 4D `InferenceRouter` + `Vec<PeerConfig>`.
    pub async fn load_mesh_snapshot(
        db: &Arc<Database>,
    ) -> Result<(Vec<PeerRecord>, Vec<PeerConfig>, HashMap<String, NodeResources>)> {
        db.client.use_ns("nexus").use_db("system").await?;
        let mut response = db
            .client
            .query("SELECT * FROM peer_registry")
            .await
            .context("Failed to query peer_registry")?;

        let results: Vec<serde_json::Value> = response.take(0).unwrap_or_default();
        let mut records = Vec::new();
        for val in results {
            if let Ok(rec) = serde_json::from_value::<PeerRecord>(val) {
                if !rec.pubkey.is_empty() {
                    records.push(rec);
                }
            }
        }

        let mut peer_configs = Vec::new();
        let mut resources_snapshot = HashMap::new();

        for record in &records {
            if let Some(ref res) = record.resources {
                resources_snapshot.insert(record.pubkey.clone(), res.clone());
            }
            let wg_v4 = derive_mesh_ipv4(&record.pubkey);
            let wg_v6 = derive_mesh_ipv6(&record.pubkey);
            peer_configs.push(PeerConfig {
                public_key: record.pubkey.clone(),
                endpoint: record.endpoint.clone().or_else(|| Some(format!("{}:8443", wg_v4))),
                _allowed_ips: vec![format!("{}/32", wg_v4), format!("{}/128", wg_v6)],
            });
        }

        Ok((records, peer_configs, resources_snapshot))
    }

    /// Single reconciliation step
    pub async fn reconcile(&self) -> Result<()> {
        let (records, _all_peers, resources_snapshot) = Self::load_mesh_snapshot(&self.db).await?;

        let mut remote_peers = Vec::new();
        for record in records {
            if !record.is_local {
                let wg_v4 = derive_mesh_ipv4(&record.pubkey);
                let wg_v6 = derive_mesh_ipv6(&record.pubkey);
                remote_peers.push(PeerConfig {
                    public_key: record.pubkey,
                    endpoint: record.endpoint,
                    _allowed_ips: vec![format!("{}/32", wg_v4), format!("{}/128", wg_v6)],
                });
            }
        }

        if let Ok(mut router) = self.router.write() {
            *router = InferenceRouter::from_snapshot(resources_snapshot);
        }

        self.interface.apply_peers(&remote_peers).await?;

        for peer in &remote_peers {
            if let Some(endpoint) = &peer.endpoint {
                let _ = self.bridge.connect_peer(&peer.public_key, endpoint).await;
            }
        }

        Ok(())
    }

    // =========================================================================
    // Authenticated P2P Mesh Transport (Zero Extra Crates — Binary Streaming)
    // =========================================================================

    /// Maximum mesh forwarding hops allowed before failing closed with `508 Loop Detected`.
    pub const MAX_MESH_HOPS: u8 = 3;

    /// Normalize a peer endpoint (`"http://host:port"`, `"host:port"`) into `(host_port, host_header)`.
    fn parse_peer_host_port(endpoint: &str) -> Result<String> {
        let trimmed = endpoint
            .trim()
            .strip_prefix("http://")
            .or_else(|| endpoint.trim().strip_prefix("https://"))
            .unwrap_or(endpoint.trim())
            .split('/')
            .next()
            .unwrap_or("")
            .trim();
        if trimmed.is_empty() || !trimmed.contains(':') {
            anyhow::bail!("Invalid mesh peer endpoint '{}': expected host:port", endpoint);
        }
        Ok(trimmed.to_string())
    }

    /// Minimal HTTP/1.1 binary request/response over `tokio::net::TcpStream` (reuses node WireGuard/TCP
    /// endpoints with zero intermediate base64/JSON wrapping on binary payloads).
    async fn raw_http_exchange(
        endpoint: &str,
        method: &str,
        path_and_query: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = Self::parse_peer_host_port(endpoint)?;
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .context("Mesh peer connection timed out")?
            .with_context(|| format!("Failed to connect to mesh peer '{}'", addr))?;

        let mut req_buf = Vec::with_capacity(256 + body.len());
        req_buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path_and_query).as_bytes());
        req_buf.extend_from_slice(format!("Host: {}\r\n", addr).as_bytes());
        req_buf.extend_from_slice(b"Connection: close\r\n");
        req_buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        for (k, v) in headers {
            req_buf.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        req_buf.extend_from_slice(b"\r\n");
        req_buf.extend_from_slice(body);

        stream.write_all(&req_buf).await.context("Failed writing mesh HTTP request")?;
        stream.flush().await?;

        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
            .await
            .context("Mesh peer response timed out")?
            .context("Failed reading mesh HTTP response")?;

        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow::anyhow!("Malformed HTTP response from mesh peer '{}'", addr))?;

        let head_str = String::from_utf8_lossy(&raw[..header_end]);
        let mut lines = head_str.lines();
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid HTTP status line from peer: {}", status_line))?;

        let mut resp_headers = Vec::new();
        let mut is_chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("transfer-encoding") && val.to_ascii_lowercase().contains("chunked") {
                    is_chunked = true;
                }
                resp_headers.push((key, val));
            }
        }

        let raw_body = &raw[header_end + 4..];
        let body_bytes = if is_chunked {
            decode_chunked_body(raw_body)?
        } else {
            raw_body.to_vec()
        };

        Ok((status, resp_headers, body_bytes))
    }

    /// Push local 4D telemetry + WireGuard peer announcement to a remote peer's `POST /_nexus/mesh/gossip`
    /// and CRDT-LWW merge the peer's returned peer list into local `peer_registry`.
    pub async fn push_gossip_to_peer(
        db: &Arc<Database>,
        bridge: &Arc<BlobBridge>,
        peer_endpoint: &str,
        bearer_token: &str,
        payload: &MeshGossipPayload,
    ) -> Result<serde_json::Value> {
        let body = serde_json::to_vec(payload)?;
        let auth_hdr = format!("Bearer {}", bearer_token);
        let (status, _hdrs, resp_body) = Self::raw_http_exchange(
            peer_endpoint,
            "POST",
            "/_nexus/mesh/gossip",
            &[("Authorization", &auth_hdr), ("Content-Type", "application/json")],
            &body,
        )
        .await?;
        if status < 200 || status >= 300 {
            anyhow::bail!(
                "Peer gossip rejected by '{}' (HTTP {}): {}",
                peer_endpoint,
                status,
                String::from_utf8_lossy(&resp_body)
            );
        }
        let val: serde_json::Value = serde_json::from_slice(&resp_body)
            .context("Failed to parse peer gossip response JSON")?;
        // Merge peer's returned topology back into our local registry if present
        if let Some(peer_node_id) = val.get("node_id").and_then(|v| v.as_str()) {
            if let Ok(peer_res) = serde_json::from_value::<NodeResources>(
                val.get("resources").cloned().unwrap_or(serde_json::Value::Null),
            ) {
                let peers: Vec<PeerRecord> = val
                    .get("peers")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let incoming = MeshGossipPayload {
                    pubkey: peer_node_id.to_string(),
                    endpoint: Some(peer_endpoint.to_string()),
                    wg_ipv4: derive_mesh_ipv4(peer_node_id),
                    wg_ipv6: derive_mesh_ipv6(peer_node_id),
                    resources: peer_res,
                    peers,
                };
                let _ = Self::ingest_gossip(db, bridge, incoming).await;
            }
        }
        Ok(val)
    }

    /// Stream a content-addressed blob from a remote peer (`GET /_nexus/mesh/blobs/{cid}`),
    /// verify the complete BLAKE3 digest locally, and atomically store + acquire ownership in `CasStore`.
    pub async fn hydrate_blob_from_peer(
        bridge: &Arc<BlobBridge>,
        peer_endpoint: &str,
        bearer_token: &str,
        bucket: &str,
        owner_id: &str,
        expected_cid: &str,
    ) -> Result<bytes::Bytes> {
        let hex_cid = expected_cid
            .strip_prefix("blake3:")
            .unwrap_or(expected_cid)
            .to_ascii_lowercase();
        if hex_cid.len() != 64 || !hex_cid.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("Invalid BLAKE3 CID '{}'", expected_cid);
        }
        let auth_hdr = format!("Bearer {}", bearer_token);
        let path = format!("/_nexus/mesh/blobs/{}", hex_cid);
        let (status, _hdrs, raw_bytes) = Self::raw_http_exchange(
            peer_endpoint,
            "GET",
            &path,
            &[("Authorization", &auth_hdr)],
            &[],
        )
        .await?;
        if status != 200 {
            anyhow::bail!(
                "Failed to hydrate blob '{}' from '{}' (HTTP {})",
                hex_cid,
                peer_endpoint,
                status
            );
        }
        let actual_cid = blake3::hash(&raw_bytes).to_hex().to_string();
        if actual_cid != hex_cid {
            anyhow::bail!(
                "BLAKE3 verification failed while hydrating from '{}': expected {}, got {}",
                peer_endpoint,
                hex_cid,
                actual_cid
            );
        }
        let bytes = bytes::Bytes::from(raw_bytes);
        let cas = crate::storage::cas_store::CasStore::new(bridge.clone());
        let stored = cas.put_verified_blob(bucket, "blobs/", bytes.clone()).await?;
        cas.acquire_owners_batch(bucket, owner_id, &[stored]).await?;
        Ok(bytes)
    }

    /// Forward an authenticated `/cells/{app}/{cell_id}` HTTP request to a remote mesh peer,
    /// propagating caller identity, delegation metadata, bounded hop count, and cycle detection.
    pub async fn forward_cell_http(
        peer_endpoint: &str,
        method: &str,
        path_and_query: &str,
        local_node_id: &str,
        auth_header: Option<&str>,
        request_id: Option<&str>,
        prev_hops: u8,
        prev_visited: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, String, Vec<u8>)> {
        if prev_hops >= Self::MAX_MESH_HOPS {
            anyhow::bail!("LOOP_DETECTED: Mesh hop limit ({}) exceeded", Self::MAX_MESH_HOPS);
        }
        let visited_list: Vec<&str> = prev_visited
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if visited_list.iter().any(|&n| n == local_node_id) {
            anyhow::bail!("LOOP_DETECTED: Node '{}' already visited in mesh forwarding chain", local_node_id);
        }
        let next_hops = (prev_hops + 1).to_string();
        let next_visited = if visited_list.is_empty() {
            local_node_id.to_string()
        } else {
            format!("{},{}", visited_list.join(","), local_node_id)
        };
        let req_id_owned = request_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());

        let mut hdrs: Vec<(&str, &str)> = vec![
            ("X-Nexus-Mesh-Hops", &next_hops),
            ("X-Nexus-Mesh-Visited", &next_visited),
            ("X-Nexus-Delegated-By", local_node_id),
            ("X-Nexus-Request-Id", &req_id_owned),
        ];
        if let Some(auth) = auth_header {
            hdrs.push(("Authorization", auth));
        }
        if let Some(ct) = content_type {
            hdrs.push(("Content-Type", ct));
        }

        let (status, resp_hdrs, resp_body) =
            Self::raw_http_exchange(peer_endpoint, method, path_and_query, &hdrs, body).await?;
        let resp_ct = resp_hdrs
            .into_iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        Ok((status, resp_ct, resp_body))
    }
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let Some(crlf) = input.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_str = std::str::from_utf8(&input[..crlf])
            .unwrap_or("0")
            .split(';')
            .next()
            .unwrap_or("0")
            .trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| anyhow::anyhow!("Invalid HTTP chunk size '{}': {}", size_str, e))?;
        input = &input[crlf + 2..];
        if chunk_size == 0 {
            break;
        }
        if input.len() < chunk_size {
            anyhow::bail!("Truncated HTTP chunked body");
        }
        out.extend_from_slice(&input[..chunk_size]);
        input = &input[chunk_size..];
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
    Ok(out)
}
