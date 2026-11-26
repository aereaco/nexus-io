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
}
