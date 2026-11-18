use std::sync::Arc;
use std::time::Duration;
use anyhow::{Result, Context};
use crate::db::Database;
use crate::storage::wireguard::{WireGuardInterface, PeerConfig};
use crate::storage::BlobBridge;
use crate::compute::{NodeResources, InferenceRouter, PeerRecord};
use std::collections::HashMap;

/// MeshReactor: Actively reconciles the state of the "Dark Cloud" mesh
/// 
/// It watches the `sys::peer_registry` table in SurrealDB and ensures the
/// local WireGuard interface matches the desired state (peers, endpoints).
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
        bridge: Arc<BlobBridge>
    ) -> Self {
        Self { 
            db, 
            interface, 
            bridge,
            router: Arc::new(std::sync::RwLock::new(InferenceRouter::new())),
        }
    }

    /// Start the reactor loop in the background
    pub async fn start(self: Arc<Self>) {
        println!("🕸️  Mesh Reactor: Online (Watching peer_registry)");
        
        // Main Reconciliation Loop
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        
        loop {
            interval.tick().await;
            
            // 1. Telemetry Gossip (Fluid Projection)
            let stats = NodeResources::scan();
            let db = self.db.clone();
            tokio::spawn(async move {
                if let Ok(stats_val) = serde_json::to_value(stats) {
                    let query = "UPDATE peer_registry SET resources = $stats WHERE is_local = true";
                    if let Err(e) = db.client.query(query).bind(("stats", stats_val)).await {
                        eprintln!("⚠️  Mesh Reactor: Gossip Query failed: {}", e);
                    }
                }
            });

            // 2. Network Reconciliation
            if let Err(e) = self.reconcile().await {
                eprintln!("⚠️  Mesh Reactor: Reconciliation failure: {}", e);
            }
        }
    }

    /// Single reconciliation step
    async fn reconcile(&self) -> Result<()> {
        // 1. Fetch all peers and telemetry from DB (Object-Native Projection)
        // We use JSON-wire format as a bridge to satisfy SurrealDB v3 beta trait bounds
        let mut response = self.db.client
            .query("SELECT * FROM peer_registry")
            .await
            .context("Failed to query peer_registry")?;

        let results: Vec<serde_json::Value> = response.take(0).or_else(|_| Ok::<Vec<serde_json::Value>, anyhow::Error>(vec![]))?;
        let mut records = Vec::new();
        for val in results {
            // Fluid Pattern: Map JSON wire-format to Record Objects
            if let Ok(rec) = serde_json::from_value::<PeerRecord>(val) {
                records.push(rec);
            }
        }
        
        let mut remote_peers = Vec::new();
        let mut resources_snapshot = HashMap::new();

        for record in records {
            // Update local snapshot/router with latest telemetry (local or remote)
            if let Some(res) = record.resources {
                resources_snapshot.insert(record.pubkey.clone(), res);
            }

            // Only remote peers go to the WireGuard interface
            if !record.is_local {
                remote_peers.push(PeerConfig {
                    public_key: record.pubkey,
                    endpoint: record.endpoint,
                    _allowed_ips: vec!["0.0.0.0/0".to_string()], 
                });
            }
        }

        // 2. Update the in-memory Router with the fresh snapshot
        {
            if let Ok(mut router) = self.router.write() {
                *router = InferenceRouter::from_snapshot(resources_snapshot);
            }
        }

        // 3. Apply remote peers to WireGuard
        self.interface.apply_peers(&remote_peers).await?;
        
        // 4. Garage Autopilot: Connect to remote peers
        for peer in &remote_peers {
            if let Some(endpoint) = &peer.endpoint {
                let _ = self.bridge.connect_peer(&peer.public_key, endpoint).await;
            }
        }

        Ok(())
    }
}

