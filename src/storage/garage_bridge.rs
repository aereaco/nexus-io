use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;
use futures::StreamExt;
use garage_model::garage::Garage;
use garage_util::background::BackgroundRunner;
use garage_util::data::{Hash, Uuid};
use garage_model::s3::object_table::{
    Object, ObjectVersion, ObjectVersionState, ObjectVersionData,
    ObjectVersionMeta, ObjectVersionMetaInner, ObjectVersionEncryption
};
use garage_util::crdt::Crdt;
use garage_rpc::layout::{NodeRole, NodeRoleV};
use crate::db::Database;
use super::garage_config::create_dev_config;
use rand::RngCore;

/// Global singleton Garage instance
static GARAGE: Lazy<Arc<RwLock<Option<Arc<Garage>>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Initialize or get the global Garage instance
async fn init_garage() -> Result<Arc<Garage>> {
    let mut garage_lock = GARAGE.write().await;
    
    if garage_lock.is_none() {
        println!("🚀 Initializing Garage DHT (single-node mode)");
        
        // Detect WireGuard IP (e.g. 10.0.0.x)
        let vpn_ip = crate::storage::wireguard::WireGuardInterface::get_vpn_ip();
        let bind_addr = vpn_ip.clone().map(|ip| format!("{}:3901", ip));
        
        if let Some(ip) = &vpn_ip {
             println!("🔒 Secure Mesh Detected: Binding to {}", ip);
        } else {
             println!("⚠️  Secure Mesh NOT Detected: Binding to localhost (Dev Mode)");
        }
        
        let config = create_dev_config(bind_addr);
        
        // Initialize Garage version (required by garage_util)
        // This fixes the panic in NodeStatus::initial
        garage_util::version::init_version("2.2.0");
        
        // Initialize Garage
        let garage = Garage::new(config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize Garage: {}", e))?;
            
        // Auto-configure layout for single-node setup
        let system = &garage.system;
        let node_id = system.id;
        
        // Wait for layout helper to be available/synced? 
        // Single node should be immediate.
        
        let mut layout = system.cluster_layout().inner().clone();
        let current_role = layout.current().roles.get(&node_id);
        
        // If we don't have a role with capacity, assign one
        if !matches!(current_role, Some(NodeRoleV(Some(r))) if r.capacity.is_some()) {
            println!("⚙️  Initializing Garage Layout for single node: {:?}", node_id);
            
            let new_role = NodeRole {
                zone: "dc1".to_string(),
                capacity: Some(1024 * 1024 * 1024), // 1 GB capacity
                tags: vec![],
            };
            
            // 1. Stage role change
            let roles = layout.current().roles.clone();
            layout.staging.get_mut().roles.merge(
                &roles.update_mutator(node_id, NodeRoleV(Some(new_role)))
            );
            
            system.layout_manager.update_cluster_layout(&layout).await
                .map_err(|e| anyhow::anyhow!("Failed to stage layout: {}", e))?;
                
            // 2. Apply change
            // Re-fetch layout to be safe (though we have local clone, manager ensures consistency)
            let layout = system.cluster_layout().inner().clone();
            let next_version = layout.current().version + 1;
            
            let (new_layout, _msg) = layout.apply_staged_changes(next_version)
                 .map_err(|e| anyhow::anyhow!("Failed to apply layout changes: {:?}", e))?; // Debug format for GarageError
                 
            system.layout_manager.update_cluster_layout(&new_layout).await
                 .map_err(|e| anyhow::anyhow!("Failed to commit new layout: {}", e))?;
                 
            println!("✅ Garage Layout applied (v{})", next_version);
        }
        
        // Create stop signal channel
        let (stop_send, stop_recv) = tokio::sync::watch::channel(false);
        
        // Start background workers
        let (bg, _join_handle) = BackgroundRunner::new(stop_recv);
        
        garage.spawn_workers(&bg)
            .map_err(|e| anyhow::anyhow!("Failed to spawn Garage workers: {}", e))?;
            
        std::mem::forget(stop_send);
        *garage_lock = Some(garage.clone());
        
        println!("✅ Garage DHT initialized");
    }
    
    Ok(garage_lock.as_ref().unwrap().clone())
}

#[derive(Clone)]
pub struct GarageBridge {
    garage: Arc<Garage>,
    db: Arc<Database>,
}

impl GarageBridge {
    pub async fn new(db: Arc<Database>) -> Result<Self> {
        let garage = init_garage().await?;
        Ok(Self {
            garage,
            db,
        })
    }
    
    /// Create a new bucket (Metadata Only)
    pub async fn create_bucket(&self, name: &str) -> Result<()> {
        println!("DEBUG: Creating bucket '{}' in metadata store", name);
        
        // Direct parameter binding - No intermediate DTOs
        // Must own string for async future
        let name_owned = name.to_string();
        
        self.db.client
            .query("CREATE bucket CONTENT { name: $name, created_at: time::now() }")
            .bind(("name", name_owned))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create bucket metadata: {}", e))?;
            
        Ok(())
    }

    /// Connect to a peer (Garage Autopilot)
    /// Triggers the RPC system to handshake with the given endpoint.
    pub async fn connect_peer(&self, pubkey: &str, endpoint: &str) -> Result<()> {
        // Parse endpoint to socket address
        // If endpoint is just IP:Port, it should parse.
        // If it's a domain, we might need lookup, but usually WireGuard endpoints are IPs.
        // Garage connect usually expects "NodeID@IP:Port" or just "IP:Port".
        // If we don't know NodeID, we can just try to connect to IP:3901 (RPC port).
        
        // Assumption: endpoint passed here is the endpoint of the peer's WireGuard interface?
        // OR is it the public endpoint?
        // Actually, for Garage peering, we want to talk to the peer's *Garage RPC* port.
        // If we assume a flat mesh, the peer's IP is their VPN IP.
        // And Garage listens on 3901.
        
        // Logic:
        // 1. If endpoint is valid, try to connect.
        // 2. We log the interaction.
        
        println!("🤖 Garage Autopilot: Connecting to peer {} @ {}", pubkey, endpoint);
        
        println!("🤖 Garage Autopilot: Connecting to peer {} @ {}", pubkey, endpoint);
        
        // Parse endpoint (expecting IP:Port)
        let _addr = endpoint.parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("Invalid endpoint format '{}': {}", endpoint, e))?;
            
        // Trigger active connection via Garage RPC
        // This initiates the handshake and eventual topology exchange
        // Compiler hint: connect takes &str and is async
        self.garage.system.connect(endpoint).await
            .map_err(|e| anyhow::anyhow!("Failed to connect to peer: {}", e))?;
        
        println!("✅ RPC Connection initiated to {}", endpoint);
        
        Ok(())
    }
    
    /// List all buckets (Metadata Only)
    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        // Direct row mapping - No serialization overhead, avoiding DTOs
        // We use generic HashMap to catch the {name: "..."} objects
        let mut response = self.db.client
            .query("SELECT name FROM bucket")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to query buckets: {}", e))?;
            
        // Map generic rows directly
        let rows: Vec<std::collections::HashMap<String, String>> = response.take(0)?;
        
        let names = rows.into_iter()
            .filter_map(|mut row| row.remove("name"))
            .collect();
            
        Ok(names)
    }
    
    /// Put object - zero-copy write
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        value: bytes::Bytes,
    ) -> Result<()> {
        let len = value.len() as u64;
        
        // 1. Calculate hash (BLAKE3)
        let hash = blake3::hash(&value);
        let garage_hash = Hash::from(*hash.as_bytes());
        
        // 2. Store block via BlockManager (zero-copy)
        // using bytes::Bytes to avoid copy if possible
        let data = value;
        
        self.garage.block_manager.rpc_put_block(
            garage_hash,
            data,
            false, // allow compression
            None,  // no order tag needed
        ).await.map_err(|e| anyhow::anyhow!("Failed to store block: {}", e))?;
        
        // 3. Update object table metadata
        // Use full 32 bytes of hash for bucket_id (Garage Uuid is 32 bytes)
        let bucket_hash = blake3::hash(bucket.as_bytes());
        let bucket_id = Uuid::from(*bucket_hash.as_bytes());
        
        // Create version info using ObjectVersionData::FirstBlock (assuming single block)
        // For PoC, we rely on large block_size config to avoid splitting
        let meta_inner = ObjectVersionMetaInner {
            headers: Default::default(),
            checksum: None,
            checksum_type: None,
        };
        
        let meta = ObjectVersionMeta {
            size: len,
            etag: hex::encode(hash.as_bytes()),
            encryption: ObjectVersionEncryption::Plaintext { inner: meta_inner },
        };
        
        let version_data = ObjectVersionData::FirstBlock(meta, garage_hash);
        
        // Generate random 32-byte UUID for version
        let mut version_uuid_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut version_uuid_bytes);
        let version_uuid = Uuid::from(version_uuid_bytes);

        // ObjectVersion::new might not exist, initializing struct directly
        let version = ObjectVersion {
             uuid: version_uuid,
             timestamp: now_msec(),
             state: ObjectVersionState::Complete(version_data),
        };

        // Fetch existing object or create new one
        let mut object = match self.garage.object_table.get(&bucket_id, &key.to_string()).await? {
            Some(obj) => obj,
            None => Object::new(bucket_id, key.to_string(), vec![]),
        };
        
        // Add new version
        object.add_version(version).map_err(|e| anyhow::anyhow!("Failed to add version: {:?}", e))?;
        
        // Save back to table
        self.garage.object_table.insert(&object).await
            .map_err(|e| anyhow::anyhow!("Failed to update object table: {}", e))?;
            
        Ok(())
    }
    
    /// Get object - zero-copy read
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<bytes::Bytes>> {
        // Generate bucket UUID
        let bucket_hash = blake3::hash(bucket.as_bytes());
        let bucket_id = Uuid::from(*bucket_hash.as_bytes());
        
        // 1. Get object metadata
        let object = match self.garage.object_table.get(&bucket_id, &key.to_string()).await? {
            Some(obj) => obj,
            None => return Ok(None),
        };
        
        // 2. Get latest version
        let version = object.versions().last()
            .ok_or_else(|| anyhow::anyhow!("Object found but has no versions"))?;
            
        let version_data = match &version.state {
            ObjectVersionState::Complete(data) => data,
            _ => return Ok(None), // Not readable
        };
        
        // 3. Retrieve block data
        match version_data {
            ObjectVersionData::Inline(_, bytes) => Ok(Some(bytes::Bytes::from(bytes.clone()))),
            ObjectVersionData::FirstBlock(_, hash) => {
                let stream = self.garage.block_manager
                    .rpc_get_block_streaming(hash, None)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to retrieve block: {}", e))?;
                    
                let mut stream = stream;
                let mut result = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|e| anyhow::anyhow!("Stream error: {}", e))?;
                    result.extend_from_slice(&chunk);
                }
                Ok(Some(bytes::Bytes::from(result)))
            },
            _ => Err(anyhow::anyhow!("Unsupported object version data type: {:?}", version_data)),
        }
    }

    /// Delete object - create tombstone version
    pub async fn delete_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<()> {
        // Generate bucket UUID
        let bucket_hash = blake3::hash(bucket.as_bytes());
        let bucket_id = Uuid::from(*bucket_hash.as_bytes());
        
        // 1. Fetch existing object or create new one
        let mut object = match self.garage.object_table.get(&bucket_id, &key.to_string()).await? {
            Some(obj) => obj,
            None => return Ok(()), // Already deleted or never existed
        };
        
        // 2. Create tombstone version
        let mut version_uuid_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut version_uuid_bytes);
        let version_uuid = Uuid::from(version_uuid_bytes);

        let version = ObjectVersion {
             uuid: version_uuid,
             timestamp: now_msec(),
             state: ObjectVersionState::Complete(ObjectVersionData::DeleteMarker),
        };

        // 3. Add version and save
        object.add_version(version).map_err(|e| anyhow::anyhow!("Failed to add tombstone: {:?}", e))?;
        self.garage.object_table.insert(&object).await
            .map_err(|e| anyhow::anyhow!("Failed to update object table: {}", e))?;
            
        Ok(())
    }
}

fn now_msec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
