use serde::{Deserialize, Serialize};

/// Cross-platform configuration for Nexus-IO distributed object & blob storage (`s3s` + `iroh-blobs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStorageConfig {
    pub data_dir: String,
    pub replication_factor: usize,
    pub s3_bind_addr: String,
    pub bootstrap_peers: Vec<String>,
}

/// Create minimal storage configuration for single-node development.
pub fn create_dev_config(rpc_addr: Option<String>) -> ClusterStorageConfig {
    let bind_addr = rpc_addr.unwrap_or_else(|| "127.0.0.1:3900".to_string());
    ClusterStorageConfig {
        data_dir: "./nexus-blobs".to_string(),
        replication_factor: 1,
        s3_bind_addr: bind_addr,
        bootstrap_peers: Vec::new(),
    }
}

/// Create production-ready multi-node configuration.
#[allow(dead_code)]
pub fn create_prod_config(
    data_dir: &str,
    s3_bind: &str,
    bootstrap_peers: Vec<String>,
) -> ClusterStorageConfig {
    ClusterStorageConfig {
        data_dir: data_dir.to_string(),
        replication_factor: 3,
        s3_bind_addr: s3_bind.to_string(),
        bootstrap_peers,
    }
}
