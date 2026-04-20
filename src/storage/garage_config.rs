use garage_util::config::*;

/// Create minimal Garage configuration for single-node development
///  
/// Based on Garage 2.1.0 Config struct
/// Create minimal Garage configuration for single-node development
///  
/// Based on Garage 2.1.0 Config struct
pub fn create_dev_config(rpc_addr: Option<String>) -> Config {
    let bind_addr = rpc_addr.unwrap_or_else(|| "127.0.0.1:3901".to_string());
    
    // Read TOML and parse properly
    // NOTE: block_size is set to 100MB to avoid multi-block complexity in PoC
    let toml_str = format!(r#"
metadata_dir = "./garage-meta"
data_dir = [ {{ path = "./garage-data", capacity = "1G" }} ]
db_engine = "sqlite"

replication_factor = 1

rpc_bind_addr = "{}"
rpc_public_addr = "{}"
rpc_secret = "4e6578757349724465764b657900000000000000000000000000000000000000"

block_size = 104857600
metadata_auto_snapshot_interval = "6h"

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
"#, bind_addr, bind_addr);

    toml::from_str(&toml_str).expect("Failed to parse Garage config TOML")
}

/// Create production-ready multi-node configuration
#[allow(dead_code)]
pub fn create_prod_config_toml(
    metadata_dir: &str,
    data_dir: &str,
    rpc_bind: &str,
    rpc_public: &str,
    rpc_secret: &str,
    bootstrap_peers: Vec<String>,
) -> Config {
    let bootstrap_list = bootstrap_peers.join("\", \"");
    
    let toml_str = format!(r#"
metadata_dir = "{}"
data_dir = [ {{ path = "{}", capacity = "1T" }} ]
db_engine = "sqlite"

replication_factor = 3

rpc_bind_addr = "{}"
rpc_public_addr = "{}"
rpc_secret = "{}"

bootstrap_peers = [ "{}" ]

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:3900"
"#, metadata_dir, data_dir, rpc_bind, rpc_public, rpc_secret, bootstrap_list);

    toml::from_str(&toml_str).expect("Failed to parse Garage config TOML")
}
