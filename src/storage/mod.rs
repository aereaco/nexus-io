// Storage module for iroh-blobs, s3s, and optional WireGuard VPN mesh integration
pub mod wireguard;
#[cfg(feature = "vpn")]
pub mod mesh;
pub mod storage_config;
pub mod blob_bridge;
pub mod cas_store;
#[cfg(feature = "shell")]
pub mod command;

pub use blob_bridge::BlobBridge;
pub use cas_store::CasStore;
pub use wireguard::WireGuardManager;
#[cfg(feature = "vpn")]
pub use mesh::MeshReactor;

#[cfg(feature = "shell")]
pub use command::{
    StorageInitCommand, StorageStatusCommand,
    StorageBucketCreateCommand, StorageBucketListCommand,
    StoragePutCommand, StorageGetCommand,
    StoragePeerAddCommand, StoragePeerListCommand
};
