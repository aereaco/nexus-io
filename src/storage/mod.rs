// Storage module for Garage DHT and WireGuard mesh integration
pub mod wireguard;
pub mod mesh;
pub mod garage_config;
pub mod garage_bridge;
pub mod command;

pub use garage_bridge::GarageBridge;
pub use wireguard::WireGuardManager;
pub use mesh::MeshReactor;

pub use command::{
    StorageInitCommand, StorageStatusCommand,
    StorageBucketCreateCommand, StorageBucketListCommand,
    StoragePutCommand, StorageGetCommand,
    StoragePeerAddCommand, StoragePeerListCommand
};
