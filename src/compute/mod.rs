pub mod telemetry;
pub mod router;
#[cfg(feature = "ops-shell")]
pub mod command;
#[cfg(feature = "ops-shell")]
pub mod route_command;
#[cfg(feature = "ops-shell")]
pub mod grid_command;
#[cfg(feature = "ops-shell")]
pub mod run_command;
pub mod md_runtime;
#[cfg(feature = "ops-k8s")]
pub mod k8s_bridge;
pub mod analytics;
#[cfg(feature = "runtime-wasm")]
pub mod crystal;
#[cfg(feature = "runtime-wasm")]
pub mod wasm_registry;
#[cfg(feature = "runtime-wasm")]
pub mod wasm_db;
#[cfg(feature = "runtime-wasm")]
pub mod manifest;

pub use telemetry::NodeResources;
pub use router::{InferenceRouter, ComputeRequirements};
use serde::{Serialize, Deserialize};

/// PeerRecord represents a node in the mesh as projected from SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub pubkey: String,
    pub endpoint: Option<String>,
    pub resources: Option<NodeResources>,
    pub is_local: bool,
}
