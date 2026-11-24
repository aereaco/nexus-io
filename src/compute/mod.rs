pub mod telemetry;
pub mod router;
pub mod command;
pub mod route_command;
pub mod grid_command;
pub mod run_command;
pub mod md_runtime;
#[cfg(feature = "k8s-bridge")]
pub mod k8s_bridge;
pub mod analytics;
#[cfg(feature = "wasm-runtime")]
pub mod crystal;

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
