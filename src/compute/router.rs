use std::collections::HashMap;
use crate::compute::telemetry::NodeResources;
use crate::storage::wireguard::PeerConfig;

pub struct InferenceRouter {
    grid_state: HashMap<String, NodeResources>,
}

#[derive(Debug)]
pub struct ComputeRequirements {
    pub min_cpu: u32,
    pub min_ram_mb: u64,
    pub min_vram_mb: u64,
}

impl InferenceRouter {
    pub fn new() -> Self {
        Self { grid_state: HashMap::new() }
    }

    pub fn from_snapshot(grid_state: HashMap<String, NodeResources>) -> Self {
        Self { grid_state }
    }

    /// Select the best node for the job based on requirements
    /// Returns the PeerConfig of the chosen node (or None if no match)
    pub fn select_node(
        &self, 
        peers: &[PeerConfig], 
        req: &ComputeRequirements
    ) -> Option<PeerConfig> {
        let mut best_candidate: Option<&PeerConfig> = None;
        let mut best_score = 0;

        for peer in peers {
            if let Some(stats) = self.grid_state.get(&peer.public_key) {
                // 1. Filter: specific hard requirements
                if stats.cpu_cores < req.min_cpu { continue; }
                if (stats.memory_free / 1024 / 1024) < req.min_ram_mb { continue; }
                
                // GPU Check (sum of all GPU VRAM for now, or match specific card)
                let total_vram_mb: u64 = stats.gpus.iter().map(|g| g.vram_free / 1024 / 1024).sum();
                if total_vram_mb < req.min_vram_mb { continue; }

                // 2. Score: prioritize free VRAM for GPU workloads, free RAM otherwise (+10% green bonus)
                let base_score = if req.min_vram_mb > 0 {
                    total_vram_mb * 1024 * 1024
                } else {
                    stats.memory_free
                };
                let score = if stats.is_green {
                    base_score.saturating_add(base_score / 10)
                } else {
                    base_score
                }; 
                
                if score > best_score {
                    best_score = score;
                    best_candidate = Some(peer);
                }
            }
        }
        
        best_candidate.cloned()
    }
}


