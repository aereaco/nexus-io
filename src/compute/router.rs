use std::collections::{BTreeMap, HashMap};
use crate::compute::telemetry::NodeResources;
use crate::storage::blob_bridge::select_hrw_replicas;
use crate::storage::wireguard::PeerConfig;

/// 4D Resource & Placement Requirements (`CPU + GPU/VRAM + Memory + Storage + Labels + HRW Data Locality`).
#[derive(Debug, Clone, Default)]
pub struct ComputeRequirements {
    pub min_cpu: u32,
    pub min_ram_mb: u64,
    pub min_vram_mb: u64,
    pub min_storage_mb: u64,
    pub requires: Vec<String>,
    pub required_labels: BTreeMap<String, String>,
    pub affinity_key: Option<String>,
}

impl ComputeRequirements {
    /// Construct 4D requirements from a manifest cell's `requires` tokens, `labels` (`key=val`, `key:val`, or `BTreeMap`), and memory/storage limits.
    pub fn from_placement(
        requires: &[String],
        labels: &[String],
        min_ram_mb: u64,
        affinity_key: Option<String>,
    ) -> Self {
        let mut required_labels = BTreeMap::new();
        for item in labels {
            let trimmed = item.trim();
            if let Some((k, v)) = trimmed.split_once('=').or_else(|| trimmed.split_once(':')) {
                required_labels.insert(k.trim().to_string(), v.trim().to_string());
            } else if !trimmed.is_empty() {
                required_labels.insert(trimmed.to_string(), "true".to_string());
            }
        }
        let mut req = Self {
            min_cpu: 1,
            min_ram_mb,
            min_vram_mb: 0,
            min_storage_mb: 0,
            requires: requires.to_vec(),
            required_labels,
            affinity_key,
        };
        for tok in requires {
            let lower = tok.trim().to_ascii_lowercase();
            if lower == "gpu" && req.min_vram_mb == 0 {
                req.min_vram_mb = 1;
            } else if let Some(val) = lower.strip_prefix("vram:") {
                if let Ok(mb) = val.parse::<u64>() {
                    req.min_vram_mb = req.min_vram_mb.max(mb);
                }
            } else if let Some(val) = lower.strip_prefix("ram:") {
                if let Ok(mb) = val.parse::<u64>() {
                    req.min_ram_mb = req.min_ram_mb.max(mb);
                }
            } else if let Some(val) = lower.strip_prefix("cpu:") {
                if let Ok(cores) = val.parse::<u32>() {
                    req.min_cpu = req.min_cpu.max(cores);
                }
            } else if let Some(val) = lower.strip_prefix("storage:") {
                if let Ok(mb) = val.parse::<u64>() {
                    req.min_storage_mb = req.min_storage_mb.max(mb);
                }
            }
        }
        req
    }
}

/// 4D Decentralized Mesh Scheduler (`CPU + GPU/VRAM + Memory + Storage/HRW Locality`).
#[derive(Clone, Default)]
pub struct InferenceRouter {
    grid_state: HashMap<String, NodeResources>,
}

impl InferenceRouter {
    pub fn new() -> Self {
        Self {
            grid_state: HashMap::new(),
        }
    }

    pub fn from_snapshot(grid_state: HashMap<String, NodeResources>) -> Self {
        Self { grid_state }
    }

    pub fn grid_state(&self) -> &HashMap<String, NodeResources> {
        &self.grid_state
    }

    /// Evaluate whether a node's `NodeResources` satisfies all hard 4D requirements and compute its score.
    pub fn score_node(
        &self,
        pubkey: &str,
        stats: &NodeResources,
        req: &ComputeRequirements,
        hrw_primary: Option<&str>,
    ) -> Option<u64> {
        // 1. Hard Dimension Filters: CPU, Memory, GPU VRAM, Storage
        if stats.cpu_cores < req.min_cpu {
            return None;
        }
        let free_ram_mb = stats.memory_free / 1024 / 1024;
        if free_ram_mb < req.min_ram_mb {
            return None;
        }
        let total_vram_mb: u64 = stats.gpus.iter().map(|g| g.vram_free / 1024 / 1024).sum();
        if total_vram_mb < req.min_vram_mb {
            return None;
        }
        let free_storage_mb = stats.storage_free / 1024 / 1024;
        if req.min_storage_mb > 0 && free_storage_mb < req.min_storage_mb {
            return None;
        }

        // 2. Capability Token Filters (`requires`)
        for tok in &req.requires {
            let lower = tok.trim().to_ascii_lowercase();
            match lower.as_str() {
                "gpu" => {
                    if stats.gpus.is_empty() || total_vram_mb == 0 {
                        return None;
                    }
                }
                "green" => {
                    if !stats.is_green {
                        return None;
                    }
                }
                "persistent" => {
                    if stats.storage_total == 0 && stats.storage_free == 0 {
                        return None;
                    }
                }
                _ if lower.starts_with("vram:")
                    || lower.starts_with("ram:")
                    || lower.starts_with("cpu:")
                    || lower.starts_with("storage:") =>
                {
                    // Already enforced by numeric bounds above
                }
                other => {
                    let has_label = if let Some((rk, rv)) = other.split_once(':').or_else(|| other.split_once('=')) {
                        stats
                            .labels
                            .iter()
                            .any(|(k, v)| k.eq_ignore_ascii_case(rk.trim()) && v.eq_ignore_ascii_case(rv.trim()))
                    } else {
                        stats
                            .labels
                            .iter()
                            .any(|(k, v)| k.eq_ignore_ascii_case(other) || v.eq_ignore_ascii_case(other))
                    };
                    if !has_label {
                        return None;
                    }
                }
            }
        }

        // 3. Explicit Label Filters (`required_labels`)
        for (k, expected_v) in &req.required_labels {
            let matched = stats
                .labels
                .get(k)
                .map(|actual| actual.eq_ignore_ascii_case(expected_v))
                .unwrap_or(false);
            if !matched {
                return None;
            }
        }

        // 4. Composite 4D Score (Memory + CPU Headroom + Storage + GPU VRAM)
        let cpu_headroom_pct = 100u64.saturating_sub((stats.cpu_load_pct as u64).min(95));
        let cpu_score = (stats.cpu_cores as u64) * cpu_headroom_pct * 16; // MB-equivalent weight
        let ram_score = free_ram_mb;
        let storage_score = (free_storage_mb / 16).min(32_768); // Bounded storage contribution
        let vram_score = total_vram_mb * 4; // High weight for GPU VRAM capacity

        let mut score = if req.min_vram_mb > 0 || req.requires.iter().any(|r| r.eq_ignore_ascii_case("gpu")) {
            (vram_score * 1024 * 1024)
                .saturating_add(ram_score * 1024)
                .saturating_add(cpu_score * 1024)
        } else {
            (ram_score * 1024 * 1024)
                .saturating_add((cpu_score + storage_score + vram_score) * 1024)
        };

        // 5. BLAKE3 HRW Data-Locality Affinity Bonus (+25% if this node holds the primary CAS replica)
        if let Some(primary) = hrw_primary {
            if primary == pubkey {
                score = score.saturating_add(score / 4);
            }
        }

        // 6. Green Sustainability Bonus (+10%)
        if stats.is_green {
            score = score.saturating_add(score / 10);
        }

        Some(score.max(1))
    }

    /// Rank all eligible mesh nodes in descending order of 4D composite score, returning up to `replicas`.
    pub fn select_ranked_nodes(
        &self,
        peers: &[PeerConfig],
        req: &ComputeRequirements,
        replicas: usize,
    ) -> Vec<(PeerConfig, u64)> {
        let peer_ids: Vec<String> = peers.iter().map(|p| p.public_key.clone()).collect();
        let hrw_primary = req.affinity_key.as_ref().and_then(|key| {
            select_hrw_replicas(key, &peer_ids, 1).into_iter().next()
        });

        let mut scored: Vec<(PeerConfig, u64)> = peers
            .iter()
            .filter_map(|peer| {
                let stats = self.grid_state.get(&peer.public_key)?;
                let s = self.score_node(&peer.public_key, stats, req, hrw_primary.as_deref())?;
                Some((peer.clone(), s))
            })
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.public_key.cmp(&b.0.public_key)));
        scored.into_iter().take(replicas.max(1)).collect()
    }

    /// Select the single highest-scoring node for the job based on 4D requirements.
    pub fn select_node(
        &self,
        peers: &[PeerConfig],
        req: &ComputeRequirements,
    ) -> Option<PeerConfig> {
        self.select_ranked_nodes(peers, req, 1)
            .into_iter()
            .next()
            .map(|(peer, _)| peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::telemetry::GpuInfo;

    #[test]
    fn mesh_scheduler_ranks_4d_cpu_gpu_ram_storage_and_hrw_locality() {
        let mut grid = HashMap::new();
        grid.insert(
            "node-cpu-1".to_string(),
            NodeResources {
                cpu_cores: 8,
                cpu_load_pct: 10,
                memory_total: 16 * 1024 * 1024 * 1024,
                memory_free: 12 * 1024 * 1024 * 1024,
                storage_total: 500 * 1024 * 1024 * 1024,
                storage_free: 200 * 1024 * 1024 * 1024,
                gpus: vec![],
                is_green: false,
                labels: BTreeMap::from([("region".into(), "us-east".into())]),
                timestamp: 1000,
            },
        );
        grid.insert(
            "node-gpu-green".to_string(),
            NodeResources {
                cpu_cores: 16,
                cpu_load_pct: 20,
                memory_total: 64 * 1024 * 1024 * 1024,
                memory_free: 48 * 1024 * 1024 * 1024,
                storage_total: 1000 * 1024 * 1024 * 1024,
                storage_free: 800 * 1024 * 1024 * 1024,
                gpus: vec![GpuInfo {
                    name: "NVIDIA RTX 4090".into(),
                    vram_total: 24 * 1024 * 1024 * 1024,
                    vram_free: 20 * 1024 * 1024 * 1024,
                }],
                is_green: true,
                labels: BTreeMap::from([
                    ("region".into(), "eu-north".into()),
                    ("gpu".into(), "true".into()),
                ]),
                timestamp: 1000,
            },
        );

        let peers = vec![
            PeerConfig {
                public_key: "node-cpu-1".into(),
                endpoint: Some("10.0.0.1:51820".into()),
                _allowed_ips: vec![],
            },
            PeerConfig {
                public_key: "node-gpu-green".into(),
                endpoint: Some("10.0.0.2:51820".into()),
                _allowed_ips: vec![],
            },
        ];

        let router = InferenceRouter::from_snapshot(grid);

        // 1. GPU requirement strictly filters out CPU-only node
        let gpu_req = ComputeRequirements::from_placement(
            &["gpu".into(), "vram:16384".into()],
            &[],
            4096,
            Some("ai/agent_1".into()),
        );
        let winner = router.select_node(&peers, &gpu_req).expect("GPU node must match");
        assert_eq!(winner.public_key, "node-gpu-green");

        // 2. Region label requirement selects matching region
        let east_req = ComputeRequirements::from_placement(
            &[],
            &["region=us-east".into()],
            1024,
            None,
        );
        let east_winner = router.select_node(&peers, &east_req).expect("us-east node must match");
        assert_eq!(east_winner.public_key, "node-cpu-1");
    }
}
