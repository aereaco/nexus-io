use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sysinfo::{Disks, System};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vram_total: u64,
    pub vram_free: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeResources {
    pub cpu_cores: u32,
    #[serde(default)]
    pub cpu_load_pct: u32,
    pub memory_total: u64,
    pub memory_free: u64,
    #[serde(default)]
    pub storage_total: u64,
    #[serde(default)]
    pub storage_free: u64,
    #[serde(default)]
    pub gpus: Vec<GpuInfo>,
    #[serde(default)]
    pub is_green: bool,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub timestamp: i64,
}

impl NodeResources {
    pub fn scan() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        // 1. Core CPU & Memory Telemetry
        let cpu_cores = sys.physical_core_count().unwrap_or(1).max(1) as u32;
        let cpu_load_pct = (sys.global_cpu_usage().clamp(0.0, 100.0) as u32).min(100);
        let memory_total = sys.total_memory();
        let memory_free = sys.available_memory().max(sys.free_memory());

        // 2. Storage Telemetry (Available disk capacity across active volumes)
        let disks = Disks::new_with_refreshed_list();
        let mut storage_total: u64 = 0;
        let mut storage_free: u64 = 0;
        for d in &disks {
            storage_total = storage_total.saturating_add(d.total_space());
            storage_free = storage_free.saturating_add(d.available_space());
        }

        // 3. GPU Telemetry (NVML - Desktop/Server only; gated out on Android/iOS)
        #[allow(unused_mut)]
        let mut gpus = vec![];
        #[cfg(all(feature = "ops-gpu", not(any(target_os = "android", target_os = "ios"))))]
        if let Ok(nvml) = nvml_wrapper::Nvml::init() {
            if let Ok(count) = nvml.device_count() {
                for i in 0..count {
                    if let Ok(device) = nvml.device_by_index(i) {
                        let name = device.name().unwrap_or_else(|_| "Unknown GPU".to_string());
                        let mem = device.memory_info().map(|m| (m.total, m.free)).unwrap_or((0, 0));

                        gpus.push(GpuInfo {
                            name,
                            vram_total: mem.0,
                            vram_free: mem.1,
                        });
                    }
                }
            }
        }

        // 4. Sustainability Flag & Node Capability Labels
        let is_green = std::env::var("NEXUS_GREEN").map(|v| v == "1").unwrap_or(false);
        let mut labels = BTreeMap::new();
        labels.insert("os".to_string(), std::env::consts::OS.to_string());
        labels.insert("arch".to_string(), std::env::consts::ARCH.to_string());
        if !gpus.is_empty() {
            labels.insert("gpu".to_string(), "true".to_string());
        }
        if storage_free > 0 {
            labels.insert("persistent".to_string(), "true".to_string());
        }
        if is_green {
            labels.insert("green".to_string(), "true".to_string());
        }

        Self {
            cpu_cores,
            cpu_load_pct,
            memory_total,
            memory_free,
            storage_total,
            storage_free,
            gpus,
            is_green,
            labels,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn total_vram_free_mb(&self) -> u64 {
        self.gpus.iter().map(|g| g.vram_free / 1024 / 1024).sum()
    }

    pub fn memory_free_mb(&self) -> u64 {
        self.memory_free / 1024 / 1024
    }

    pub fn storage_free_mb(&self) -> u64 {
        self.storage_free / 1024 / 1024
    }

    /// Project live CPU/RAM/Storage/GPU telemetry into the `pinned` `nexus::system` `sys::gpu` table.
    pub async fn project_to_state(
        &self,
        engine: &dyn crate::db::StateEngine,
        node_id: &str,
    ) -> anyhow::Result<()> {
        let total_vram_free: u64 = self.gpus.iter().map(|g| g.vram_free).sum();
        let total_vram: u64 = self.gpus.iter().map(|g| g.vram_total).sum();
        let surql = "DEFINE TABLE IF NOT EXISTS `sys::gpu` SCHEMALESS;
                     UPSERT type::record('sys::gpu', $id) SET
                         node_id = $id,
                         cpu_cores = $cpu,
                         cpu_load_pct = $cpu_load,
                         memory_total = $mem_total,
                         memory_free = $mem_free,
                         storage_total = $disk_total,
                         storage_free = $disk_free,
                         vram_total = $vram_total,
                         vram_free = $vram_free,
                         is_green = $green,
                         updated_at = time::now();";
        let bindings = vec![
            ("id".to_string(), nexus_db::Value::String(node_id.to_string())),
            ("cpu".to_string(), nexus_db::Value::Int(self.cpu_cores as i64)),
            ("cpu_load".to_string(), nexus_db::Value::Int(self.cpu_load_pct as i64)),
            ("mem_total".to_string(), nexus_db::Value::Int(self.memory_total as i64)),
            ("mem_free".to_string(), nexus_db::Value::Int(self.memory_free as i64)),
            ("disk_total".to_string(), nexus_db::Value::Int(self.storage_total as i64)),
            ("disk_free".to_string(), nexus_db::Value::Int(self.storage_free as i64)),
            ("vram_total".to_string(), nexus_db::Value::Int(total_vram as i64)),
            ("vram_free".to_string(), nexus_db::Value::Int(total_vram_free as i64)),
            ("green".to_string(), nexus_db::Value::Bool(self.is_green)),
        ];
        engine.query_scoped("nexus", "system", surql, bindings).await?;
        Ok(())
    }
}
