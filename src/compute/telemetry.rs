use sysinfo::System;

// Actually, let's look at the error again: "no `SystemExt` in the root".
// It might be `sysinfo::traits::SystemExt` or similar, or just not needed.
// Let's try importing `sysinfo::{System, RefreshKind}` and use inherent methods if possible.
// Wait, `SystemExt` is common in older versions.
// Let's try `use sysinfo::System;` and see. The error said `help: a similar name exists in the module: System`.
// So let's just use `System`.
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vram_total: u64,
    pub vram_free: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeResources {
    pub cpu_cores: u32,
    pub memory_total: u64,
    pub memory_free: u64,
    pub gpus: Vec<GpuInfo>,
    pub is_green: bool,
    pub timestamp: i64,
}

impl NodeResources {
    pub fn scan() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        // 1. Core CPU/RAM Telemetry
        let cpu_cores = sys.physical_core_count().unwrap_or(1) as u32;
        let memory_total = sys.total_memory();
        let memory_free = sys.free_memory();
        
        // 2. GPU Telemetry (NVML - Desktop/Server only; gated out on Android/iOS)
        #[allow(unused_mut)]
        let mut gpus = vec![];
        #[cfg(all(feature = "hardware-monitoring", not(any(target_os = "android", target_os = "ios"))))]
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

        // 3. Sustainability Flag (Nexus-IO "Green" incentive)
        // For PoC, we check for NEXUS_GREEN=1 environment variable
        let is_green = std::env::var("NEXUS_GREEN").map(|v| v == "1").unwrap_or(false);

        Self {
            cpu_cores,
            memory_total,
            memory_free,
            gpus,
            is_green,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Project live CPU/RAM/GPU telemetry into the `pinned` `nexus::system` `sys::gpu` table for `InferMesh`.
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
                         memory_total = $mem_total,
                         memory_free = $mem_free,
                         vram_total = $vram_total,
                         vram_free = $vram_free,
                         is_green = $green,
                         updated_at = time::now();";
        let bindings = vec![
            ("id".to_string(), nexus_db::Value::String(node_id.to_string())),
            ("cpu".to_string(), nexus_db::Value::Int(self.cpu_cores as i64)),
            ("mem_total".to_string(), nexus_db::Value::Int(self.memory_total as i64)),
            ("mem_free".to_string(), nexus_db::Value::Int(self.memory_free as i64)),
            ("vram_total".to_string(), nexus_db::Value::Int(total_vram as i64)),
            ("vram_free".to_string(), nexus_db::Value::Int(total_vram_free as i64)),
            ("green".to_string(), nexus_db::Value::Bool(self.is_green)),
        ];
        engine.query_scoped("nexus", "system", surql, bindings).await?;
        Ok(())
    }
}
