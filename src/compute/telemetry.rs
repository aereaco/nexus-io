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
        
        // 2. GPU Telemetry (NVML)
        let mut gpus = vec![];
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
}
