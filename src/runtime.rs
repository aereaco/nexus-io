use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Explicit lifecycle state of a Nexus-IO runtime capability, separating compile-time
/// availability from runtime initialization and active background execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    NotCompiled,
    Compiled,
    Configured,
    Initialized,
    Active,
    Suspended,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityInfo {
    pub name: String,
    pub state: CapabilityState,
    pub detail: Option<String>,
}

/// Runtime capability registry making compile-time profiles and lazy runtime activation
/// observable (e.g., via `GET /_nexus/capabilities`).
#[derive(Clone)]
pub struct CapabilityRegistry {
    entries: Arc<RwLock<BTreeMap<String, CapabilityInfo>>>,
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        let mut map = BTreeMap::new();
        let mut reg = |name: &str, compiled: bool| {
            map.insert(
                name.to_string(),
                CapabilityInfo {
                    name: name.to_string(),
                    state: if compiled {
                        CapabilityState::Compiled
                    } else {
                        CapabilityState::NotCompiled
                    },
                    detail: None,
                },
            );
        };

        reg("database", true);
        reg("gateway", true);
        reg("js-runtime", true);
        reg("cells", true);
        reg("iam", true);
        reg("object-storage", true);
        reg("p2p-storage", cfg!(feature = "p2p-storage"));
        reg("s3-gateway", cfg!(feature = "s3-gateway"));
        reg("shell", cfg!(feature = "shell"));
        reg("wasm-runtime", cfg!(feature = "wasm-runtime"));
        reg("k8s-bridge", cfg!(feature = "k8s-bridge"));
        reg("vpn", cfg!(feature = "vpn"));
        reg("hardware-monitoring", cfg!(feature = "hardware-monitoring"));
        reg("surrealdb-ref", cfg!(feature = "surrealdb-ref"));

        let gui_desc = crate::ux::native_gui::NativeGuiDescriptor::current();
        map.insert(
            "gui".to_string(),
            CapabilityInfo {
                name: "gui".to_string(),
                state: if gui_desc.compiled {
                    CapabilityState::Compiled
                } else {
                    CapabilityState::NotCompiled
                },
                detail: Some(gui_desc.engine_label.to_string()),
            },
        );

        Self {
            entries: Arc::new(RwLock::new(map)),
        }
    }

    pub fn set_state(&self, name: &str, state: CapabilityState, detail: Option<String>) {
        let mut guard = self.entries.write().unwrap();
        guard.insert(
            name.to_string(),
            CapabilityInfo {
                name: name.to_string(),
                state,
                detail,
            },
        );
    }

    pub fn get_state(&self, name: &str) -> CapabilityState {
        self.entries
            .read()
            .unwrap()
            .get(name)
            .map(|c| c.state)
            .unwrap_or(CapabilityState::NotCompiled)
    }

    pub fn active_profile() -> &'static str {
        if cfg!(feature = "profile-dev") {
            "profile-dev"
        } else if cfg!(feature = "profile-full") {
            "profile-full"
        } else if cfg!(feature = "profile-app") {
            "profile-app"
        } else {
            "profile-core"
        }
    }

    pub fn active_os_profile() -> &'static str {
        if cfg!(feature = "profile-windows") {
            "profile-windows"
        } else if cfg!(feature = "profile-linux") {
            "profile-linux"
        } else if cfg!(feature = "profile-macos") {
            "profile-macos"
        } else if cfg!(feature = "profile-android") {
            "profile-android"
        } else if cfg!(feature = "profile-ios") {
            "profile-ios"
        } else {
            "generic"
        }
    }

    pub fn snapshot_json(&self) -> serde_json::Value {
        let guard = self.entries.read().unwrap();
        let list: Vec<&CapabilityInfo> = guard.values().collect();
        let gui_desc = crate::ux::native_gui::NativeGuiDescriptor::current();
        serde_json::json!({
            "profile": Self::active_profile(),
            "os_profile": Self::active_os_profile(),
            "target_os": std::env::consts::OS,
            "native_webview_engine": gui_desc.engine_label,
            "capabilities": list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_registry_tracks_compiled_vs_active_lifecycle() {
        let reg = CapabilityRegistry::new();
        assert_eq!(reg.get_state("database"), CapabilityState::Compiled);
        reg.set_state(
            "database",
            CapabilityState::Active,
            Some("nexus-db (redb)".into()),
        );
        assert_eq!(reg.get_state("database"), CapabilityState::Active);

        let snap = reg.snapshot_json();
        assert!(snap["profile"].is_string());
        assert!(snap["capabilities"].as_array().unwrap().len() >= 10);
    }
}
