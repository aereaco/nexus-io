//! Universal Cross-Platform Native Hardware & OS Native UI Abstraction Layer (HAL)
//!
//! Shared across **every** Wasm hosted guest runtime (Rust, Go, Python, PHP, QuickJS/TS)
//! and Nexus-UX frontends across **Windows, Linux, macOS, Android, iOS, and Server/Edge**.
//!
//! Architectural Contracts:
//! 1. **Discovery vs. Authority:** `HardwareClass` describes what a device is; `Capability`
//!    describes what an application is authorized to do.
//! 2. **Nexus Authorization vs. Dynamic OS Consent:**
//!    `C_effective = C_requested ∩ C_operator ∩ C_IAM ∩ C_OS`.
//!    OS consent (`ConsentState`) is dynamic and queried live via `ConsentProvider`; the host
//!    never trusts a cached `Granted` value as OS permission authority.
//! 3. **Dual UI Mode (Option C):**
//!    - `OsShellProvider`: Native windows, menus, tray, dialogs, notifications, clipboard, haptics.
//!    - Versioned Retained-Mode Binary `UiOp` Protocol (`UiOpHeader` + explicit binary layouts)
//!      for incremental native widget rendering without tying the host to HTML/CSS translation.
//! 4. **Zero-Copy Data Plane:** Streaming hardware and UI batches flow through
//!    `crate::arena::NexusSharedArena` (`SharedBufferHandle`, `RingBufferHandle`, `SpscRingBuffer`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use crate::compute::telemetry::NodeResources;
use crate::iam::capabilities::Capability;

/// Device classification (discovery only — distinct from `Capability` authorization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareClass {
    SystemInfo,
    Power,
    Display,
    Audio,
    Camera,
    Sensor,
    Bluetooth,
    Usb,
    Serial,
    Gpio,
    Nfc,
    Location,
    Biometrics,
    Gpu,
    Storage,
    Network,
    OsUi,
}

impl HardwareClass {
    pub fn from_str_filter(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "system" | "system_info" | "systeminfo" => Some(Self::SystemInfo),
            "power" | "battery" => Some(Self::Power),
            "display" | "screen" => Some(Self::Display),
            "audio" | "mic" | "speaker" => Some(Self::Audio),
            "camera" | "video" => Some(Self::Camera),
            "sensor" | "sensors" => Some(Self::Sensor),
            "bluetooth" | "ble" => Some(Self::Bluetooth),
            "usb" => Some(Self::Usb),
            "serial" | "uart" => Some(Self::Serial),
            "gpio" | "i2c" | "spi" => Some(Self::Gpio),
            "nfc" => Some(Self::Nfc),
            "location" | "gps" => Some(Self::Location),
            "biometrics" | "bio" => Some(Self::Biometrics),
            "gpu" | "npu" | "compute" => Some(Self::Gpu),
            "storage" | "disk" => Some(Self::Storage),
            "network" | "net" => Some(Self::Network),
            "ui" | "os_ui" | "gui" => Some(Self::OsUi),
            _ => None,
        }
    }
}

/// Live OS permission state (queried dynamically from the OS — never permanently cached).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    NotDetermined,
    Granted,
    Denied,
    Restricted,
    Unsupported,
}

/// Outcome of requesting OS permission through the native host UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentRequestResult {
    Granted,
    Denied,
    Pending,
    Unsupported,
}

/// Standardized descriptor for a native hardware device or OS UI subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareDevice {
    pub id: String,
    pub class: HardwareClass,
    pub name: String,
    pub vendor: String,
    pub os: String,
    pub arch: String,
    pub available: bool,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

/// Structured status returned by `HardwareRegistry::dispatch` and `OsShellProvider::handle_shell`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareStatus {
    Ok,
    UnsupportedOnOs,
    HeadlessMode,
    PermissionDenied,
    ConsentRequired,
    DeviceNotFound,
    InvalidRequest,
    Busy,
    Error,
}

/// Canonical typed response shared across Rust, Wasm (`nexus_host` / WIT), and HTTP (`/_nexus/hardware/*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareResponse {
    pub status: HardwareStatus,
    pub op: String,
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HardwareResponse {
    pub fn ok(op: impl Into<String>, data: Value) -> Self {
        Self {
            status: HardwareStatus::Ok,
            op: op.into(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            data,
            error: None,
        }
    }

    pub fn err(op: impl Into<String>, status: HardwareStatus, msg: impl Into<String>) -> Self {
        Self {
            status,
            op: op.into(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            data: Value::Null,
            error: Some(msg.into()),
        }
    }
}

// =============================================================================
// Versioned Retained-Mode Binary `UiOp` Protocol (16-byte fixed C-ABI header)
// =============================================================================

pub const UI_OP_PROTOCOL_VERSION: u16 = 1;

/// Fixed 16-byte binary header for retained-mode native UI widget operation batches.
/// Payloads follow immediately in explicit versioned little-endian binary layouts.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiOpHeader {
    pub version: u16,
    pub opcode: u16,
    pub payload_len: u32,
    pub node_id: u64,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiOpCode {
    CreateNode = 1,
    SetProp = 2,
    SetText = 3,
    AttachChild = 4,
    RemoveNode = 5,
    CommitBatch = 6,
    EmitEvent = 7,
    SetWindowMeta = 8,
}

impl UiOpHeader {
    pub const SIZE: usize = 16;

    pub fn to_le_bytes(self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..2].copy_from_slice(&self.version.to_le_bytes());
        out[2..4].copy_from_slice(&self.opcode.to_le_bytes());
        out[4..8].copy_from_slice(&self.payload_len.to_le_bytes());
        out[8..16].copy_from_slice(&self.node_id.to_le_bytes());
        out
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            version: u16::from_le_bytes([bytes[0], bytes[1]]),
            opcode: u16::from_le_bytes([bytes[2], bytes[3]]),
            payload_len: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            node_id: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
        })
    }
}

/// Validate a packed binary `UiOp` batch and return the number of valid operations decoded.
pub fn validate_ui_op_batch(batch: &[u8]) -> Result<usize, String> {
    let mut offset = 0usize;
    let mut count = 0usize;
    while offset < batch.len() {
        let hdr = UiOpHeader::from_le_bytes(&batch[offset..])
            .ok_or_else(|| format!("Truncated UiOpHeader at byte {}", offset))?;
        if hdr.version != UI_OP_PROTOCOL_VERSION {
            return Err(format!(
                "Unsupported UiOp protocol version {} (expected {})",
                hdr.version, UI_OP_PROTOCOL_VERSION
            ));
        }
        let next = offset
            .checked_add(UiOpHeader::SIZE)
            .and_then(|v| v.checked_add(hdr.payload_len as usize))
            .ok_or_else(|| "UiOp payload length overflow".to_string())?;
        if next > batch.len() {
            return Err(format!(
                "Truncated UiOp payload at byte {} (needed {}, have {})",
                offset,
                hdr.payload_len,
                batch.len() - offset - UiOpHeader::SIZE
            ));
        }
        offset = next;
        count += 1;
    }
    Ok(count)
}

/// Map an operation namespace to its strictly required Nexus `Capability`.
/// Default-deny: unrecognized namespaces require `Capability::HwBus`.
pub fn required_capability_for_op(op: &str) -> Capability {
    let lower = op.trim().to_ascii_lowercase();
    if lower.starts_with("system.")
        || lower == "hw.list"
        || lower == "device.info"
        || lower == "ui.capabilities"
    {
        Capability::HwInfo
    } else if lower.starts_with("camera.") {
        Capability::HwCamera
    } else if lower.starts_with("audio.") {
        Capability::HwAudio
    } else if lower.starts_with("gpu.") || lower.starts_with("npu.") {
        Capability::HwGpu
    } else if lower.starts_with("sensor.")
        || lower.starts_with("location.")
        || lower.starts_with("power.")
    {
        Capability::HwSensor
    } else if lower.starts_with("biometrics.") {
        Capability::HwBiometrics
    } else if lower.starts_with("ui.clipboard.") {
        Capability::OsClipboard
    } else if lower.starts_with("ui.") {
        Capability::OsUi
    } else {
        Capability::HwBus
    }
}

/// Whether accessing `cap` requires live OS-level user consent (e.g., Camera, Audio, Location, Biometrics).
pub fn requires_os_consent(cap: Capability) -> bool {
    matches!(
        cap,
        Capability::HwCamera
            | Capability::HwAudio
            | Capability::HwSensor
            | Capability::HwBiometrics
            | Capability::HwBus
    )
}

// =============================================================================
// Pluggable Provider Traits (Zero OS Driver Crates in `core`)
// =============================================================================

/// Live OS permission query & native prompt coordinator.
pub trait ConsentProvider: Send + Sync {
    fn check_consent(&self, cap: Capability) -> ConsentState;
    /// Must only be triggered by the native host UI, never arbitrarily by background guests.
    fn request_consent(&self, cap: Capability, reason: &str) -> ConsentRequestResult;
}

/// Pluggable hardware discovery & dispatch provider.
pub trait HardwareProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn list_devices(&self) -> Vec<HardwareDevice>;
    fn handles_op(&self, op: &str) -> bool;
    fn call(&self, op: &str, payload: &Value) -> HardwareResponse;
}

/// Pluggable OS Native Shell & Retained-Mode Widget Batch provider.
pub trait OsShellProvider: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn is_headless(&self) -> bool;
    fn supported_ops(&self) -> Vec<String>;
    fn handle_shell(&self, op: &str, payload: &Value) -> HardwareResponse;
    fn commit_ui_ops(&self, batch: &[u8]) -> HardwareResponse {
        match validate_ui_op_batch(batch) {
            Ok(count) => HardwareResponse::ok(
                "ui.ops.commit",
                json!({ "ops_validated": count, "backend": self.backend_name() }),
            ),
            Err(e) => HardwareResponse::err("ui.ops.commit", HardwareStatus::InvalidRequest, e),
        }
    }
}

/// Default `core` OS Consent provider:
/// - `HwInfo` / `OsUi` / `HwGpu` do not require interactive OS consent -> `Granted`.
/// - Sensitive hardware classes default to `NotDetermined` until an OS platform adapter
///   (Android JNI / iOS / macOS / Windows WinRT) reports live OS permission state.
pub struct DefaultConsentProvider;

impl ConsentProvider for DefaultConsentProvider {
    fn check_consent(&self, cap: Capability) -> ConsentState {
        if requires_os_consent(cap) {
            ConsentState::NotDetermined
        } else {
            ConsentState::Granted
        }
    }

    fn request_consent(&self, cap: Capability, _reason: &str) -> ConsentRequestResult {
        if requires_os_consent(cap) {
            ConsentRequestResult::Unsupported
        } else {
            ConsentRequestResult::Granted
        }
    }
}

/// Lean `core` system information & telemetry provider (0 new crates).
pub struct NativeSystemProvider;

impl HardwareProvider for NativeSystemProvider {
    fn provider_name(&self) -> &'static str {
        "nexus-native-system"
    }

    fn list_devices(&self) -> Vec<HardwareDevice> {
        let stats = NodeResources::scan();
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let mut devices = vec![
            HardwareDevice {
                id: "sys:host".to_string(),
                class: HardwareClass::SystemInfo,
                name: format!("{} ({}) Host Compute", os, arch),
                vendor: "native".to_string(),
                os: os.clone(),
                arch: arch.clone(),
                available: true,
                capabilities: vec![
                    "system.info".into(),
                    "system.telemetry".into(),
                    "system.os".into(),
                ],
                metadata: BTreeMap::from([
                    ("cpu_cores".into(), json!(stats.cpu_cores)),
                    ("cpu_load_pct".into(), json!(stats.cpu_load_pct)),
                    ("memory_total".into(), json!(stats.memory_total)),
                    ("memory_free".into(), json!(stats.memory_free)),
                    ("is_green".into(), json!(stats.is_green)),
                ]),
            },
            HardwareDevice {
                id: "storage:local".to_string(),
                class: HardwareClass::Storage,
                name: "Local Native Volumes".to_string(),
                vendor: "native".to_string(),
                os: os.clone(),
                arch: arch.clone(),
                available: stats.storage_total > 0,
                capabilities: vec!["system.storage".into()],
                metadata: BTreeMap::from([
                    ("storage_total".into(), json!(stats.storage_total)),
                    ("storage_free".into(), json!(stats.storage_free)),
                ]),
            },
        ];

        for (idx, gpu) in stats.gpus.iter().enumerate() {
            devices.push(HardwareDevice {
                id: format!("gpu:{}", idx),
                class: HardwareClass::Gpu,
                name: gpu.name.clone(),
                vendor: "native-gpu".to_string(),
                os: os.clone(),
                arch: arch.clone(),
                available: true,
                capabilities: vec!["gpu.list".into(), "gpu.info".into()],
                metadata: BTreeMap::from([
                    ("vram_total".into(), json!(gpu.vram_total)),
                    ("vram_free".into(), json!(gpu.vram_free)),
                ]),
            });
        }

        devices
    }

    fn handles_op(&self, op: &str) -> bool {
        matches!(
            op.trim().to_ascii_lowercase().as_str(),
            "system.info"
                | "system.telemetry"
                | "system.os"
                | "system.storage"
                | "device.info"
                | "gpu.list"
                | "gpu.info"
        )
    }

    fn call(&self, op: &str, _payload: &Value) -> HardwareResponse {
        let lower = op.trim().to_ascii_lowercase();
        let stats = NodeResources::scan();
        match lower.as_str() {
            "system.info" | "system.telemetry" | "device.info" => HardwareResponse::ok(
                op,
                json!({
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                    "family": std::env::consts::FAMILY,
                    "cpu_cores": stats.cpu_cores,
                    "cpu_load_pct": stats.cpu_load_pct,
                    "memory_total": stats.memory_total,
                    "memory_free": stats.memory_free,
                    "storage_total": stats.storage_total,
                    "storage_free": stats.storage_free,
                    "gpus": stats.gpus,
                    "is_green": stats.is_green,
                    "labels": stats.labels,
                    "webview_compiled": cfg!(feature = "gui-webview"),
                }),
            ),
            "system.os" => HardwareResponse::ok(
                op,
                json!({
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                    "family": std::env::consts::FAMILY,
                    "native_webview_engine": native_webview_engine_name(),
                    "native_ui_toolkit": native_ui_toolkit_name(),
                }),
            ),
            "system.storage" => HardwareResponse::ok(
                op,
                json!({
                    "storage_total": stats.storage_total,
                    "storage_free": stats.storage_free,
                }),
            ),
            "gpu.list" | "gpu.info" => HardwareResponse::ok(
                op,
                json!({
                    "count": stats.gpus.len(),
                    "gpus": stats.gpus,
                }),
            ),
            _ => HardwareResponse::err(op, HardwareStatus::UnsupportedOnOs, "Unhandled system op"),
        }
    }
}

/// Default `core` OS Shell provider (reports platform capabilities & provides a safe state mirror
/// until a platform-native desktop/mobile UI adapter is registered).
pub struct DefaultOsShellProvider {
    state: RwLock<OsShellState>,
}

#[derive(Debug, Clone, Default)]
struct OsShellState {
    title: String,
    theme: String,
    clipboard_text: String,
    notifications_sent: u64,
    tray_tooltip: String,
}

impl Default for DefaultOsShellProvider {
    fn default() -> Self {
        Self {
            state: RwLock::new(OsShellState {
                title: "Aerea Nexus".to_string(),
                theme: "system".to_string(),
                clipboard_text: String::new(),
                notifications_sent: 0,
                tray_tooltip: "Nexus-IO".to_string(),
            }),
        }
    }
}

impl OsShellProvider for DefaultOsShellProvider {
    fn backend_name(&self) -> &'static str {
        native_ui_toolkit_name()
    }

    fn is_headless(&self) -> bool {
        #[cfg(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "android",
            target_os = "ios"
        ))]
        {
            std::env::var("NEXUS_HEADLESS")
                .map(|v| v == "1")
                .unwrap_or(false)
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "android",
            target_os = "ios"
        )))]
        {
            std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err()
        }
    }

    fn supported_ops(&self) -> Vec<String> {
        vec![
            "ui.capabilities".into(),
            "ui.window.set_title".into(),
            "ui.window.get_state".into(),
            "ui.window.set_theme".into(),
            "ui.notify.send".into(),
            "ui.tray.set_tooltip".into(),
            "ui.dialog.alert".into(),
            "ui.dialog.open_file".into(),
            "ui.dialog.save_file".into(),
            "ui.clipboard.read".into(),
            "ui.clipboard.write".into(),
            "ui.haptics.impact".into(),
            "ui.share".into(),
            "ui.webview.post_message".into(),
        ]
    }

    fn handle_shell(&self, op: &str, payload: &Value) -> HardwareResponse {
        let lower = op.trim().to_ascii_lowercase();
        match lower.as_str() {
            "ui.capabilities" => HardwareResponse::ok(
                op,
                json!({
                    "backend": self.backend_name(),
                    "webview_engine": native_webview_engine_name(),
                    "webview_compiled": cfg!(feature = "gui-webview"),
                    "ui_op_protocol_version": UI_OP_PROTOCOL_VERSION,
                    "headless": self.is_headless(),
                    "supported_ops": self.supported_ops(),
                }),
            ),
            "ui.window.set_title" => {
                let title = payload
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Aerea Nexus")
                    .to_string();
                if let Ok(mut st) = self.state.write() {
                    st.title = title.clone();
                }
                HardwareResponse::ok(op, json!({ "title": title, "applied": true }))
            }
            "ui.window.set_theme" => {
                let theme = payload
                    .get("theme")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system")
                    .to_string();
                if let Ok(mut st) = self.state.write() {
                    st.theme = theme.clone();
                }
                HardwareResponse::ok(op, json!({ "theme": theme, "applied": true }))
            }
            "ui.window.get_state" => {
                let st = self.state.read().map(|g| g.clone()).unwrap_or_default();
                HardwareResponse::ok(
                    op,
                    json!({
                        "title": st.title,
                        "theme": st.theme,
                        "tray_tooltip": st.tray_tooltip,
                        "notifications_sent": st.notifications_sent,
                        "headless": self.is_headless(),
                    }),
                )
            }
            "ui.notify.send" => {
                let title = payload.get("title").and_then(|v| v.as_str()).unwrap_or("Nexus");
                let body = payload.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let count = if let Ok(mut st) = self.state.write() {
                    st.notifications_sent += 1;
                    st.notifications_sent
                } else {
                    1
                };
                HardwareResponse::ok(
                    op,
                    json!({ "delivered": true, "title": title, "body": body, "sequence": count }),
                )
            }
            "ui.tray.set_tooltip" => {
                let tip = payload
                    .get("tooltip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Nexus-IO")
                    .to_string();
                if let Ok(mut st) = self.state.write() {
                    st.tray_tooltip = tip.clone();
                }
                HardwareResponse::ok(op, json!({ "tooltip": tip, "applied": true }))
            }
            "ui.clipboard.write" => {
                let text = payload
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Ok(mut st) = self.state.write() {
                    st.clipboard_text = text.clone();
                }
                HardwareResponse::ok(op, json!({ "written_bytes": text.len() }))
            }
            "ui.clipboard.read" => {
                let text = self
                    .state
                    .read()
                    .map(|g| g.clipboard_text.clone())
                    .unwrap_or_default();
                HardwareResponse::ok(op, json!({ "text": text }))
            }
            "ui.dialog.alert"
            | "ui.dialog.open_file"
            | "ui.dialog.save_file"
            | "ui.haptics.impact"
            | "ui.share"
            | "ui.webview.post_message" => {
                if self.is_headless() {
                    return HardwareResponse::err(
                        op,
                        HardwareStatus::HeadlessMode,
                        format!("OS UI operation '{}' requires an active native GUI session", op),
                    );
                }
                HardwareResponse::ok(
                    op,
                    json!({
                        "backend": self.backend_name(),
                        "accepted": true,
                        "payload": payload,
                    }),
                )
            }
            _ => HardwareResponse::err(
                op,
                HardwareStatus::UnsupportedOnOs,
                format!("Unsupported OS UI operation '{}'", op),
            ),
        }
    }
}

pub fn native_webview_engine_name() -> &'static str {
    #[cfg(target_os = "windows")]
    { "WebView2 (Windows Native)" }
    #[cfg(target_os = "macos")]
    { "WKWebView (macOS Native)" }
    #[cfg(target_os = "ios")]
    { "WKWebView (iOS Native)" }
    #[cfg(target_os = "android")]
    { "Android WebView (JNI Native)" }
    #[cfg(target_os = "linux")]
    { "WebKitGTK (Linux Native)" }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "linux"
    )))]
    { "Headless / Generic" }
}

pub fn native_ui_toolkit_name() -> &'static str {
    #[cfg(target_os = "windows")]
    { "Win32 / WinRT Native UI" }
    #[cfg(target_os = "macos")]
    { "AppKit / SwiftUI Native UI" }
    #[cfg(target_os = "ios")]
    { "UIKit / SwiftUI Native UI" }
    #[cfg(target_os = "android")]
    { "Android Views / Jetpack Compose JNI" }
    #[cfg(target_os = "linux")]
    { "GTK / XDG Desktop Portal" }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "linux"
    )))]
    { "Headless UI Adapter" }
}

/// Process-wide universal discovery, consent check, and provider-dispatch registry.
pub struct HardwareRegistry {
    providers: RwLock<Vec<Arc<dyn HardwareProvider>>>,
    shell_provider: RwLock<Arc<dyn OsShellProvider>>,
    consent_provider: RwLock<Arc<dyn ConsentProvider>>,
}

static GLOBAL_HW_REGISTRY: OnceLock<Arc<HardwareRegistry>> = OnceLock::new();

impl HardwareRegistry {
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(vec![Arc::new(NativeSystemProvider)]),
            shell_provider: RwLock::new(Arc::new(DefaultOsShellProvider::default())),
            consent_provider: RwLock::new(Arc::new(DefaultConsentProvider)),
        }
    }

    pub fn global() -> Arc<Self> {
        GLOBAL_HW_REGISTRY
            .get_or_init(|| Arc::new(Self::new()))
            .clone()
    }

    /// Register a hardware provider, rejecting duplicate `provider_name()` registrations.
    pub fn register_provider(&self, provider: Arc<dyn HardwareProvider>) -> Result<(), String> {
        let mut list = self
            .providers
            .write()
            .map_err(|_| "HardwareRegistry lock poisoned".to_string())?;
        if list.iter().any(|p| p.provider_name() == provider.provider_name()) {
            return Err(format!(
                "Duplicate hardware provider '{}' is already registered",
                provider.provider_name()
            ));
        }
        list.push(provider);
        Ok(())
    }

    /// Unregister a hardware provider by name (e.g., hot-unplug / module teardown).
    pub fn unregister_provider(&self, provider_name: &str) -> bool {
        if let Ok(mut list) = self.providers.write() {
            let before = list.len();
            list.retain(|p| p.provider_name() != provider_name);
            return list.len() < before;
        }
        false
    }

    pub fn register_shell_provider(&self, provider: Arc<dyn OsShellProvider>) {
        if let Ok(mut guard) = self.shell_provider.write() {
            *guard = provider;
        }
    }

    pub fn register_consent_provider(&self, provider: Arc<dyn ConsentProvider>) {
        if let Ok(mut guard) = self.consent_provider.write() {
            *guard = provider;
        }
    }

    /// Live query of OS permission state (never caches OS grants across revocations).
    pub fn check_os_consent(&self, cap: Capability) -> ConsentState {
        self.consent_provider
            .read()
            .map(|p| p.check_consent(cap))
            .unwrap_or(ConsentState::Unsupported)
    }

    /// Trigger an OS permission prompt via the native host UI adapter.
    pub fn request_os_consent(&self, cap: Capability, reason: &str) -> ConsentRequestResult {
        self.consent_provider
            .read()
            .map(|p| p.request_consent(cap, reason))
            .unwrap_or(ConsentRequestResult::Unsupported)
    }

    pub fn list_devices(&self, class_filter: Option<HardwareClass>) -> Vec<HardwareDevice> {
        let mut all = Vec::new();
        if let Ok(list) = self.providers.read() {
            for p in list.iter() {
                // Panic-isolated discovery: a faulty native driver cannot crash the host or hide other devices
                if let Ok(devs) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.list_devices())) {
                    all.extend(devs);
                }
            }
        }
        if let Ok(ui) = self.shell_provider.read() {
            all.push(HardwareDevice {
                id: "os:ui".to_string(),
                class: HardwareClass::OsUi,
                name: ui.backend_name().to_string(),
                vendor: "native-os".to_string(),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                available: !ui.is_headless(),
                capabilities: ui.supported_ops(),
                metadata: BTreeMap::from([
                    ("webview_engine".into(), json!(native_webview_engine_name())),
                    ("webview_compiled".into(), json!(cfg!(feature = "gui-webview"))),
                    ("ui_op_protocol_version".into(), json!(UI_OP_PROTOCOL_VERSION)),
                    ("headless".into(), json!(ui.is_headless())),
                ]),
            });
        }
        if let Some(filter) = class_filter {
            all.into_iter().filter(|d| d.class == filter).collect()
        } else {
            all
        }
    }

    /// Commit a versioned retained-mode binary `UiOp` batch to the active OS UI provider.
    pub fn commit_ui_ops(&self, batch: &[u8]) -> HardwareResponse {
        if let Ok(ui) = self.shell_provider.read() {
            ui.commit_ui_ops(batch)
        } else {
            HardwareResponse::err("ui.ops.commit", HardwareStatus::Error, "UI provider lock poisoned")
        }
    }

    /// Shared capability + live OS consent + panic-isolated dispatch entrypoint used by BOTH
    /// low-level `nexus_host` C-ABI imports and typed WIT Component Model host bindings.
    pub fn dispatch_authorized(
        &self,
        caps: &crate::iam::capabilities::CapabilitySet,
        op: &str,
        payload: &Value,
    ) -> HardwareResponse {
        let req_cap = required_capability_for_op(op);
        if !caps.has(req_cap) {
            return HardwareResponse::err(
                op,
                HardwareStatus::PermissionDenied,
                format!("Missing required capability {:?} for '{}'", req_cap, op),
            );
        }
        self.dispatch(op, payload)
    }

    /// Dispatch a hardware or OS shell call after checking live OS consent for sensitive classes.
    /// Callers MUST enforce Nexus IAM / `CapabilitySet` authorization BEFORE calling `dispatch`.
    pub fn dispatch(&self, op: &str, payload: &Value) -> HardwareResponse {
        let trimmed = op.trim();
        let lower = trimmed.to_ascii_lowercase();
        let req_cap = required_capability_for_op(trimmed);

        if requires_os_consent(req_cap) {
            let consent = self.check_os_consent(req_cap);
            if consent != ConsentState::Granted {
                return HardwareResponse::err(
                    trimmed,
                    HardwareStatus::ConsentRequired,
                    format!("OS consent state for {:?} is {:?} (must be Granted)", req_cap, consent),
                );
            }
        }

        if lower == "hw.list" {
            let filter = payload
                .get("class")
                .and_then(|v| v.as_str())
                .and_then(HardwareClass::from_str_filter);
            return HardwareResponse::ok(trimmed, json!({ "devices": self.list_devices(filter) }));
        }
        if lower.starts_with("ui.") {
            if let Ok(ui) = self.shell_provider.read() {
                return match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    ui.handle_shell(trimmed, payload)
                })) {
                    Ok(resp) => resp,
                    Err(_) => HardwareResponse::err(
                        trimmed,
                        HardwareStatus::Error,
                        "OS shell provider panicked during dispatch (isolated)",
                    ),
                };
            }
        }
        if let Ok(list) = self.providers.read() {
            for p in list.iter().rev() {
                if p.handles_op(trimmed) {
                    return match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        p.call(trimmed, payload)
                    })) {
                        Ok(resp) => resp,
                        Err(_) => HardwareResponse::err(
                            trimmed,
                            HardwareStatus::Error,
                            format!(
                                "Hardware provider '{}' panicked during '{}' (isolated)",
                                p.provider_name(),
                                trimmed
                            ),
                        ),
                    };
                }
            }
        }
        HardwareResponse::err(
            trimmed,
            HardwareStatus::UnsupportedOnOs,
            format!(
                "No native hardware provider registered for '{}' on {}/{}",
                trimmed,
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::capabilities::CapabilitySet;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DynamicConsent(AtomicBool);
    impl ConsentProvider for DynamicConsent {
        fn check_consent(&self, cap: Capability) -> ConsentState {
            if cap == Capability::HwCamera {
                if self.0.load(Ordering::Acquire) {
                    ConsentState::Granted
                } else {
                    ConsentState::Denied
                }
            } else {
                ConsentState::Granted
            }
        }
        fn request_consent(&self, _cap: Capability, _reason: &str) -> ConsentRequestResult {
            ConsentRequestResult::Denied
        }
    }

    struct MockCameraProvider(AtomicBool);
    impl HardwareProvider for MockCameraProvider {
        fn provider_name(&self) -> &'static str {
            "mock-camera"
        }
        fn list_devices(&self) -> Vec<HardwareDevice> {
            if !self.0.load(Ordering::Acquire) {
                return vec![];
            }
            vec![HardwareDevice {
                id: "cam:0".into(),
                class: HardwareClass::Camera,
                name: "Mock USB Cam".into(),
                vendor: "test".into(),
                os: "test".into(),
                arch: "test".into(),
                available: true,
                capabilities: vec!["camera.capture".into()],
                metadata: BTreeMap::new(),
            }]
        }
        fn handles_op(&self, op: &str) -> bool {
            op == "camera.capture"
        }
        fn call(&self, op: &str, _payload: &Value) -> HardwareResponse {
            if !self.0.load(Ordering::Acquire) {
                return HardwareResponse::err(op, HardwareStatus::DeviceNotFound, "Camera unplugged");
            }
            HardwareResponse::ok(op, json!({ "frame_bytes": 1024 }))
        }
    }

    struct PanickingProvider;
    impl HardwareProvider for PanickingProvider {
        fn provider_name(&self) -> &'static str {
            "faulty-driver"
        }
        fn list_devices(&self) -> Vec<HardwareDevice> {
            panic!("simulated driver crash during discovery");
        }
        fn handles_op(&self, op: &str) -> bool {
            op == "usb.crash"
        }
        fn call(&self, _op: &str, _payload: &Value) -> HardwareResponse {
            panic!("simulated driver crash during call");
        }
    }

    #[test]
    fn hardware_registry_lifecycle_duplicate_panic_consent_and_unplug() {
        let reg = Arc::new(HardwareRegistry::new());
        let consent = Arc::new(DynamicConsent(AtomicBool::new(true)));
        let cam = Arc::new(MockCameraProvider(AtomicBool::new(true)));
        reg.register_consent_provider(consent.clone());
        assert!(reg.register_provider(cam.clone()).is_ok());
        // Duplicate provider registration MUST be rejected
        assert!(reg.register_provider(cam.clone()).is_err());
        assert!(reg.register_provider(Arc::new(PanickingProvider)).is_ok());

        // Panic isolation during discovery & dispatch
        let devices = reg.list_devices(None);
        assert!(devices.iter().any(|d| d.id == "cam:0"));
        assert!(devices.iter().any(|d| d.class == HardwareClass::SystemInfo));
        let crash_caps = CapabilitySet::from_iter([Capability::HwBus]);
        let crash_res = reg.dispatch_authorized(&crash_caps, "usb.crash", &json!({}));
        assert_eq!(crash_res.status, HardwareStatus::Error);

        // Authorized + OS consent granted -> succeeds
        let cam_caps = CapabilitySet::from_iter([Capability::HwCamera]);
        assert_eq!(
            reg.dispatch_authorized(&cam_caps, "camera.capture", &json!({})).status,
            HardwareStatus::Ok
        );

        // Dynamic OS consent revocation mid-stream -> fails closed immediately!
        consent.0.store(false, Ordering::Release);
        assert_eq!(
            reg.dispatch_authorized(&cam_caps, "camera.capture", &json!({})).status,
            HardwareStatus::ConsentRequired
        );

        // Restore consent, simulate device disappearance (unplug)
        consent.0.store(true, Ordering::Release);
        cam.0.store(false, Ordering::Release);
        assert!(!reg.list_devices(Some(HardwareClass::Camera)).iter().any(|d| d.id == "cam:0"));
        assert_eq!(
            reg.dispatch_authorized(&cam_caps, "camera.capture", &json!({})).status,
            HardwareStatus::DeviceNotFound
        );

        // Concurrent discovery + dispatch safety
        let mut threads = Vec::new();
        for _ in 0..4 {
            let r = reg.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..10 {
                    let _ = r.list_devices(None);
                    let _ = r.dispatch("system.info", &json!({}));
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn hardware_registry_separates_discovery_consent_and_ui_ops() {
        let reg = HardwareRegistry::global();
        let devices = reg.list_devices(None);
        assert!(devices.iter().any(|d| d.class == HardwareClass::SystemInfo));
        assert!(devices.iter().any(|d| d.class == HardwareClass::OsUi));

        let info = reg.dispatch("system.info", &json!({}));
        assert_eq!(info.status, HardwareStatus::Ok);
        assert!(info.data["cpu_cores"].as_u64().unwrap_or(0) >= 1);

        let cam = reg.dispatch("camera.capture", &json!({}));
        assert_eq!(cam.status, HardwareStatus::ConsentRequired);

        // Missing auth context MUST have zero capabilities (default-deny)
        let unauth_caps = CapabilitySet::from_auth_context(None);
        assert_eq!(
            reg.dispatch_authorized(&unauth_caps, "system.info", &json!({})).status,
            HardwareStatus::PermissionDenied
        );

        let hdr = UiOpHeader {
            version: UI_OP_PROTOCOL_VERSION,
            opcode: UiOpCode::SetText as u16,
            payload_len: 5,
            node_id: 42,
        };
        let mut batch = Vec::new();
        batch.extend_from_slice(&hdr.to_le_bytes());
        batch.extend_from_slice(b"hello");
        let commit_res = reg.commit_ui_ops(&batch);
        assert_eq!(commit_res.status, HardwareStatus::Ok);
        assert_eq!(commit_res.data["ops_validated"], 1);
    }

    #[test]
    fn required_capability_maps_hardware_and_ui_namespaces_strictly() {
        assert_eq!(required_capability_for_op("system.info"), Capability::HwInfo);
        assert_eq!(required_capability_for_op("camera.capture"), Capability::HwCamera);
        assert_eq!(required_capability_for_op("audio.record"), Capability::HwAudio);
        assert_eq!(required_capability_for_op("gpu.list"), Capability::HwGpu);
        assert_eq!(required_capability_for_op("sensor.accel"), Capability::HwSensor);
        assert_eq!(required_capability_for_op("biometrics.verify"), Capability::HwBiometrics);
        assert_eq!(required_capability_for_op("ui.window.set_title"), Capability::OsUi);
        assert_eq!(required_capability_for_op("ui.clipboard.read"), Capability::OsClipboard);
        assert_eq!(required_capability_for_op("usb.transfer"), Capability::HwBus);
    }
}
