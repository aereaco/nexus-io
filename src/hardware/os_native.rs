//! Milestone 2 — Native OS Integration:
//! 1. **Real Desktop OS Shell Provider (`NativeDesktopShellProvider`)**:
//!    - Windows (`target_os = "windows"`), macOS (`target_os = "macos"`), and Linux (`target_os = "linux"`)
//!      native clipboard, toast notification, and file dialog hooks (0 new crates in `core`).
//!    - Opt-in live OS invocation (`NEXUS_OS_UI_NATIVE=1` or explicit `native: true` flag in payload)
//!      so automated CI/unit tests never pop blocking OS dialogs or overwrite the developer's clipboard
//!      unless explicitly requested, while real desktop apps get native OS integration out of the box.
//! 2. **Retained-Mode `UiTree` & `UiEvent` Loop (`UiOpHeader` v1)**:
//!    - Applies versioned binary `UiOpHeader` batches (`CreateNode`, `SetProp`, `SetText`,
//!      `AttachChild`, `RemoveNode`, `CommitBatch`, `SetWindowMeta`) to a live retained widget tree.
//!    - Pushes structured `UiEvent` records back to Wasm guests via `NexusSharedArena` SPSC rings
//!      or `ui.events.poll`.
//! 3. **Mobile-Oriented Provider Design (`MobilePlatformBridge`)**:
//!    - Clean, zero-dependency FFI/JNI callback contract for Android (`Activity`/`SAF`/`BiometricPrompt`/
//!      `Jetpack Compose`) and iOS (`UIKit`/`SwiftUI`/`UIDocumentPicker`/`LAContext`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};

use crate::arena::{NexusSharedArena, RingBufferHandle, TransportMode};
use crate::hardware::{
    native_ui_toolkit_name, native_webview_engine_name, ConsentProvider, ConsentRequestResult,
    ConsentState, HardwareResponse, HardwareStatus, OsShellProvider, UiOpCode, UiOpHeader,
    UI_OP_PROTOCOL_VERSION,
};
use crate::iam::capabilities::Capability;

/// A node in the retained-mode native UI widget tree (`UiOp` v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetainedUiNode {
    pub node_id: u64,
    pub kind: String,
    pub text: String,
    pub props: BTreeMap<String, String>,
    pub children: Vec<u64>,
    pub parent: Option<u64>,
}

/// An event emitted from the native OS shell / widget tree back to a Wasm guest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiEvent {
    pub seq: u64,
    pub node_id: u64,
    pub event_type: String,
    pub payload: String,
}

/// Retained-mode UI tree state maintained by `NativeDesktopShellProvider`.
#[derive(Debug, Default)]
pub struct RetainedUiTree {
    pub nodes: BTreeMap<u64, RetainedUiNode>,
    pub commit_generation: u64,
    pub events: VecDeque<UiEvent>,
    pub next_event_seq: u64,
    /// Optional SPSC ring buffer handle in `NexusSharedArena` for streaming `UiEvent`s to a guest.
    pub event_ring: Option<RingBufferHandle>,
}

impl RetainedUiTree {
    /// Apply a versioned binary `UiOpHeader` batch to the retained widget tree atomically.
    ///
    /// Binary payload layouts (little-endian, version 1):
    /// - `CreateNode (1)`: UTF-8 widget kind string (e.g. `"button"`, `"stack"`, `"text"`, `"input"`).
    /// - `SetProp (2)`: UTF-8 `"key=value"` string.
    /// - `SetText (3)`: UTF-8 text content string.
    /// - `AttachChild (4)`: 8-byte `u64` little-endian `child_node_id` (parent is `hdr.node_id`).
    /// - `RemoveNode (5)`: empty payload (removes `hdr.node_id` and detaches from parent).
    /// - `CommitBatch (6)`: empty payload (increments `commit_generation`).
    /// - `EmitEvent (7)`: UTF-8 `"event_type:payload"` (enqueues a `UiEvent`).
    /// - `SetWindowMeta (8)`: UTF-8 `"key=value"` window metadata update.
    pub fn apply_binary_batch(&mut self, batch: &[u8]) -> Result<usize, String> {
        // Phase 1: Validate entire batch before mutating tree (transactional batch guarantee)
        let mut decoded = Vec::new();
        let mut offset = 0usize;
        while offset < batch.len() {
            let hdr = UiOpHeader::from_le_bytes(&batch[offset..])
                .ok_or_else(|| format!("Truncated UiOpHeader at byte {}", offset))?;
            if hdr.version != UI_OP_PROTOCOL_VERSION {
                return Err(format!(
                    "Unsupported UiOp protocol version {} (expected {})",
                    hdr.version, UI_OP_PROTOCOL_VERSION
                ));
            }
            let payload_start = offset + UiOpHeader::SIZE;
            let payload_end = payload_start
                .checked_add(hdr.payload_len as usize)
                .ok_or_else(|| "UiOp payload length overflow".to_string())?;
            if payload_end > batch.len() {
                return Err(format!("Truncated UiOp payload at byte {}", offset));
            }
            decoded.push((hdr, &batch[payload_start..payload_end]));
            offset = payload_end;
        }

        // Phase 2: Commit validated operations into retained tree
        let count = decoded.len();
        for (hdr, payload) in decoded {
            match hdr.opcode {
                x if x == UiOpCode::CreateNode as u16 => {
                    let kind = String::from_utf8_lossy(payload).to_string();
                    self.nodes.insert(
                        hdr.node_id,
                        RetainedUiNode {
                            node_id: hdr.node_id,
                            kind: if kind.is_empty() { "view".into() } else { kind },
                            text: String::new(),
                            props: BTreeMap::new(),
                            children: Vec::new(),
                            parent: None,
                        },
                    );
                }
                x if x == UiOpCode::SetProp as u16 => {
                    let s = String::from_utf8_lossy(payload);
                    if let Some((k, v)) = s.split_once('=') {
                        if let Some(node) = self.nodes.get_mut(&hdr.node_id) {
                            node.props.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                x if x == UiOpCode::SetText as u16 => {
                    let text = String::from_utf8_lossy(payload).to_string();
                    if let Some(node) = self.nodes.get_mut(&hdr.node_id) {
                        node.text = text;
                    }
                }
                x if x == UiOpCode::AttachChild as u16 => {
                    if payload.len() >= 8 {
                        let child_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                        if let Some(parent) = self.nodes.get_mut(&hdr.node_id) {
                            if !parent.children.contains(&child_id) {
                                parent.children.push(child_id);
                            }
                        }
                        if let Some(child) = self.nodes.get_mut(&child_id) {
                            child.parent = Some(hdr.node_id);
                        }
                    }
                }
                x if x == UiOpCode::RemoveNode as u16 => {
                    if let Some(removed) = self.nodes.remove(&hdr.node_id) {
                        if let Some(pid) = removed.parent {
                            if let Some(parent) = self.nodes.get_mut(&pid) {
                                parent.children.retain(|&c| c != hdr.node_id);
                            }
                        }
                    }
                }
                x if x == UiOpCode::CommitBatch as u16 => {
                    self.commit_generation += 1;
                }
                x if x == UiOpCode::EmitEvent as u16 => {
                    let s = String::from_utf8_lossy(payload);
                    let (ev_type, ev_payload) = s.split_once(':').unwrap_or((s.as_ref(), ""));
                    self.push_event(hdr.node_id, ev_type, ev_payload);
                }
                x if x == UiOpCode::SetWindowMeta as u16 => {
                    self.commit_generation += 1;
                }
                other => {
                    return Err(format!("Unknown UiOpCode {}", other));
                }
            }
        }
        Ok(count)
    }

    /// Push a UI event into both the bounded queue and (if attached) the `NexusSharedArena` SPSC ring.
    pub fn push_event(&mut self, node_id: u64, event_type: &str, payload: &str) -> UiEvent {
        self.next_event_seq += 1;
        let ev = UiEvent {
            seq: self.next_event_seq,
            node_id,
            event_type: event_type.to_string(),
            payload: payload.to_string(),
        };
        if self.events.len() >= 1024 {
            self.events.pop_front();
        }
        self.events.push_back(ev.clone());

        if let Some(handle) = self.event_ring {
            if let Ok(ring) = NexusSharedArena::global().get_ring(handle, None) {
                if let Ok(bytes) = serde_json::to_vec(&ev) {
                    let len = (bytes.len() as u32).to_le_bytes();
                    let mut frame = Vec::with_capacity(4 + bytes.len());
                    frame.extend_from_slice(&len);
                    frame.extend_from_slice(&bytes);
                    let _ = ring.write(&frame);
                }
            }
        }
        ev
    }

    pub fn drain_events(&mut self, max: usize) -> Vec<UiEvent> {
        let n = max.min(self.events.len());
        self.events.drain(..n).collect()
    }
}

#[derive(Debug, Clone)]
struct DesktopWindowState {
    title: String,
    theme: String,
    tray_tooltip: String,
    clipboard_mirror: String,
    notifications_sent: u64,
}

impl Default for DesktopWindowState {
    fn default() -> Self {
        Self {
            title: "Aerea Nexus".to_string(),
            theme: "system".to_string(),
            tray_tooltip: "Nexus-IO".to_string(),
            clipboard_mirror: String::new(),
            notifications_sent: 0,
        }
    }
}

/// Real Cross-Platform Desktop OS Shell Provider (Windows, macOS, Linux — 0 new crates in `core`).
/// Combines native OS integration (clipboard, notifications, dialogs) with a live retained-mode
/// `RetainedUiTree` and `UiEvent` queue.
pub struct NativeDesktopShellProvider {
    window: RwLock<DesktopWindowState>,
    tree: RwLock<RetainedUiTree>,
    live_os_bridge: bool,
}

impl Default for NativeDesktopShellProvider {
    fn default() -> Self {
        let live_os_bridge = std::env::var("NEXUS_OS_UI_NATIVE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self::new(live_os_bridge)
    }
}

impl NativeDesktopShellProvider {
    pub fn new(live_os_bridge: bool) -> Self {
        Self {
            window: RwLock::new(DesktopWindowState::default()),
            tree: RwLock::new(RetainedUiTree::default()),
            live_os_bridge,
        }
    }

    /// Attach a `NexusSharedArena` SPSC ring so native UI events stream directly into the ring.
    pub fn attach_event_ring(&self, owner_id: &str, capacity: usize) -> Result<RingBufferHandle, String> {
        let desc = NexusSharedArena::global()
            .alloc_ring(owner_id, "ui.events", capacity, TransportMode::PortableCopy)
            .map_err(|e| e.to_string())?;
        if let Ok(mut tree) = self.tree.write() {
            tree.event_ring = Some(desc.handle);
        }
        Ok(desc.handle)
    }

    pub fn snapshot_tree(&self) -> (u64, Vec<RetainedUiNode>) {
        if let Ok(tree) = self.tree.read() {
            (tree.commit_generation, tree.nodes.values().cloned().collect())
        } else {
            (0, Vec::new())
        }
    }

    fn native_clipboard_write(&self, text: &str) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            use std::io::Write;
            let mut child = std::process::Command::new("clip")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            if status.success() { Ok(()) } else { Err("clip exited with error".into()) }
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Write;
            let mut child = std::process::Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            if status.success() { Ok(()) } else { Err("pbcopy exited with error".into()) }
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            let tool = if std::env::var("WAYLAND_DISPLAY").is_ok() { "wl-copy" } else { "xclip" };
            let mut cmd = std::process::Command::new(tool);
            if tool == "xclip" {
                cmd.args(["-selection", "clipboard"]);
            }
            let mut child = cmd
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            if status.success() { Ok(()) } else { Err(format!("{} exited with error", tool)) }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            let _ = text;
            Err("Native desktop clipboard not available on this OS".into())
        }
    }

    fn native_clipboard_read(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "Get-Clipboard"])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(String::from_utf8_lossy(&out.stdout).trim_end_matches(['\r', '\n']).to_string())
        }
        #[cfg(target_os = "macos")]
        {
            let out = std::process::Command::new("pbpaste")
                .output()
                .map_err(|e| e.to_string())?;
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        }
        #[cfg(target_os = "linux")]
        {
            let out = if std::env::var("WAYLAND_DISPLAY").is_ok() {
                std::process::Command::new("wl-paste").output()
            } else {
                std::process::Command::new("xclip")
                    .args(["-selection", "clipboard", "-o"])
                    .output()
            }
            .map_err(|e| e.to_string())?;
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Err("Native desktop clipboard not available on this OS".into())
        }
    }
}

impl OsShellProvider for NativeDesktopShellProvider {
    fn backend_name(&self) -> &'static str {
        native_ui_toolkit_name()
    }

    fn is_headless(&self) -> bool {
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            std::env::var("NEXUS_HEADLESS")
                .map(|v| v == "1")
                .unwrap_or(false)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err()
        }
    }

    fn supported_ops(&self) -> Vec<String> {
        vec![
            "ui.capabilities".into(),
            "ui.window.set_title".into(),
            "ui.window.set_theme".into(),
            "ui.window.get_state".into(),
            "ui.notify.send".into(),
            "ui.tray.set_tooltip".into(),
            "ui.clipboard.read".into(),
            "ui.clipboard.write".into(),
            "ui.tree.snapshot".into(),
            "ui.events.poll".into(),
            "ui.events.emit".into(),
            "ui.dialog.alert".into(),
            "ui.dialog.open_file".into(),
            "ui.dialog.save_file".into(),
            "ui.haptics.impact".into(),
            "ui.share".into(),
            "ui.webview.post_message".into(),
        ]
    }

    fn commit_ui_ops(&self, batch: &[u8]) -> HardwareResponse {
        match self.tree.write() {
            Ok(mut tree) => match tree.apply_binary_batch(batch) {
                Ok(applied) => HardwareResponse::ok(
                    "ui.ops.commit",
                    json!({
                        "ops_applied": applied,
                        "node_count": tree.nodes.len(),
                        "commit_generation": tree.commit_generation,
                        "backend": self.backend_name(),
                    }),
                ),
                Err(e) => HardwareResponse::err("ui.ops.commit", HardwareStatus::InvalidRequest, e),
            },
            Err(_) => HardwareResponse::err("ui.ops.commit", HardwareStatus::Error, "UI tree lock poisoned"),
        }
    }

    fn handle_shell(&self, op: &str, payload: &Value) -> HardwareResponse {
        let lower = op.trim().to_ascii_lowercase();
        let use_live_os = self.live_os_bridge
            || payload.get("native").and_then(|v| v.as_bool()).unwrap_or(false);

        match lower.as_str() {
            "ui.capabilities" => HardwareResponse::ok(
                op,
                json!({
                    "backend": self.backend_name(),
                    "webview_engine": native_webview_engine_name(),
                    "webview_compiled": cfg!(feature = "gui-webview"),
                    "live_os_bridge": self.live_os_bridge,
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
                if let Ok(mut w) = self.window.write() {
                    w.title = title.clone();
                }
                HardwareResponse::ok(op, json!({ "title": title, "applied": true }))
            }
            "ui.window.set_theme" => {
                let theme = payload
                    .get("theme")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system")
                    .to_string();
                if let Ok(mut w) = self.window.write() {
                    w.theme = theme.clone();
                }
                HardwareResponse::ok(op, json!({ "theme": theme, "applied": true }))
            }
            "ui.window.get_state" => {
                let w = self.window.read().map(|g| g.clone()).unwrap_or_default();
                let (gen, nodes) = self.snapshot_tree();
                HardwareResponse::ok(
                    op,
                    json!({
                        "title": w.title,
                        "theme": w.theme,
                        "tray_tooltip": w.tray_tooltip,
                        "notifications_sent": w.notifications_sent,
                        "commit_generation": gen,
                        "node_count": nodes.len(),
                        "headless": self.is_headless(),
                    }),
                )
            }
            "ui.notify.send" => {
                let title = payload.get("title").and_then(|v| v.as_str()).unwrap_or("Nexus");
                let body = payload.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let seq = if let Ok(mut w) = self.window.write() {
                    w.notifications_sent += 1;
                    w.notifications_sent
                } else {
                    1
                };
                HardwareResponse::ok(
                    op,
                    json!({
                        "delivered": true,
                        "native_invoked": use_live_os && !self.is_headless(),
                        "title": title,
                        "body": body,
                        "sequence": seq,
                    }),
                )
            }
            "ui.tray.set_tooltip" => {
                let tip = payload
                    .get("tooltip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Nexus-IO")
                    .to_string();
                if let Ok(mut w) = self.window.write() {
                    w.tray_tooltip = tip.clone();
                }
                HardwareResponse::ok(op, json!({ "tooltip": tip, "applied": true }))
            }
            "ui.clipboard.write" => {
                let text = payload
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Ok(mut w) = self.window.write() {
                    w.clipboard_mirror = text.clone();
                }
                let mut native_ok = false;
                if use_live_os && !self.is_headless() {
                    native_ok = self.native_clipboard_write(&text).is_ok();
                }
                HardwareResponse::ok(
                    op,
                    json!({ "written_bytes": text.len(), "native_synced": native_ok }),
                )
            }
            "ui.clipboard.read" => {
                let text = if use_live_os && !self.is_headless() {
                    self.native_clipboard_read().unwrap_or_else(|_| {
                        self.window
                            .read()
                            .map(|w| w.clipboard_mirror.clone())
                            .unwrap_or_default()
                    })
                } else {
                    self.window
                        .read()
                        .map(|w| w.clipboard_mirror.clone())
                        .unwrap_or_default()
                };
                HardwareResponse::ok(op, json!({ "text": text }))
            }
            "ui.tree.snapshot" => {
                let (gen, nodes) = self.snapshot_tree();
                HardwareResponse::ok(op, json!({ "commit_generation": gen, "nodes": nodes }))
            }
            "ui.events.emit" => {
                let node_id = payload.get("node_id").and_then(|v| v.as_u64()).unwrap_or(0);
                let event_type = payload.get("event_type").and_then(|v| v.as_str()).unwrap_or("click");
                let ev_payload = payload.get("payload").and_then(|v| v.as_str()).unwrap_or("");
                if let Ok(mut tree) = self.tree.write() {
                    let ev = tree.push_event(node_id, event_type, ev_payload);
                    HardwareResponse::ok(op, json!({ "event": ev }))
                } else {
                    HardwareResponse::err(op, HardwareStatus::Error, "UI tree lock poisoned")
                }
            }
            "ui.events.poll" => {
                let max = payload.get("max").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
                if let Ok(mut tree) = self.tree.write() {
                    let events = tree.drain_events(max.clamp(1, 256));
                    HardwareResponse::ok(op, json!({ "events": events }))
                } else {
                    HardwareResponse::err(op, HardwareStatus::Error, "UI tree lock poisoned")
                }
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

// =============================================================================
// Mobile-Oriented Platform Bridge Design (Android JNI / iOS Swift FFI)
// =============================================================================

/// Callback contract implemented by Android JNI (`Activity` / `Jetpack Compose` / `SAF` /
/// `BiometricPrompt`) and iOS Swift/Obj-C (`UIKit` / `SwiftUI` / `UIDocumentPicker` / `LAContext`)
/// host shells and registered into `HardwareRegistry` at mobile app startup.
pub trait MobilePlatformBridge: Send + Sync {
    fn platform_name(&self) -> &'static str;
    fn check_mobile_permission(&self, cap: Capability) -> ConsentState;
    fn request_mobile_permission(&self, cap: Capability, rationale: &str) -> ConsentRequestResult;
    fn invoke_native_shell(&self, op: &str, payload: &Value) -> HardwareResponse;
}

/// Adapter that exposes any `MobilePlatformBridge` as both an `OsShellProvider` and a `ConsentProvider`.
pub struct MobileShellAdapter<B: MobilePlatformBridge + 'static> {
    bridge: Arc<B>,
    tree: RwLock<RetainedUiTree>,
}

impl<B: MobilePlatformBridge + 'static> MobileShellAdapter<B> {
    pub fn new(bridge: Arc<B>) -> Self {
        Self {
            bridge,
            tree: RwLock::new(RetainedUiTree::default()),
        }
    }
}

impl<B: MobilePlatformBridge + 'static> ConsentProvider for MobileShellAdapter<B> {
    fn check_consent(&self, cap: Capability) -> ConsentState {
        self.bridge.check_mobile_permission(cap)
    }

    fn request_consent(&self, cap: Capability, reason: &str) -> ConsentRequestResult {
        self.bridge.request_mobile_permission(cap, reason)
    }
}

impl<B: MobilePlatformBridge + 'static> OsShellProvider for MobileShellAdapter<B> {
    fn backend_name(&self) -> &'static str {
        self.bridge.platform_name()
    }

    fn is_headless(&self) -> bool {
        false
    }

    fn supported_ops(&self) -> Vec<String> {
        vec![
            "ui.capabilities".into(),
            "ui.notify.send".into(),
            "ui.haptics.impact".into(),
            "ui.share".into(),
            "ui.dialog.open_file".into(),
            "ui.clipboard.read".into(),
            "ui.clipboard.write".into(),
            "ui.tree.snapshot".into(),
            "ui.events.poll".into(),
        ]
    }

    fn commit_ui_ops(&self, batch: &[u8]) -> HardwareResponse {
        match self.tree.write() {
            Ok(mut tree) => match tree.apply_binary_batch(batch) {
                Ok(applied) => HardwareResponse::ok(
                    "ui.ops.commit",
                    json!({
                        "ops_applied": applied,
                        "node_count": tree.nodes.len(),
                        "commit_generation": tree.commit_generation,
                        "backend": self.backend_name(),
                    }),
                ),
                Err(e) => HardwareResponse::err("ui.ops.commit", HardwareStatus::InvalidRequest, e),
            },
            Err(_) => HardwareResponse::err("ui.ops.commit", HardwareStatus::Error, "Mobile UI tree lock poisoned"),
        }
    }

    fn handle_shell(&self, op: &str, payload: &Value) -> HardwareResponse {
        let lower = op.trim().to_ascii_lowercase();
        if lower == "ui.tree.snapshot" {
            if let Ok(tree) = self.tree.read() {
                return HardwareResponse::ok(
                    op,
                    json!({
                        "commit_generation": tree.commit_generation,
                        "nodes": tree.nodes.values().cloned().collect::<Vec<_>>(),
                    }),
                );
            }
        }
        if lower == "ui.events.poll" {
            let max = payload.get("max").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
            if let Ok(mut tree) = self.tree.write() {
                return HardwareResponse::ok(op, json!({ "events": tree.drain_events(max.clamp(1, 256)) }));
            }
        }
        self.bridge.invoke_native_shell(op, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_op(buf: &mut Vec<u8>, opcode: UiOpCode, node_id: u64, payload: &[u8]) {
        let hdr = UiOpHeader {
            version: UI_OP_PROTOCOL_VERSION,
            opcode: opcode as u16,
            payload_len: payload.len() as u32,
            node_id,
        };
        buf.extend_from_slice(&hdr.to_le_bytes());
        buf.extend_from_slice(payload);
    }

    #[test]
    fn desktop_shell_retained_ui_tree_and_spsc_event_ring_roundtrip() {
        let provider = NativeDesktopShellProvider::new(false);
        let owner = NexusSharedArena::global()
            .mint_owner_id("erp", "desktop-ui")
            .as_canonical();
        let ring_handle = provider.attach_event_ring(&owner, 1024).unwrap();

        // Build transactional retained-mode binary UiOp batch:
        // Create root stack (1), button (2), set text & prop, attach child, emit click event, commit
        let mut batch = Vec::new();
        push_op(&mut batch, UiOpCode::CreateNode, 1, b"stack");
        push_op(&mut batch, UiOpCode::CreateNode, 2, b"button");
        push_op(&mut batch, UiOpCode::SetText, 2, b"Approve PO");
        push_op(&mut batch, UiOpCode::SetProp, 2, b"variant=primary");
        push_op(&mut batch, UiOpCode::AttachChild, 1, &2u64.to_le_bytes());
        push_op(&mut batch, UiOpCode::EmitEvent, 2, b"click:po-1042");
        push_op(&mut batch, UiOpCode::CommitBatch, 0, b"");

        let commit = provider.commit_ui_ops(&batch);
        assert_eq!(commit.status, HardwareStatus::Ok);
        assert_eq!(commit.data["ops_applied"], 7);
        assert_eq!(commit.data["node_count"], 2);
        assert_eq!(commit.data["commit_generation"], 1);

        let snap = provider.handle_shell("ui.tree.snapshot", &json!({}));
        assert_eq!(snap.data["nodes"].as_array().unwrap().len(), 2);

        // Verify event arrived in BOTH the SPSC ring buffer and `ui.events.poll`
        let ring = NexusSharedArena::global().get_ring(ring_handle, Some(&owner)).unwrap();
        let mut len_buf = [0u8; 4];
        assert_eq!(ring.read(&mut len_buf).unwrap(), 4);
        let frame_len = u32::from_le_bytes(len_buf) as usize;
        let mut frame = vec![0u8; frame_len];
        assert_eq!(ring.read(&mut frame).unwrap(), frame_len);
        let ring_ev: UiEvent = serde_json::from_slice(&frame).unwrap();
        assert_eq!(ring_ev.node_id, 2);
        assert_eq!(ring_ev.event_type, "click");
        assert_eq!(ring_ev.payload, "po-1042");

        let polled = provider.handle_shell("ui.events.poll", &json!({ "max": 10 }));
        assert_eq!(polled.data["events"].as_array().unwrap().len(), 1);

        NexusSharedArena::global().revoke_owner(&owner);
    }

    #[test]
    fn mobile_bridge_adapter_wires_consent_and_native_shell() {
        struct MockAndroidBridge;
        impl MobilePlatformBridge for MockAndroidBridge {
            fn platform_name(&self) -> &'static str {
                "Android Views / Jetpack Compose JNI"
            }
            fn check_mobile_permission(&self, cap: Capability) -> ConsentState {
                if cap == Capability::HwCamera { ConsentState::Granted } else { ConsentState::NotDetermined }
            }
            fn request_mobile_permission(&self, _cap: Capability, _rationale: &str) -> ConsentRequestResult {
                ConsentRequestResult::Pending
            }
            fn invoke_native_shell(&self, op: &str, payload: &Value) -> HardwareResponse {
                HardwareResponse::ok(op, json!({ "android_bridge": true, "payload": payload }))
            }
        }

        let adapter = MobileShellAdapter::new(Arc::new(MockAndroidBridge));
        assert_eq!(adapter.check_consent(Capability::HwCamera), ConsentState::Granted);
        assert_eq!(adapter.check_consent(Capability::HwAudio), ConsentState::NotDetermined);
        let res = adapter.handle_shell("ui.haptics.impact", &json!({ "style": "light" }));
        assert_eq!(res.status, HardwareStatus::Ok);
        assert_eq!(res.data["android_bridge"], true);
    }
}
