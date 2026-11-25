//! Device-native modern web rendering engine integration for Nexus-IO (`--features gui`).
//!
//! Zero Electron, zero bundled Chromium, zero third-party browser shells:
//! - **Windows:** OS-provided `WebView2` (Edge Chromium engine)
//! - **macOS:** OS-provided `WKWebView` (Apple WebKit)
//! - **Linux:** OS-provided `WebKitGTK`
//! - **Android:** OS-provided `Android System WebView` (`android.webkit.WebView`)
//! - **iOS:** OS-provided `WKWebView` (Apple WebKit, `W^X` compliant)

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Device-native modern web rendering engine bound to the host operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeWebViewEngine {
    /// Windows OS WebView2 (Microsoft Edge Chromium runtime)
    WebView2,
    /// Apple macOS / iOS WKWebView (WebKit)
    WKWebView,
    /// Linux WebKitGTK
    WebKitGtk,
    /// Android System WebView (android.webkit.WebView)
    AndroidWebView,
    /// Fallback for exotic / headless-only targets
    Unsupported,
}

impl NativeWebViewEngine {
    /// Returns the device-native web rendering engine for the current compilation target.
    pub const fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WebView2
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            Self::WKWebView
        }
        #[cfg(target_os = "linux")]
        {
            Self::WebKitGtk
        }
        #[cfg(target_os = "android")]
        {
            Self::AndroidWebView
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        )))]
        {
            Self::Unsupported
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WebView2 => "WebView2 (Windows Native)",
            Self::WKWebView => "WKWebView (Apple Native)",
            Self::WebKitGtk => "WebKitGTK (Linux Native)",
            Self::AndroidWebView => "Android System WebView (Android Native)",
            Self::Unsupported => "Unsupported (Headless Only)",
        }
    }
}

/// Configuration for launching a device-native GUI window pointing at a Nexus-IO gateway or cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeWindowConfig {
    pub title: String,
    pub url: String,
    pub width: f64,
    pub height: f64,
    pub resizable: bool,
    pub decorations: bool,
    pub transparent: bool,
    pub devtools: bool,
}

impl Default for NativeWindowConfig {
    fn default() -> Self {
        Self {
            title: "Nexus-IO".to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            width: 1280.0,
            height: 800.0,
            resizable: true,
            decorations: true,
            transparent: false,
            devtools: cfg!(debug_assertions),
        }
    }
}

/// Diagnostic descriptor exposed by `CapabilityRegistry` and mobile host bridges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeGuiDescriptor {
    pub compiled: bool,
    pub target_os: &'static str,
    pub engine: NativeWebViewEngine,
    pub engine_label: &'static str,
}

impl NativeGuiDescriptor {
    pub const fn current() -> Self {
        let engine = NativeWebViewEngine::current();
        Self {
            compiled: cfg!(feature = "gui-webview"),
            target_os: std::env::consts::OS,
            engine,
            engine_label: engine.as_str(),
        }
    }
}

/// Launch a device-native OS WebView window (`WebView2` / `WKWebView` / `WebKitGTK`).
///
/// Must be called on the main OS thread on desktop platforms.
#[cfg(all(feature = "gui-webview", not(any(target_os = "android", target_os = "ios"))))]
pub fn launch_native_window(config: NativeWindowConfig) -> Result<()> {
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title(&config.title)
        .with_inner_size(LogicalSize::new(config.width, config.height))
        .with_resizable(config.resizable)
        .with_decorations(config.decorations)
        .with_transparent(config.transparent)
        .build(&event_loop)
        .map_err(|e| anyhow::anyhow!("Failed to create native OS window: {}", e))?;

    let _webview = WebViewBuilder::new()
        .with_url(&config.url)
        .with_devtools(config.devtools)
        .with_transparent(config.transparent)
        .build(&window)
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to initialize native {} webview: {}",
                NativeWebViewEngine::current().as_str(),
                e
            )
        })?;

    println!(
        "🖥️  Native GUI launched via {} -> {}",
        NativeWebViewEngine::current().as_str(),
        config.url
    );

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

/// On Android and iOS, the mobile OS Activity / UIViewController owns the main UI thread
/// and attaches its native `WebView` / `WKWebView` to `config.url`.
#[cfg(all(feature = "gui-webview", any(target_os = "android", target_os = "ios")))]
pub fn launch_native_window(config: NativeWindowConfig) -> Result<()> {
    println!(
        "📱 Native mobile WebView host bridge ready ({}) -> {}",
        NativeWebViewEngine::current().as_str(),
        config.url
    );
    Ok(())
}

/// Headless build stub when `--features gui` is not enabled.
#[cfg(not(feature = "gui-webview"))]
pub fn launch_native_window(_config: NativeWindowConfig) -> Result<()> {
    anyhow::bail!(
        "Native GUI is not compiled into this binary. Rebuild with `--features gui` to enable {}.",
        NativeWebViewEngine::current().as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_device_native_webview_engine() {
        let desc = NativeGuiDescriptor::current();
        assert_eq!(desc.target_os, std::env::consts::OS);
        #[cfg(target_os = "windows")]
        assert_eq!(desc.engine, NativeWebViewEngine::WebView2);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        assert_eq!(desc.engine, NativeWebViewEngine::WKWebView);
        #[cfg(target_os = "linux")]
        assert_eq!(desc.engine, NativeWebViewEngine::WebKitGtk);
        #[cfg(target_os = "android")]
        assert_eq!(desc.engine, NativeWebViewEngine::AndroidWebView);
    }

    #[test]
    fn default_window_config_targets_local_gateway() {
        let cfg = NativeWindowConfig::default();
        assert_eq!(cfg.title, "Nexus-IO");
        assert_eq!(cfg.url, "http://127.0.0.1:8080");
        assert!(cfg.width >= 800.0 && cfg.height >= 600.0);
    }
}
