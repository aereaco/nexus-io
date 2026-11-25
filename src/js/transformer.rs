use anyhow::Result;

/// TypeScript/JavaScript source passthrough for the Wasm-first microkernel.
/// TypeScript transpilation is performed by guest Wasm toolchains (e.g. OXC/SWC Wasm modules)
/// rather than linking native compiler crates into the host binary.
pub fn transform_ts_to_js(source: &str) -> Result<String> {
    if is_likely_ts(source) {
        anyhow::bail!(
            "TypeScript must be pre-transpiled or compiled via a Wasm transpiler module in Nexus-IO"
        );
    }
    Ok(source.to_string())
}

/// A heuristic to check if code might be TypeScript.
pub fn is_likely_ts(code: &str) -> bool {
    code.contains(": ")
        || (code.contains('<') && code.contains('>'))
        || code.contains("interface ")
        || code.contains("type ")
        || code.contains("enum ")
}
