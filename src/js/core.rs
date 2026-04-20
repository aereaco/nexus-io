/// Modern QuickJS-NG integration with Nushell alignment
/// Provides JavaScript/TypeScript execution with SurrealDB and Deno/Node compatibility

use quickjs_rusty::{Context, OwnedJsValue};
use nu_protocol::{Value as NuValue, Span, ShellError, Record};
use nu_protocol::engine::{EngineState, Stack, StateWorkingSet};
use nu_protocol::debugger::DebugContext;
use std::ffi::c_void;

#[derive(Clone, Copy, Debug)]
struct NoDebug;
impl DebugContext for NoDebug {}

/// Bridge structure to pass Nushell state to QuickJS callbacks
pub struct NuBridge<'a> {
    pub engine_state: *mut EngineState, 
    pub stack: &'a mut Stack,
    pub base_path: Option<String>,
}

/// Create a QuickJS context with Nushell-aligned configuration
pub fn create_context(bridge: &mut NuBridge) -> Result<Context, ShellError> {
    let context = Context::builder()
        .console(|level, args: Vec<OwnedJsValue>| {
            let items: Vec<String> = args.iter()
                .map(|v| format_js_value(v))
                .collect();
            println!("[JS {:?}] {}", level, items.join(" "));
        })
        .build()
        .map_err(|e| ShellError::GenericError {
            error: "QuickJS Context Creation Failed".into(),
            msg: format!("{:?}", e),
            span: None,
            help: None,
            inner: vec![],
        })?;

    // Add Deno/Node compatibility globals
    inject_compat_globals(&context)?;

    // Integrate native OXC parser bridge
    inject_oxc_parser(&context)?;

    // Set module loader for Porffor imports
    context.set_module_loader(
        Box::new(|module_name, _opaque| {
             // Handle node:* virtual modules
             if module_name.starts_with("node:") {
                 return match module_name {
                     "node:fs" => Ok(r#"
                        export const readFileSync = (path) => globalThis.__nexus_fs_read_sync(path);
                        export const writeFileSync = (path, content) => {}; // No-op for safety
                        export const promises = { readFile: async (path) => globalThis.__nexus_fs_read_sync(path) };
                        export default { readFileSync, writeFileSync, promises };
                     "#.to_string()),
                     "node:path" => Ok(r#"
                        export const join = (...args) => args.join('/');
                        export const dirname = (path) => path.split('/').slice(0, -1).join('/') || '.';
                        export const basename = (path) => path.split('/').pop();
                        export default { join, dirname, basename };
                     "#.to_string()),
                     "node:process" => Ok("export default globalThis.process;".to_string()),
                     "node:module" => Ok("export const createRequire = () => (id) => {}; export default { createRequire };".to_string()),
                     "node:url" => Ok("export const pathToFileURL = (p) => p; export default { pathToFileURL };".to_string()),
                     _ => Ok("export default {};".to_string()),
                 };
             }

             // Basic reading for local files
             std::fs::read_to_string(module_name)
                .map_err(|e| anyhow::anyhow!("Failed to load module '{}': {}", module_name, e))
        }),
        Some(Box::new(|base_name, module_name, opaque| {
            let bridge = unsafe { &mut *(opaque as *mut NuBridge) };
            resolve_module_path(base_name, module_name, bridge)
                 .map(|p| p.to_string_lossy().to_string())
                 .map_err(|e| anyhow::anyhow!("{}", e))
        })),
        bridge as *mut NuBridge as *mut c_void,
    );
    
    Ok(context)
}

/// Helper to evaluate Nushell code from the bridge
fn nu_eval(bridge: &mut NuBridge, source: &str) -> Result<NuValue, ShellError> {
    let engine_state = unsafe { &*bridge.engine_state };
    let mut working_set = StateWorkingSet::new(engine_state);
    let block = nu_parser::parse(&mut working_set, None, source.as_bytes(), false);
    
    if let Some(err) = working_set.parse_errors.first() {
        return Err(ShellError::GenericError {
            error: "Nu Parse Error".into(),
            msg: format!("{:?}", err),
            span: None,
            help: None,
            inner: vec![],
        });
    }

    // Use eval_block without turbofish and let it infer DebugContext
    // In many cases, adding a simple closure or similar works
    let pipeline = nu_engine::eval_block::<NoDebug>(
        engine_state,
        bridge.stack,
        &block,
        nu_protocol::PipelineData::empty()
    ).map_err(|e| {
        let err_msg = format!("Nushell Execution Error for '{}': {:?}", source, e);
        ShellError::GenericError {
            error: "Nushell Execution Error".into(),
            msg: err_msg,
            span: None,
            help: None,
            inner: vec![],
        }
    })?;

    // Extract value from pipeline
    let body = pipeline.body;
    match body {
        nu_protocol::PipelineData::Value(v, _) => Ok(v),
        _ => Ok(body.into_value(Span::unknown())?),
    }
}

/// Helper to resolve module paths (Node.js style-ish)
fn resolve_module_path(base_name: &str, module_name: &str, bridge: &mut NuBridge) -> std::io::Result<std::path::PathBuf> {
    // If base_name is empty or generic, use the bridge's base_path
    let effective_base = if base_name.is_empty() || base_name == "module.js" {
        bridge.base_path.as_deref().unwrap_or(".")
    } else {
        base_name
    };

    // 0. Handle remote and npm specifiers
    if module_name.starts_with("http:") || module_name.starts_with("https:") {
        return Ok(std::path::PathBuf::from(module_name));
    }

    if module_name.starts_with("npm:") {
        let package = &module_name[4..];
        return resolve_npm_specifier(package, bridge);
    }

    // Origin-aware resolution for remote bases
    if effective_base.starts_with("http:") || effective_base.starts_with("https:") {
        if module_name.starts_with('/') {
            // Absolute path from origin
            let proto_end = effective_base.find("://").map(|p| p + 3).unwrap_or(0);
            if let Some(pos) = effective_base[proto_end..].find('/') {
                let origin = &effective_base[..proto_end + pos];
                return Ok(std::path::PathBuf::from(format!("{}{}", origin, module_name)));
            } else {
                return Ok(std::path::PathBuf::from(format!("{}{}", effective_base, module_name)));
            }
        } else if module_name.starts_with("./") || module_name.starts_with("../") {
            // Relative path from base directory
            let mut base_url = effective_base.to_string();
            if let Some(pos) = base_url.rfind('/') {
                let proto_end = base_url.find("://").map(|p| p + 3).unwrap_or(0);
                if pos >= proto_end {
                    base_url.truncate(pos + 1);
                } else {
                    base_url.push('/');
                }
            } else {
                base_url.push('/');
            }
            let clean_mod = if module_name.starts_with("./") { &module_name[2..] } else { module_name };
            return Ok(std::path::PathBuf::from(format!("{}{}", base_url, clean_mod)));
        }
    }

    let base_path = std::path::Path::new(effective_base);
    
    // Handle virtual "module.js" from eval_module or non-existent files with extensions
    let base_dir = if effective_base == "module.js" || (base_path.extension().is_some() && !effective_base.starts_with("http")) {
        base_path.parent().unwrap_or_else(|| std::path::Path::new("."))
    } else {
        base_path
    };

    // 1. Relative paths
    if module_name.starts_with("./") || module_name.starts_with("../") || module_name.starts_with("/") {
        let candidate = base_dir.join(module_name);
        if candidate.exists() && candidate.is_file() {
             return std::fs::canonicalize(&candidate);
        }
        // Try extensions
        for ext in &[".js", ".mjs", ".ts"] {
             let with_ext = candidate.with_extension(ext.trim_start_matches('.'));
             if with_ext.exists() {
                 return std::fs::canonicalize(&with_ext);
             }
        }
        // Try index.js
        let index = candidate.join("index.js");
        if index.exists() {
             return std::fs::canonicalize(&index);
        }
        return Ok(candidate); // Return as-is to let it fail or be handled by loader
    }

    // 2. Bare specifiers (node_modules)
    // Simple look in ./node_modules
    let node_modules = std::env::current_dir()?.join("node_modules");
    let target_dir = node_modules.join(module_name);
    
    if target_dir.exists() && target_dir.is_dir() {
        let pkg_json_path = target_dir.join("package.json");
        if pkg_json_path.exists() {
             let content = std::fs::read_to_string(&pkg_json_path)?;
             if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                  if let Some(m) = json.get("module").and_then(|v| v.as_str()) {
                      let p = target_dir.join(m);
                      if p.exists() {
                          return std::fs::canonicalize(&p);
                      }
                  }
                  if let Some(m) = json.get("main").and_then(|v| v.as_str()) {
                      let p = target_dir.join(m);
                      if p.exists() {
                          return std::fs::canonicalize(&p);
                      }
                  }
              }
        }
        let index = target_dir.join("index.js");
        if index.exists() {
            return std::fs::canonicalize(&index);
        }
    }
    
    // Fallback: return as absolute path if possible or keep as is
    Ok(std::path::PathBuf::from(module_name))
}

/// Specialized resolver for npm: specifiers using Nushell-native cache
fn resolve_npm_specifier(package: &str, bridge: &mut NuBridge) -> std::io::Result<std::path::PathBuf> {
    // Determine cache directory
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        
    let cache_root = std::path::Path::new(&home).join(".nexus").join("cache");
    let package_dir = cache_root.join(package);

    if !package_dir.exists() || std::fs::read_dir(&package_dir).map(|mut d| d.next().is_none()).unwrap_or(true) {
        fetch_npm_package(package, &package_dir, bridge)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    }

    // Reuse node_modules resolution logic within the package directory
    resolve_in_package_dir(&package_dir, package)
}

fn fetch_npm_package(package: &str, target_dir: &std::path::Path, bridge: &mut NuBridge) -> Result<(), ShellError> {
    // 1. Get tarball URL from registry
    let registry_url = format!("https://registry.npmjs.org/{}/latest", package);
    let get_url_cmd = format!("http get {} | get dist.tarball", registry_url);
    let val = nu_eval(bridge, &get_url_cmd)?;
    let tarball_url = val.as_str()?;

    // 2. Download to temp
    let temp_tarball = target_dir.with_extension("tar.gz");
    std::fs::create_dir_all(target_dir.parent().unwrap_or(std::path::Path::new("."))).map_err(|e| ShellError::GenericError {
        error: "Cache Directory Creation Failed".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;

    let download_cmd = format!("http get --raw \"{}\" | save --force \"{}\"", tarball_url, temp_tarball.display());
    nu_eval(bridge, &download_cmd)?;

    // 3. Extract using Nushell's external tar command
    std::fs::create_dir_all(target_dir).map_err(|e| ShellError::GenericError {
        error: "Package Directory Creation Failed".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;

    // Npm tarballs usually have a 'package' root folder, we want to strip it
    let extract_cmd = format!("^tar -xzf \"{}\" -C \"{}\" --strip-components=1", temp_tarball.display(), target_dir.display());
    nu_eval(bridge, &extract_cmd)?;

    // 4. Cleanup temp tarball
    let _ = std::fs::remove_file(temp_tarball);

    Ok(())
}

fn resolve_in_package_dir(package_dir: &std::path::Path, _module_name: &str) -> std::io::Result<std::path::PathBuf> {
    // Simplified version of the bare specifier logic
    if package_dir.exists() && package_dir.is_dir() {
        let pkg_json_path = package_dir.join("package.json");
        if pkg_json_path.exists() {
             let content = std::fs::read_to_string(&pkg_json_path)?;
             if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                 if let Some(m) = json.get("module").and_then(|v| v.as_str()) {
                     let p = package_dir.join(m);
                     if p.exists() {
                         return std::fs::canonicalize(&p);
                     }
                 }
                 if let Some(m) = json.get("main").and_then(|v| v.as_str()) {
                     let p = package_dir.join(m);
                     if p.exists() {
                         return std::fs::canonicalize(&p);
                     }
                 }
             }
        }
        let index = package_dir.join("index.js");
        if index.exists() {
            return std::fs::canonicalize(&index);
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Could not resolve npm package entry point"))
}

/// Inject Deno/Node compatibility globals
fn inject_compat_globals(context: &Context) -> Result<(), ShellError> {
    context.eval(r#"
        // Process global
        globalThis.process = { 
            env: {},
            argv: [],
            cwd: () => '/',
            platform: 'linux',
            version: 'v18.0.0', // Faking Node version for tool compatibility
            nextTick: (fn) => setTimeout(fn, 0),
            stdout: {
                isTTY: false,
                write: (str) => console.log(str)
            }
        };
        
        // Timer polyfills
        if (!globalThis.setInterval) {
            globalThis.setInterval = (fn, ms) => setTimeout(fn, ms);
            globalThis.clearInterval = () => {};
        }

        // Buffer global
        globalThis.Buffer = {
            from: (data) => new Uint8Array(data),
            alloc: (size) => new Uint8Array(size),
            isBuffer: (obj) => obj instanceof Uint8Array
        };

        // Performance polyfill
        if (!globalThis.performance) {
            globalThis.performance = {
                now: () => Date.now()
            };
        }
        
        // Console fixes for Porffor compatibility
        if (globalThis.console) {
            ['log', 'info', 'warn', 'error', 'debug'].forEach(m => {
                const original = globalThis.console[m];
                if (original && typeof original === 'function') {
                    try {
                        Object.defineProperty(original, 'name', { 
                            value: m, 
                            configurable: true 
                        });
                    } catch (e) {
                        // Some built-ins might not allow redefinition
                    }
                }
            });
        }

        // Deno compatibility stub
        globalThis.Deno = {
            version: { deno: 'nexus-compat' },
            pid: process.pid,
            noColor: false,
            args: []
        };

        // Bun compatibility stub
        globalThis.Bun = {
            version: 'nexus-compat',
            env: process.env,
            // Mock common Bun APIs as needed
            file: (path) => ({ text: () => 'Bun stub' }) 
        };

        // Node.js fs mock for Porffor's internal logic
        globalThis.__nexus_fs_read_sync = (path) => {
            // This will be called by our virtual node:fs
            const content = __nexus_native_read_file(path);
            if (content === null) throw new Error(`File not found: ${path}`);
            return content;
        };
    "#, false)
    .map_err(|e| ShellError::GenericError {
        error: "Failed to inject compatibility globals".into(),
        msg: format!("{:?}", e),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    Ok(())
}

/// Inject Native OXC Parser Bridge
fn inject_oxc_parser(context: &Context) -> Result<(), ShellError> {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    use libquickjs_ng_sys as q;

    // Define custom callback for direct AST projection
    fn nexus_js_parse_callback(ctx: *mut q::JSContext, args: &[q::JSValue]) -> anyhow::Result<Option<q::JSValue>> {
        use quickjs_rusty::OwnedJsValue;
        use quickjs_rusty::serde::to_js;

        if args.is_empty() {
            return Err(anyhow::anyhow!("Missing code argument"));
        }

        let code_val = OwnedJsValue::own(ctx, &args[0]);
        let code = code_val.to_string().map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let allocator = Allocator::default();
        let source_type = SourceType::from_path("input.js").unwrap();
        let parser = Parser::new(&allocator, &code, source_type);
        let ret = parser.parse();

        if !ret.errors.is_empty() {
            return Err(anyhow::anyhow!(ret.errors[0].message.to_string()));
        }

        // Project AST directly to JS objects via Serde
        let js_ast = to_js(ctx, &ret.program).map_err(|e| anyhow::anyhow!("AST Projection Error: {}", e))?;
        
        unsafe { Ok(Some(js_ast.extract())) }
    }

    let parse_func = context.create_custom_callback(nexus_js_parse_callback)
        .map_err(|e| ShellError::GenericError {
            error: "OXC Bridge Creation Failed".into(),
            msg: format!("{:?}", e),
            span: None,
            help: None,
            inner: vec![],
        })?;

    context.global().map_err(|e| ShellError::GenericError {
        error: "Global Access Failed".into(),
        msg: format!("{:?}", e),
        span: None,
        help: None,
        inner: vec![],
    })?
    .set_property("__nexus_js_parse", parse_func.into_value())
    .map_err(|e| ShellError::GenericError {
        error: "Global Property Set Failed".into(),
        msg: format!("{:?}", e),
        span: None,
        help: None,
        inner: vec![],
    })?;

    // Add JS wrapper to adapt OXC AST to Estree (which Porffor expects)
    context.eval(r#"
        globalThis.parse = (code) => {
            const ast = __nexus_js_parse(code);
            
            // Minimal Estree Adapter
            const fix = (node) => {
                if (!node || typeof node !== 'object') return;
                if (node.span) {
                    node.start = node.span.start;
                    node.end = node.span.end;
                }
                if (Array.isArray(node)) {
                    for (let i = 0; i < node.length; i++) fix(node[i]);
                } else {
                    for (const key in node) fix(node[key]);
                }
            };
            fix(ast);
            return ast;
        };

        // Native file reader for mocks
        globalThis.__nexus_native_read_file = (path) => {
            const content = __nexus_native_read_file(path);
            return content || null;
        };
    "#, false).map_err(|e| ShellError::GenericError {
        error: "OXC Wrapper Failed".into(),
        msg: format!("{:?}", e),
        span: None,
        help: None,
        inner: vec![],
    })?;

    // Native file reader for mocks
    context.add_callback("__nexus_native_read_file", |path: String| -> Option<String> {
        std::fs::read_to_string(path).ok()
    }).map_err(|e| ShellError::GenericError {
        error: "Native Bridge Error".into(),
        msg: format!("{:?}", e),
        span: None,
        help: None,
        inner: vec![],
    })?;

    Ok(())
}

/// Format JavaScript value for display (Nushell-style)
pub fn format_js_value(v: &OwnedJsValue) -> String {
    if v.is_string() {
        v.to_string().unwrap_or_else(|_| "Error".to_string())
    } else if v.is_int() {
        v.to_int().map(|i| i.to_string()).unwrap_or_default()
    } else if v.is_float() {
        v.to_float().map(|f| f.to_string()).unwrap_or_default()
    } else if v.is_bool() {
        v.to_bool().map(|b| b.to_string()).unwrap_or_default()
    } else if v.is_array() {
        format!("[Array]")
    } else if v.is_object() {
        format!("{{Object}}")
    } else {
        format!("{:?}", v)
    }
}

/// Convert QuickJS value to Nushell Value (zero-copy where possible)
pub fn js_to_nu(val: &OwnedJsValue, span: Span) -> NuValue {
    js_to_nu_depth(val, span, 0)
}

fn js_to_nu_depth(val: &OwnedJsValue, span: Span, depth: u32) -> NuValue {
    if depth > 16 {
        return NuValue::string("... (max depth)", span);
    }

    if val.is_null() || val.is_undefined() {
        return NuValue::nothing(span);
    }
    
    if val.is_bool() {
        return NuValue::bool(val.to_bool().unwrap_or(false), span);
    }

    if val.is_int() {
        return NuValue::int(val.to_int().unwrap_or(0) as i64, span);
    }

    if val.is_float() {
        return NuValue::float(val.to_float().unwrap_or(0.0), span);
    }

    if val.is_string() {
        return NuValue::string(val.to_string().unwrap_or_default(), span);
    }

    if val.is_array() {
        if let Ok(arr) = val.clone().to_array() {
            let len = arr.length();
            let mut items = Vec::with_capacity(len as usize);
            for i in 0..len {
                if let Ok(Some(item)) = arr.get_index(i as u32) {
                    items.push(js_to_nu_depth(&item, span, depth + 1));
                }
            }
            return NuValue::list(items, span);
        }
    }

    if val.is_object() {
        if let Ok(obj) = val.clone().try_into_object() {
            let mut record = Record::new();
            if let Ok(iter) = obj.properties_iter() {
                for prop_res in iter {
                    if let Ok(key) = prop_res {
                        if let Ok(key_str) = key.to_string() {
                            if let Ok(Some(val)) = obj.property(&key_str) {
                                record.push(key_str, js_to_nu_depth(&val, span, depth + 1));
                            }
                        }
                    }
                }
            }
            return NuValue::record(record, span);
        }
    }

    // Fallback
    NuValue::string(val.to_string().unwrap_or_default(), span)
}

/// Convert Nushell Value to QuickJS value
#[allow(dead_code)]
pub fn nu_to_js(_context: &Context, val: &NuValue) -> Result<OwnedJsValue, ShellError> {
    // Simplified placeholder - implement as needed
    Err(ShellError::GenericError {
        error: "Nu to JS conversion not yet implemented".into(),
        msg: format!("Cannot convert {:?} to JavaScript yet", val),
        span: Some(val.span()),
        help: None,
        inner: vec![],
    })
}
