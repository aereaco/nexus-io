use quickjs_rusty::{Context, OwnedJsValue};
use libquickjs_ng_sys as q;
use nu_protocol::{Value as NuValue, Span, ShellError};
use std::sync::{mpsc::{channel, Sender, Receiver}, Arc};
use std::thread;
use crate::db::Database;

pub mod command;
pub mod transformer;

#[derive(Clone)]
pub struct JsClient {
    tx: Sender<JsRequest>,
    db: Arc<Database>,
}

enum JsRequest {
    Execute(String, NuValue, Sender<Result<NuValue, ShellError>>),
}

thread_local! {
    static IN_CONSOLE: std::cell::Cell<bool> = std::cell::Cell::new(false);
    static DB_HANDLE: std::cell::RefCell<Option<Arc<Database>>> = std::cell::RefCell::new(None);
}

impl JsClient {
    pub fn new(db: Arc<Database>) -> Self {
        let (tx, rx) = channel();
        
        let db_clone = db.clone();
        let handle = tokio::runtime::Handle::current();
        thread::spawn(move || {
            let _guard = handle.enter();
            DB_HANDLE.with(|h| *h.borrow_mut() = Some(db_clone.clone()));
            let context = Self::create_context(Some(db_clone));
            Self::actor_loop(context, rx);
        });

        Self { tx, db }
    }

    fn create_context(_db: Option<Arc<Database>>) -> Context {
        let context = Context::builder()
            .console(|level: quickjs_rusty::console::Level, args: Vec<OwnedJsValue>| {
                if IN_CONSOLE.with(|f| f.get()) { return; }
                IN_CONSOLE.with(|f| f.set(true));

                let items: Vec<String> = args.iter()
                    .map(|v| {
                        if v.is_string() {
                            v.to_string().unwrap_or_else(|_| "Error".to_string())
                        } else {
                            // Recursively format to Nushell-style syntax
                            fn format_nu_style(v: &OwnedJsValue, depth: usize) -> String {
                                if depth > 2 { return "...".to_string(); } // simple depth limit
                                
                                if v.is_array() {
                                    let arr = v.to_array().unwrap();
                                    let len = arr.length();
                                    let mut s = String::from("[");
                                    for i in 0..len {
                                        if i > 0 { s.push_str(", "); }
                                        if let Some(val) = arr.get_index(i as u32).unwrap() {
                                            s.push_str(&format_nu_style(&val, depth + 1));
                                        }
                                    }
                                    s.push(']');
                                    return s;
                                }
                                
                                if v.is_object() {
                                    if let Ok(_obj) = v.clone().try_into_object() {
                                        // Use the mapped NuValue logic but invoke a custom printer.
                                        match js_to_nu_depth(v, Span::unknown(), 0) {
                                            NuValue::Record { val, .. } => {
                                                let mut s = String::from("{ ");
                                                let inner = &val; // SharedCow
                                                let mut first = true;
                                                for (k, v) in inner.iter() {
                                                    if !first { s.push_str(", "); }
                                                    s.push_str(k);
                                                    s.push_str(": ");
                                                    match v {
                                                        NuValue::Int { val, .. } => s.push_str(&val.to_string()),
                                                        NuValue::Bool { val, .. } => s.push_str(&val.to_string()),
                                                        NuValue::String { val, .. } => s.push_str(&format!("\"{}\"", val)),
                                                        NuValue::Float { val, .. } => s.push_str(&val.to_string()),
                                                        // Fallback for nested NuValues implies recursion on NuValue, not JS value.
                                                        // Simplified fallback: just use Debug for deep nesting to avoid complexity
                                                        _ => s.push_str(&format!("{:?}", v))
                                                    }
                                                    first = false;
                                                }
                                                s.push_str(" }");
                                                return s;
                                            },
                                            // Fix recursion for lists to be cleaner
                                            primitive => {
                                                match primitive {
                                                    NuValue::Int { val, .. } => return val.to_string(),
                                                    NuValue::Bool { val, .. } => return val.to_string(),
                                                    NuValue::String { val, .. } => return val, // No quotes for top level? Or quotes? formatted usually quotes.
                                                    NuValue::Float { val, .. } => return val.to_string(),
                                                    _ => return format!("{:?}", primitive)
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                format!("{:?}", v)
                            }
                            // Re-enable js_to_nu_depth
                            format_nu_style(v, 0)
                        }
                    })
                    .collect();
                println!("[JS {:?}] {}", level, items.join(" "));
                
                IN_CONSOLE.with(|f| f.set(false));
            })
            .build()
            .expect("Failed to create JS context");

        // Safe stack size increase (verified offset 6 for JSRuntime in context struct)
        unsafe {
             let ptr = &context as *const Context as *const usize;
             let rt = *ptr.add(6) as *mut q::JSRuntime;
             if !rt.is_null() && (rt as usize) > 0x1000000 {
                 q::JS_SetMaxStackSize(rt, 1024 * 1024 * 16);
             }
        }
        
        // Inject Deno-like globals
        context.add_callback("print", |s: String| -> bool {
            println!("{}", s);
            true
        }).expect("Failed to add print callback");

        context.add_callback("load_file", |path: String| -> String {
            std::fs::read_to_string(&path).unwrap_or_else(|_| format!("/* Error loading {} */", path))
        }).expect("Failed to add load_file callback");

        // Inject sql callback via custom callback to handle async and complex types
        fn nexus_sql_callback(ctx: *mut q::JSContext, args: &[q::JSValue]) -> anyhow::Result<Option<q::JSValue>> {
            use quickjs_rusty::OwnedJsValue;
            use quickjs_rusty::serde::to_js;

            if args.is_empty() {
                return Err(anyhow::anyhow!("Missing query argument"));
            }
            let query_val = OwnedJsValue::own(ctx, &args[0]);
            let query = query_val.to_string().map_err(|e| anyhow::anyhow!(e.to_string()))?;

            let db = DB_HANDLE.with(|h| h.borrow().clone())
                .ok_or_else(|| anyhow::anyhow!("Database handle not available (lazy loaded)"))?;

            let rt = tokio::runtime::Handle::current();
            let result: serde_json::Value = tokio::task::block_in_place(|| {
                rt.block_on(async move {
                    let _ = db.client.use_ns("nexus").use_db("system").await;
                    match db.client.query(query).await {
                        Ok(mut response) => {
                             match response.take::<Vec<serde_json::Value>>(0) {
                                 Ok(rows) => serde_json::Value::Array(rows),
                                 Err(e) => serde_json::json!({ "error": format!("Fetch error: {}", e) }),
                             }
                        },
                        Err(e) => serde_json::json!({ "db_error": e.to_string() }),
                    }
                })
            });

            let js_val = to_js(ctx, &result).map_err(|e| anyhow::anyhow!("SQL Projection Error: {}", e))?;
            unsafe { Ok(Some(js_val.extract())) }
        }

        let sql_func = context.create_custom_callback(nexus_sql_callback)
            .expect("Failed to create sql callback");

        context.global().expect("Failed to get global")
            .set_property("sql", sql_func.into_value())
            .expect("Failed to set sql global");


        // Define callback matching CustomCallback signature exactly
        fn nexus_js_parse_callback(ctx: *mut q::JSContext, args: &[q::JSValue]) -> anyhow::Result<Option<q::JSValue>> {
            use oxc_allocator::Allocator;
            use oxc_parser::Parser;
            use oxc_span::SourceType;
            use quickjs_rusty::OwnedJsValue;
            use quickjs_rusty::serde::to_js;
            use anyhow::anyhow;

            if args.is_empty() {
                return Err(anyhow!("Missing code argument"));
            }

            // Convert argument to string safely (duplicating the value to not steal ownership)
            let code_val = OwnedJsValue::own(ctx, &args[0]);
            let code = code_val.to_string().map_err(|e| anyhow!(e.to_string()))?;

            let allocator = Allocator::default();
            // We force .js here because we already transpiled it (if it was TS) or it is raw JS
            // But actually, for AOT this might be the first pass.
            // Wait, for AOT we standardized on input.js.
            let source_type = SourceType::from_path("input.js").unwrap();
            let parser = Parser::new(&allocator, &code, source_type);
            let parser_return = parser.parse();
            
            if !parser_return.errors.is_empty() {
                return Err(anyhow!(parser_return.errors[0].message.to_string()));
            }
            
            // Project AST directly to JS objects via Serde
            // to_js returns Result<OwnedJsValue, Error>
            let js_ast = to_js(ctx, &parser_return.program).map_err(|e| anyhow!("AST Projection Error: {}", e))?;
            
            // Return raw value, transferring ownership to QuickJS runtime
            unsafe { Ok(Some(js_ast.extract())) }
        }

        let parse_func = context.create_custom_callback(nexus_js_parse_callback)
            .expect("Failed to create __nexus_js_parse callback");
        
        context.global().expect("Failed to get global")
            .set_property("__nexus_js_parse", parse_func.into_value())
            .expect("Failed to set __nexus_js_parse");

        // Inject Globals for Porffor/Node compatibility
        context.eval(r#"
            globalThis.parse = (code) => {
                const ast = __nexus_js_parse(code);
                
                // Zero-Copy Estree Adapter: Map OXC spans to Estree start/end
                const fix = (node) => {
                    if (!node || typeof node !== 'object') return;
                    if (node.span) {
                        node.start = node.span.start;
                        node.end = node.span.end;
                    }
                    if (Array.isArray(node)) {
                        for (let i = 0; i < node.length; i++) fix(node[i]);
                    } else {
                        for (const key in node) {
                             // potential optimization: skip certain keys
                             fix(node[key]);
                        }
                    }
                };
                fix(ast);

                return ast;
            };

            // Fix console properties for compatibility (specifically .name)
            ['log', 'info', 'warn', 'error', 'debug'].forEach(m => {
                if (globalThis.console && globalThis.console[m]) {
                    Object.defineProperty(globalThis.console[m], 'name', { value: m, configurable: true });
                }
            });

            globalThis.process = { 
                env: {},
                argv: [],
                cwd: () => '/',
                platform: 'linux',
                nextTick: (fn) => setTimeout(fn, 0)
            }; 
            globalThis.Buffer = {
                from: (data) => new Uint8Array(data),
                alloc: (size) => new Uint8Array(size),
                isBuffer: (obj) => obj instanceof Uint8Array
            };

            // Polyfill TextEncoder/TextDecoder for Porffor
            globalThis.TextEncoder = class TextEncoder {
                encode(s) {
                    if (typeof s !== 'string') s = String(s);
                    let esc = encodeURIComponent(s);
                    let bin = [];
                    for (let i = 0; i < esc.length; i++) {
                        let c = esc.charAt(i);
                        if (c === '%') {
                            bin.push(parseInt(esc.substr(i+1, 2), 16));
                            i += 2;
                        } else {
                            bin.push(c.charCodeAt(0));
                        }
                    }
                    return new Uint8Array(bin);
                }
            };
            
            globalThis.TextDecoder = class TextDecoder {
                decode(arr) {
                    if (!arr) return '';
                    let s = '';
                    for (let i = 0; i < arr.length; i++) {
                        let c = arr[i];
                        if (c < 128) {
                            s += String.fromCharCode(c);
                        } else {
                            s += '%' + c.toString(16).toUpperCase();
                        }
                    }
                    try {
                        return decodeURIComponent(s);
                    } catch (e) {
                        return s;
                    }
                }
            };
        "#, false).expect("Failed to inject globals");

        context.set_module_loader(
            Box::new(|module_name, _| {
                match module_name {
                    "node:fs" => Ok(r#"
                        export const readFileSync = (path) => globalThis.load_file(path);
                        export const promises = { readFile: async (path) => globalThis.load_file(path) };
                        export default { readFileSync, promises };
                    "#.to_string()),
                    "node:child_process" => Ok("export const execSync = () => {}; export default { execSync };".to_string()), 
                    "node:path" => Ok("export default {};".to_string()),
                    "node:process" => Ok("export default {};".to_string()),
                    "node:url" => Ok("export default {};".to_string()),
                    "node:module" => Ok("export default {};".to_string()),
                    "porffor" => Ok(include_str!("../../porffor_blob_c.js").to_string()),
                    "acorn" => {
                        std::fs::read_to_string("node_modules/acorn/dist/acorn.mjs")
                            .map_err(|e| anyhow::anyhow!("Failed to load acorn module: {}", e))
                    },
                    _ => {
                        // Basic file matching
                         std::fs::read_to_string(module_name)
                            .map_err(|e| anyhow::anyhow!("Failed to load module {}: {}", module_name, e))
                    }
                }
            }),
            None,
            std::ptr::null_mut(),
        );

        context
    }

    fn actor_loop(context: Context, rx: Receiver<JsRequest>) {
        while let Ok(msg) = rx.recv() {
            match msg {
                JsRequest::Execute(mut code, span_val, response_tx) => {
                     let span = span_val.span();
                     
                     if transformer::is_likely_ts(&code) {
                         match transformer::transform_ts_to_js(&code, span) {
                             Ok(new_code) => code = new_code,
                             Err(e) => {
                                 let _ = response_tx.send(Err(e));
                                 continue;
                             }
                         }
                     }

                     let is_module = code.contains("import ") || code.contains("export ") || code.contains("// MODULE");
                     
                     let result = if is_module {
                        match context.eval_module(&code, true) {
                            Ok(v) => Ok(js_to_nu(&v, span)),
                            Err(e) => Err(format_js_error(e, span, true)),
                        }
                     } else {
                        match context.eval(&code, true) {
                            Ok(v) => Ok(js_to_nu(&v, span)),
                            Err(e) => {
                                if code.trim().starts_with('{') {
                                    let wrapped = format!("var _res = ({}); _res", code);
                                    if let Ok(v) = context.eval(&wrapped, true) {
                                        Ok(js_to_nu(&v, span))
                                    } else {
                                        Err(format_js_error(e, span, false))
                                    }
                                } else {
                                    Err(format_js_error(e, span, false))
                                }
                            }
                        }
                    };
                    let _ = response_tx.send(result);
                }
            }
        }
    }

    pub fn execute(&self, code: String, span: Span) -> Result<NuValue, ShellError> {
        let (resp_tx, resp_rx) = channel();
        let span_val = NuValue::nothing(span);
        self.tx.send(JsRequest::Execute(code, span_val, resp_tx)).expect("JS Actor Dead");
        resp_rx.recv().unwrap_or_else(|_| Err(crate::shell_err(
            "JS Engine Error",
            "JS Actor Disconnected",
            Some(span),
            None,
        )))
    }

    pub fn oneshot_async_blocking(mut code: String, db: Option<Arc<Database>>, span: Span) -> Result<NuValue, ShellError> {
        let handle = tokio::runtime::Handle::current();
        let _guard = handle.enter();

        if transformer::is_likely_ts(&code) {
            code = transformer::transform_ts_to_js(&code, span)?;
        }
        
        DB_HANDLE.with(|h| *h.borrow_mut() = db.clone());
        let context = Self::create_context(db);
        let is_module = code.contains("import ") || code.contains("export ");

        if is_module {
            match context.eval_module(&code, true) {
                Ok(v) => Ok(js_to_nu(&v, span)),
                Err(e) => Err(format_js_error(e, span, true)),
            }
        } else {
            match context.eval(&code, true) {
                Ok(v) => Ok(js_to_nu(&v, span)),
                Err(e) => {
                    if code.trim().starts_with('{') {
                        let wrapped = format!("var _res = ({}); _res", code);
                        match context.eval(&wrapped, true) {
                            Ok(v) => Ok(js_to_nu(&v, span)),
                            Err(e) => Err(format_js_error(e, span, false)),
                        }
                    } else {
                        Err(format_js_error(e, span, false))
                    }
                }
            }
        }
    }
}

fn format_js_error(e: quickjs_rusty::ExecutionError, span: Span, is_module: bool) -> ShellError {
    let msg = match e {
        quickjs_rusty::ExecutionError::Exception(val) => {
            let base = val.to_string().unwrap_or_else(|_| "Unknown Exception".to_string());
            let stack = val.clone().try_into_object().ok()
                .and_then(|obj| obj.property("stack").ok().flatten())
                .and_then(|v| v.to_string().ok())
                .unwrap_or_default();
            if stack.is_empty() {
                base
            } else {
                format!("{}\nStack Trace:\n{}", base, stack)
            }
        },
        other => format!("{:?}", other),
    };
    
    crate::shell_err(
        if is_module { "JS Module Error" } else { "JS Error" },
        msg,
        Some(span),
        None,
    )
}

fn js_to_nu(val: &OwnedJsValue, span: Span) -> NuValue {
    js_to_nu_depth(val, span, 0)
}

fn js_to_nu_depth(val: &OwnedJsValue, span: Span, depth: u32) -> NuValue {
    if depth > 16 {
        return NuValue::string("... (Max Depth)", span);
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
        // Clone to get ownership for conversion to OwnedJsArray
        // This is cheap in QuickJS (ref count bump)
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
            let mut record = nu_protocol::Record::new();
            // Iterate over properties
            // properties_iter returns Result<PropertyIterator>
            if let Ok(iter) = obj.properties_iter() {
                for prop_res in iter {
                    if let Ok(key) = prop_res {
                         if let Ok(key_str) = key.to_string() {
                             // property() returns Result<Option<OwnedJsValue>>
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
