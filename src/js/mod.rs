use quickrs_core::ast::SourceType as JsSourceType;
use quickrs_core::context::Context;
use quickrs_core::object::{ClassId, ObjectData, PropFlags, PropValue, Property};
use quickrs_core::value::{JsResult, PropKey, Value as JsValue};
use nu_protocol::{Record, ShellError, Span, Value as NuValue};
use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc,
};
use std::thread;

use crate::db::Database;

pub mod cell;
pub mod command;
pub mod transformer;
pub mod wintercg;

#[derive(Clone)]
pub struct JsClient {
    tx: Sender<JsRequest>,
    _db: Arc<Database>,
}

enum JsRequest {
    Execute(String, NuValue, Sender<Result<NuValue, ShellError>>),
}

thread_local! {
    static DB_HANDLE: std::cell::RefCell<Option<Arc<Database>>> = std::cell::RefCell::new(None);
}

impl JsClient {
    pub fn new(db: Arc<Database>) -> Self {
        let (tx, rx) = channel();

        let db_clone = db.clone();
        let handle = tokio::runtime::Handle::current();
        thread::spawn(move || {
            let _guard = handle.enter();
            DB_HANDLE.with(|h| *h.borrow_mut() = Some(db_clone));
            let context = Self::create_context();
            Self::actor_loop(context, rx);
        });

        Self { tx, _db: db }
    }

    fn create_context() -> Context {
        let mut context = Context::new();
        let global = context.global();

        let register = |ctx: &mut Context, name: &str, arity: u32, func: quickrs_core::object::NativeFn| {
            let f = ctx.new_native_function(func, name, arity, 0);
            let key = PropKey::from_string(&ctx.intern(name));
            ctx.define_own(&global, key, Property::data(JsValue::Object(f), PropFlags::C_W_E));
        };

        // Host globals: print, load_file, sql (ZCZS direct SurrealDB -> quickrs Value)
        register(&mut context, "print", 1, nexus_print_callback);
        register(&mut context, "load_file", 1, nexus_load_file_callback);
        register(&mut context, "sql", 1, nexus_sql_callback);

        // Minimal console.log/warn/error forwarding to host stdout
        let _ = context.eval(
            r#"
            if (typeof globalThis.console === "undefined") {
                globalThis.console = {
                    log: (...args) => print(args.map(String).join(" ")),
                    info: (...args) => print(args.map(String).join(" ")),
                    warn: (...args) => print("[WARN] " + args.map(String).join(" ")),
                    error: (...args) => print("[ERROR] " + args.map(String).join(" ")),
                };
            }
            "#,
        );

        context
    }

    fn actor_loop(mut context: Context, rx: Receiver<JsRequest>) {
        while let Ok(req) = rx.recv() {
            match req {
                JsRequest::Execute(code, span_val, resp_tx) => {
                    let span = span_val.span();
                    let result = eval_code(&mut context, code, span);
                    let _ = resp_tx.send(result);
                }
            }
        }
    }

    pub fn execute(&self, code: String, span: Span) -> Result<NuValue, ShellError> {
        let (resp_tx, resp_rx) = channel();
        let span_val = NuValue::nothing(span);
        self.tx
            .send(JsRequest::Execute(code, span_val, resp_tx))
            .expect("JS Actor Dead");
        resp_rx.recv().unwrap_or_else(|_| {
            Err(crate::shell_err(
                "JS Engine Error",
                "JS Actor Disconnected",
                Some(span),
                None,
            ))
        })
    }

    pub fn oneshot_async_blocking(
        code: String,
        db: Option<Arc<Database>>,
        span: Span,
    ) -> Result<NuValue, ShellError> {
        let handle = tokio::runtime::Handle::current();
        let _guard = handle.enter();

        DB_HANDLE.with(|h| *h.borrow_mut() = db);
        let mut context = Self::create_context();
        eval_code(&mut context, code, span)
    }
}

fn eval_code(context: &mut Context, mut code: String, span: Span) -> Result<NuValue, ShellError> {
    if transformer::is_likely_ts(&code) {
        if let Ok(transpiled) = transformer::transform_ts_to_js(&code, span) {
            code = transpiled;
        }
    }

    let is_module = code.contains("import ") || code.contains("export ");
    let eval_res = if is_module {
        context
            .eval_as(&code, JsSourceType::Module)
            .and_then(|v| {
                context.run_jobs()?;
                Ok(v)
            })
    } else {
        match context.eval_and_run_jobs(&code) {
            Ok(v) => Ok(v),
            Err(e) => {
                if code.trim().starts_with('{') {
                    let wrapped = format!("var _res = ({}); _res", code);
                    context.eval_and_run_jobs(&wrapped)
                } else {
                    Err(e)
                }
            }
        }
    };

    match eval_res {
        Ok(val) => Ok(js_to_nu(context, &val, span)),
        Err(e) => Err(crate::shell_err(
            if is_module { "JS Module Error" } else { "JS Error" },
            format!("{:?}", e),
            Some(span),
            None,
        )),
    }
}

fn nexus_print_callback(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let parts: Vec<String> = args
        .iter()
        .map(|v| value_to_display(ctx, v))
        .collect();
    println!("{}", parts.join(" "));
    Ok(JsValue::Bool(true))
}

fn nexus_load_file_callback(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let path = args
        .first()
        .map(|v| value_to_display(ctx, v))
        .unwrap_or_default();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| format!("/* Error loading {} */", path));
    Ok(JsValue::Str(ctx.intern(&content)))
}

/// Zero-copy-oriented `sql(query)` bridge mapping `nexus_db::Value` directly to `quickrs_core::Value`.
fn nexus_sql_callback(
    ctx: &mut Context,
    _this: &JsValue,
    args: &[JsValue],
    _magic: i32,
) -> JsResult<JsValue> {
    let query = match args.first() {
        Some(v) => value_to_display(ctx, v),
        None => return Ok(JsValue::Undefined),
    };

    let Some(db) = DB_HANDLE.with(|h| h.borrow().clone()) else {
        return Ok(JsValue::Str(ctx.intern("Database handle not available")));
    };

    let rt = tokio::runtime::Handle::current();
    let rows: Result<Vec<nexus_db::Value>, String> = tokio::task::block_in_place(|| {
        rt.block_on(async move {
            let _ = db.client.use_ns("nexus").use_db("system").await;
            match db.client.query(query).await {
                Ok(response) => Ok(response.take_values()),
                Err(e) => Err(format!("DB error: {}", e)),
            }
        })
    });

    match rows {
        Ok(list) => {
            let js_items: Vec<JsValue> = list.into_iter().map(|v| surreal_to_js(ctx, v)).collect();
            let arr = ctx.new_array_from(js_items);
            Ok(JsValue::Object(arr))
        }
        Err(err) => {
            let obj = ctx.new_object();
            let key = PropKey::from_string(&ctx.intern("error"));
            let val = JsValue::Str(ctx.intern(&err));
            ctx.define_own(&obj, key, Property::data(val, PropFlags::C_W_E));
            Ok(JsValue::Object(obj))
        }
    }
}

/// Direct `nexus_db::Value` -> `quickrs_core::value::Value` conversion (no `serde_json` hop).
fn surreal_to_js(ctx: &mut Context, val: nexus_db::Value) -> JsValue {
    match val {
        nexus_db::Value::None | nexus_db::Value::Null => JsValue::Null,
        nexus_db::Value::Bool(b) => JsValue::Bool(b),
        nexus_db::Value::Int(i) => {
            if let Ok(i32_val) = i32::try_from(i) {
                JsValue::Int(i32_val)
            } else {
                JsValue::Float(i as f64)
            }
        }
        nexus_db::Value::Float(f) => JsValue::Float(f),
        nexus_db::Value::String(s)
        | nexus_db::Value::DateTime(s)
        | nexus_db::Value::Decimal(s) => JsValue::Str(ctx.intern(&s)),
        nexus_db::Value::Duration(secs) => JsValue::Str(ctx.intern(&format!("{}s", secs))),
        nexus_db::Value::RecordId { tb, id } => {
            JsValue::Str(ctx.intern(&format!("{}:{}", tb, id)))
        }
        nexus_db::Value::Array(arr) => {
            let items: Vec<JsValue> = arr.into_iter().map(|v| surreal_to_js(ctx, v)).collect();
            JsValue::Object(ctx.new_array_from(items))
        }
        nexus_db::Value::Object(map) => {
            let obj = ctx.new_object();
            for (k, v) in map {
                let key = PropKey::from_string(&ctx.intern(&k));
                let js_v = surreal_to_js(ctx, v);
                ctx.define_own(&obj, key, Property::data(js_v, PropFlags::C_W_E));
            }
            JsValue::Object(obj)
        }
        other => JsValue::Str(ctx.intern(&format!("{:?}", other))),
    }
}

fn value_to_display(_ctx: &Context, val: &JsValue) -> String {
    match val {
        JsValue::Undefined | JsValue::Uninitialized => "undefined".to_string(),
        JsValue::Null => "null".to_string(),
        JsValue::Bool(b) => b.to_string(),
        JsValue::Int(i) => i.to_string(),
        JsValue::Float(f) => f.to_string(),
        JsValue::Str(s) => s.to_string(),
        other => format!("{:?}", other),
    }
}

fn js_to_nu(ctx: &mut Context, val: &JsValue, span: Span) -> NuValue {
    js_to_nu_depth(ctx, val, span, 0)
}

fn js_to_nu_depth(ctx: &mut Context, val: &JsValue, span: Span, depth: usize) -> NuValue {
    if depth > 10 {
        return NuValue::string("<max depth>".to_string(), span);
    }

    match val {
        JsValue::Undefined | JsValue::Uninitialized | JsValue::Null => NuValue::nothing(span),
        JsValue::Bool(b) => NuValue::bool(*b, span),
        JsValue::Int(i) => NuValue::int(*i as i64, span),
        JsValue::Float(f) => NuValue::float(*f, span),
        JsValue::Str(s) => NuValue::string(s.to_string(), span),
        JsValue::Object(obj) => {
            let array_items: Option<Vec<JsValue>> = {
                let borrowed = obj.borrow();
                if borrowed.class == ClassId::Array {
                    if let ObjectData::Array(arr) = &borrowed.data {
                        Some(arr.elements.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(elems) = array_items {
                let list: Vec<NuValue> = elems
                    .iter()
                    .map(|v| js_to_nu_depth(ctx, v, span, depth + 1))
                    .collect();
                return NuValue::list(list, span);
            }

            let mut rec = Record::new();
            if let Ok(keys) = ctx.own_property_keys(obj) {
                for k in keys {
                    let prop_val = obj.borrow().get_own(&k).and_then(|p| match p.value {
                        PropValue::Value(v) => Some(v),
                        _ => None,
                    });
                    if let Some(v) = prop_val {
                        let key_str = match &k {
                            PropKey::Index(i) => i.to_string(),
                            PropKey::Str(s) => s.to_string(),
                            PropKey::Sym(_) => "Symbol".to_string(),
                        };
                        rec.push(key_str, js_to_nu_depth(ctx, &v, span, depth + 1));
                    }
                }
            }
            NuValue::record(rec, span)
        }
        other => NuValue::string(format!("{:?}", other), span),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_native_typescript_and_es2023_in_quickrs() {
        let mut ctx = JsClient::create_context();
        let ts = r#"
            interface Counter { val: number; }
            class Cell {
                state: Counter;
                constructor(start: number) { this.state = { val: start }; }
                async bump(n: number): Promise<number> {
                    const delta = await Promise.resolve(n);
                    this.state.val += delta;
                    return this.state.val;
                }
            }
            globalThis.__out = 0;
            (async () => {
                const c = new Cell(10);
                globalThis.__out = await c.bump(32);
            })();
            globalThis.__out
        "#;
        let _ = eval_code(&mut ctx, ts.to_string(), Span::unknown()).unwrap();
        let out = eval_code(&mut ctx, "globalThis.__out".to_string(), Span::unknown()).unwrap();
        assert_eq!(out.as_int().unwrap(), 42);
    }
}
