/// Nushell commands for JavaScript execution via QuickJS-NG

use nu_engine::CallExt;
use nu_protocol::{
    engine::{Command, EngineState, Stack, Call},
    Category, Example, PipelineData, ShellError, Signature, SyntaxShape, Type, Value, Span, IntoPipelineData
};
use crate::js::core::{create_context, format_js_value, js_to_nu, NuBridge};
use crate::js::transformer;
use rustyline::DefaultEditor;

#[derive(Clone)]
pub struct JsCommand;

impl Command for JsCommand {
    fn name(&self) -> &str {
        "js"
    }

    fn signature(&self) -> Signature {
        Signature::build("js")
            .optional("code", SyntaxShape::String, "JavaScript code to execute")
            .switch("harden", "Compile to native binary via Porffor AOT", Some('z'))
            .category(Category::Custom("nexus".into()))
            .input_output_types(vec![(Type::Any, Type::Any)])
    }

    fn description(&self) -> &str {
        "Execute JavaScript/TypeScript code via QuickJS-NG runtime"
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let code: Option<String> = call.opt(engine_state, stack, 0)?;
        let harden = call.has_flag(engine_state, stack, "harden")?;
        let span = call.head;

        let mut code = if let Some(c) = code {
            c
        } else {
            // Interactive REPL
            run_repl(span, engine_state, stack)?;
            return Ok(PipelineData::empty());
        };

        // Transform TypeScript if needed
        if transformer::is_likely_ts(&code) {
            code = transformer::transform_ts_to_js(&code, span)?;
        }

        let (final_code, filename) = if code.ends_with(".js") || code.ends_with(".ts") {
            let p = std::path::Path::new(&code);
            if p.exists() {
                let content = std::fs::read_to_string(p).map_err(|e| ShellError::GenericError {
                    error: "File read error".into(),
                    msg: e.to_string(),
                    span: Some(span),
                    help: None,
                    inner: vec![],
                })?;
                (content, Some(code))
            } else {
                return Err(ShellError::GenericError {
                    error: "File not found".into(),
                    msg: format!("The JavaScript/TypeScript file '{}' was not found", code),
                    span: Some(span),
                    help: Some("Ensure the path is correct or wrap standard JS code in quotes if it's not a file".into()),
                    inner: vec![],
                });
            }
        } else {
            (code.clone(), None)
        };

        if harden {
            // Porffor AOT compilation
            compile_to_native(&final_code, span, engine_state, stack)?;
            return Ok(Value::string(
                "Compiled to crystal.bin via Porffor AOT",
                span
            ).into_pipeline_data());
        }

        // JIT execution via QuickJS
        execute_js(&final_code, filename.as_deref(), span, engine_state, stack)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "Execute JavaScript",
                example: r#"js "console.log('Hello from QuickJS')""#,
                result: None,
            },
            Example {
                description: "Execute TypeScript",
                example: r#"js "const x: number = 42; x * 2""#,
                result: None,
            },
            Example {
                description: "Compile to native binary",
                example: r#"js --harden "console.log('Native!')""#,
                result: None,
            },
        ]
    }
}

/// Execute JavaScript code
fn execute_js(code: &str, filename: Option<&str>, span: Span, engine_state: &EngineState, stack: &mut Stack) -> Result<PipelineData, ShellError> {
    let mut bridge = NuBridge { 
        engine_state: engine_state as *const EngineState as *mut EngineState, 
        stack,
        base_path: filename.map(|s| s.to_string()),
    };
    let context = create_context(&mut bridge)?;
    
    // QuickJS v0.11 eval (true means module)
    let result = context.eval_module(code, true);

    match result {
        Ok(val) => Ok(js_to_nu(&val, span).into_pipeline_data()),
        Err(e) => {
            let msg = if let quickjs_rusty::ExecutionError::Exception(v) = &e {
                format_js_value(v)
            } else {
                format!("{:?}", e)
            };
            Err(ShellError::GenericError {
                error: "JavaScript Execution Error".into(),
                msg,
                span: Some(span),
                help: None,
                inner: vec![],
            })
        }
    }
}

/// Compile JavaScript to native binary via Porffor AOT
fn compile_to_native(code: &str, span: Span, engine_state: &EngineState, stack: &mut Stack) -> Result<(), ShellError> {
    // Step 1: Compile JS → C via Porffor
    let mut bridge = NuBridge { 
        engine_state: engine_state as *const EngineState as *mut EngineState, 
        stack,
        base_path: None,
    };
    let context = create_context(&mut bridge)?;
    
    // Setup file global for Porffor
    context.eval("globalThis.file = 'input.js';", false)
        .map_err(|e| ShellError::GenericError {
            error: "Porffor Setup Error".into(),
            msg: format!("{:?}", e),
            span: Some(span),
            help: None,
            inner: vec![],
        })?;

    // Mock process for Porffor
    context.eval(r#"
        globalThis.process = {
            version: 'v20.0.0',
            argv: ['node', 'porffor'],
            platform: 'linux',
            env: {},
            stdout: { isTTY: false, write: (msg) => {} },
            exit: (code) => { /* no-op to allow return */ }
        };
    "#, false).map_err(|e| ShellError::GenericError {
        error: "Porffor Process Mock Error".into(),
        msg: format!("{:?}", e),
        span: Some(span),
        help: None,
        inner: vec![],
    })?;

    // Inject source code directly for zero-serialization
    context.set_global("_nexus_source", code).map_err(|e| ShellError::GenericError {
        error: "QuickJS Integration Error".into(),
        msg: format!("{:?}", e),
        span: Some(span),
        help: None,
        inner: vec![],
    })?;

    // Create the Porffor compilation script (Sovereign Path)
    // This script runs Porffor directly from node_modules using our virtual Node environment
    let porffor_code = r#"
        import compile from './node_modules/porffor/compiler/index.js';
        import toc from './node_modules/porffor/compiler/2c.js';

        try {
            // Configure Porffor for C target
            globalThis.Prefs = { 
                target: 'c',
                parser: 'preset', // Use our native globalThis.parse
            };

            const out = compile(globalThis._nexus_source);
            
            // Mirroring legacy fix: ensure importedFuncs is an array for the 'c' target
            const c_code = toc({ 
                ...out, 
                importFuncs: Array.from(out.importFuncs || []) 
            });

            globalThis._nexus_c_out = c_code;
        } catch (e) {
            globalThis._nexus_c_out = 'ERR: ' + e.toString() + (e.stack ? '\n' + e.stack : '');
        }
    "#;

    // Evaluate module
    context.eval_module(porffor_code, true)
        .map_err(|e| {
            // Try to extract stack trace if it's an exception
            let msg = if let quickjs_rusty::ExecutionError::Exception(val) = &e {
                let mut m = val.to_string().unwrap_or_else(|_| format!("{:?}", e));
                // Try to get stack
                if val.is_object() {
                    if let Ok(obj) = val.clone().try_into_object() {
                        if let Ok(Some(stack)) = obj.property("stack") {
                            if let Ok(stack_str) = stack.to_string() {
                                m = format!("{}\n{}", m, stack_str);
                            }
                        }
                    }
                }
                m
            } else {
                format!("{:?}", e)
            };
            
            ShellError::GenericError {
                error: "Porffor Compilation Error".into(),
                msg,
                span: Some(span),
                help: None,
                inner: vec![],
            }
        })?;

    // Retrieve output
    let c_code_val = context.eval("globalThis._nexus_c_out", false)
        .map_err(|e| ShellError::GenericError {
            error: "Porffor Output Error".into(),
            msg: format!("{:?}", e),
            span: Some(span),
            help: None,
            inner: vec![],
        })?;

    let c_code = c_code_val.to_string().unwrap_or_else(|_| "ERROR".to_string());

    println!("DEBUG: Input code: {}", code);
    println!("DEBUG: Output C code start: {:.100}", c_code);

    if c_code.starts_with("NO_") || c_code.starts_with("ERR:") {
        return Err(ShellError::GenericError {
            error: "Porffor Failed".into(),
            msg: c_code,
            span: Some(span),
            help: None,
            inner: vec![],
        });
    }

    // Step 2: Compile C → native binary
    let c_file = "nexus_crystal.c";
    let bin_file = "crystal.bin";
    
    std::fs::write(c_file, &c_code).map_err(|e| ShellError::GenericError {
        error: "File Write Error".into(),
        msg: e.to_string(),
        span: Some(span),
        help: None,
        inner: vec![],
    })?;

    let output = std::process::Command::new("cc")
        .arg(c_file)
        .arg("src/c/NXs.c")
        .arg("-o")
        .arg(bin_file)
        .arg("-Isrc/c")
        .arg("-lm")
        .output()
        .map_err(|e| ShellError::GenericError {
            error: "C Compiler Error".into(),
            msg: e.to_string(),
            span: Some(span),
            help: None,
            inner: vec![],
        })?;
        
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ShellError::GenericError {
            error: "C Compilation Failed".into(),
            msg: stderr.to_string(),
            span: Some(span),
            help: None,
            inner: vec![],
        });
    }
    
    // Cleanup C file
    // let _ = std::fs::remove_file(c_file);

    Ok(())
}

fn run_repl(span: Span, engine_state: &EngineState, stack: &mut Stack) -> Result<(), ShellError> {
    let _bridge = NuBridge { 
        engine_state: engine_state as *const EngineState as *mut EngineState, 
        stack,
        base_path: None,
    };
    let mut rl = DefaultEditor::new().map_err(|e| ShellError::GenericError {
        error: "REPL init error".into(),
        msg: e.to_string(),
        span: Some(span),
        help: None,
        inner: vec![],
    })?;

    println!("Nexus-IO JavaScript REPL (QuickJS-NG v0.11)");
    println!("Type 'exit' to quit");

    loop {
        let readline = rl.readline("nexus [js]> ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line == "exit" {
                    break;
                }
                if line.is_empty() {
                    continue;
                }
                
                let _ = rl.add_history_entry(line);
                
                let exec_code = if transformer::is_likely_ts(line) {
                    match transformer::transform_ts_to_js(line, span) {
                        Ok(js) => js,
                        Err(e) => {
                            eprintln!("Error transforming TS: {:?}", e);
                            continue;
                        }
                    }
                } else {
                    line.to_string()
                };

                // Run JS
                match execute_js(&exec_code, None, span, engine_state, stack) {
                    Ok(pipeline_data) => {
                        // Print result
                         if let PipelineData::Value(v, _) = pipeline_data {
                            if !v.is_nothing() {
                                println!("{}", v.to_debug_string());
                            }
                        }
                    },
                    Err(e) => eprintln!("Error: {:?}", e),
                }
            },
            Err(_) => break,
        }
    }
    Ok(())
}
