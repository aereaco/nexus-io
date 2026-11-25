use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, Signature, SyntaxShape, Type, ShellError, IntoPipelineData};
use nu_engine::CallExt;
use crate::js::JsClient;
use super::transformer;

#[derive(Clone)]
pub struct JsCommand {
    pub engine: JsClient,
}

impl Command for JsCommand {
    fn name(&self) -> &str {
        "js"
    }

    fn description(&self) -> &str {
        "Execute JavaScript code via the QuickJS Runtime."
    }

    fn signature(&self) -> Signature {
        Signature::build("js")
            .input_output_types(vec![(Type::Any, Type::String)])
            .optional("code", SyntaxShape::String, "JavaScript code to execute")
            .switch("harden", "Compile to native binary (Crystal Plane)", Some('z'))
            .category(Category::Custom("polyglot".into()))
    }

    fn run(
        &self,
        engine_state: &EngineState,
        _stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let code: Option<String> = call.opt(engine_state, _stack, 0)?;
        let mut harden = call.has_flag(engine_state, _stack, "harden")?;

        let mut code = if let Some(mut c) = code {
            if (c.ends_with(".js") || c.ends_with(".ts")) && std::path::Path::new(&c).exists() {
                 if let Ok(content) = std::fs::read_to_string(&c) {
                    c = content;
                 }
            }
            c
        } else {
            #[cfg(all(feature = "shell", not(any(target_os = "android", target_os = "ios"))))]
            {
                // Interactive Sub-REPL
                use rustyline::error::ReadlineError;
                use rustyline::DefaultEditor;

                println!("--- Nexus Sovereign Logic (JavaScript) ---");
                println!("Type 'exit' to return to nexus shell.");

                let mut rl = DefaultEditor::new().map_err(|e| crate::shell_err(
                    "REPL Error",
                    e.to_string(),
                    Some(call.head),
                    None,
                ))?;

                loop {
                    let readline = rl.readline("nexus [js]> ");
                    match readline {
                        Ok(line) => {
                            let line = line.trim();
                            if line.is_empty() { continue; }
                            if line == "exit" || line == "quit" { break; }

                            let _ = rl.add_history_entry(line);

                            // Transform TS if needed
                            let mut exec_code = line.to_string();
                            if transformer::is_likely_ts(&exec_code) {
                                if let Ok(js) = transformer::transform_ts_to_js(&exec_code) {
                                    exec_code = js;
                                }
                            }

                            match self.engine.execute(exec_code, call.head) {
                                Ok(val) => {
                                    let result = nu_cli::evaluate_commands(
                                        &nu_protocol::Spanned { item: "table".to_string(), span: call.head },
                                        &mut engine_state.clone(),
                                        &mut _stack.clone(),
                                        val.into_pipeline_data(),
                                        vec![],
                                        nu_cli::EvaluateCommandsOpts::default(),
                                    );
                                    if let Err(e) = result {
                                        eprintln!("❌ Rendering Error: {:?}", e);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("❌ Error: {:?}", e);
                                }
                            }
                        },
                        Err(ReadlineError::Interrupted) => {
                            println!("Interrupted");
                            break;
                        },
                        Err(ReadlineError::Eof) => {
                            break;
                        },
                        Err(err) => {
                            println!("Error: {:?}", err);
                            break;
                        }
                    }
                }
                return Ok(PipelineData::empty());
            }
            #[cfg(not(all(feature = "shell", not(any(target_os = "android", target_os = "ios")))))]
            {
                return Err(crate::shell_err(
                    "Interactive JS REPL not compiled",
                    "Pass a JS/TS snippet or file path, or rebuild with `--features shell`.",
                    Some(call.head),
                    None,
                ));
            }
        };

        if transformer::is_likely_ts(&code) {
            code = transformer::transform_ts_to_js(&code).map_err(|e| {
                crate::shell_err("TypeScript Transform Error", e.to_string(), Some(call.head), None)
            })?;
        }

        // Auto-AOT Heuristic: If code is complex (contains functions), force harden
        if !harden && code.contains("function") {
             // println!("DEBUG: Auto-Hardening Triggered (Heuristic: 'function' keyword found)");
             harden = true;
        }

        if harden {
            // 1. Crystal Inception: Run Porffor -> C
            // We set globalThis.file for better compiler diagnostics
            self.engine.execute("globalThis.file = 'input.js';".into(), call.head)?;

            // Step A: Module Execution (Use globalThis side-channel)
            let step1_js = format!(r#"// MODULE
                import {{ porffor_compile }} from 'porffor';
                let out = 'NO_OUTPUT';
                try {{
                    const res = porffor_compile({}, ['c']);
                    out = res.c || 'NO_C_gen';
                }} catch (e) {{
                    out = 'ERR: ' + e.toString() + '\\n' + e.stack;
                }}
                globalThis._nexus_c_out = out;
            "#, serde_json::to_string(&code).unwrap());
            
            // Execute module (ignore return value, but catch compilation error)
            self.engine.execute(step1_js, call.head)?;

            // Step B: Script Execution (Retrieve global)
            let step2_js = "globalThis._nexus_c_out".to_string();
            let result_val = self.engine.execute(step2_js, call.head)?;

            // Extract string from result
            let c_code = match result_val {
                 nu_protocol::Value::String { val, .. } => val,
                 _ => format!("UNEXPECTED_RET: {:?}", result_val),
            };

            if c_code.starts_with("NO_") || c_code.starts_with("ERR:") || c_code.starts_with("COMPILER_ERROR") {
                 return Err(crate::shell_err(
                    "Compilation Failed",
                    c_code,
                    Some(call.head),
                    None,
                ));
            }

            // 2. Crystalize: Compile C -> Binary
            let c_file = "nexus_crystal.c";
            let bin_file = "crystal.bin";
            // Embed the C runtime kernel
            let kernel_c = include_str!("../../src/c/NXs.c");
            let kernel_file = "kernel.c";
            // Embed the header
            let header_c = include_str!("../../src/c/NXs.h");
            let header_file = "NXs.h";

            std::fs::write(c_file, &c_code).map_err(|e| crate::shell_err(
                "IO Error",
                e.to_string(),
                Some(call.head),
                None,
            ))?;

            // Write the embedded kernel to disk
            std::fs::write(kernel_file, kernel_c).map_err(|e| crate::shell_err(
                "IO Error (Kernel)",
                e.to_string(),
                Some(call.head),
                None,
            ))?;

            // Write the embedded header to disk
            std::fs::write(header_file, header_c).map_err(|e| crate::shell_err(
                "IO Error (Header)",
                e.to_string(),
                Some(call.head),
                None,
            ))?;

            // Compile with clang/cc and link kernel.c
            let output = std::process::Command::new("cc")
                .arg(c_file)
                .arg(kernel_file)
                .arg("-o")
                .arg(bin_file)
                .arg("-I.") // Include current dir for headers if needed
                .arg("-lm")
                .output()
                .map_err(|e| crate::shell_err(
                    "Compiler Launch Failed",
                    e.to_string(),
                    Some(call.head),
                    None,
                ))?;

            if !output.status.success() {
                 let stderr = String::from_utf8_lossy(&output.stderr);
                 return Err(crate::shell_err(
                    "Native Compilation Failed",
                    stderr.to_string(),
                    Some(call.head),
                    None,
                ));
            }

            return Ok(nu_protocol::Value::string(
                format!("Crystalized: {} (Size: {} bytes)", bin_file, std::fs::metadata(bin_file).unwrap().len()),
                call.head
            ).into_pipeline_data());
        }

        Ok(self.engine.execute(code, call.head)?.into_pipeline_data())
    }
}
