use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, Signature, SyntaxShape, Type, ShellError, IntoPipelineData, Value as NuValue, Span};
use nu_engine::CallExt;
use std::sync::Arc;
use crate::db::Database;

#[derive(Clone)]
pub struct SqlCommand {
    pub db: Arc<Database>,
}

impl Command for SqlCommand {
    fn name(&self) -> &str {
        "sql"
    }
    
    fn description(&self) -> &str {
        "Execute SurrealQL query."
    }

    fn signature(&self) -> Signature {
        Signature::build("sql")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .optional("query", SyntaxShape::String, "SurrealQL Query to execute")
            .category(Category::Custom("polyglot".into()))
    }

    fn run(
        &self,
        engine_state: &EngineState,
        _stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let query: Option<String> = call.opt(engine_state, _stack, 0)?;
        
        let query = if let Some(q) = query {
            q
        } else {
            #[cfg(all(feature = "ops-shell", not(any(target_os = "android", target_os = "ios"))))]
            {
                // Interactive Sub-REPL
                use rustyline::error::ReadlineError;
                use rustyline::DefaultEditor;

                println!("--- Nexus Mind Plane (SurrealQL) ---");
                println!("Type 'exit' to return to nexus shell.");

                let mut rl = DefaultEditor::new().map_err(|e| crate::shell_err(
                    "REPL Error",
                    e.to_string(),
                    Some(call.head),
                    None,
                ))?;

                loop {
                    let readline = rl.readline("nexus [sql]> ");
                    match readline {
                        Ok(line) => {
                            let line = line.trim();
                            if line.is_empty() { continue; }
                            if line == "exit" || line == "quit" { break; }

                            let _ = rl.add_history_entry(line);

                            // Execute query
                            let db = self.db.clone();
                            let result = tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(async move {
                                    db.client.query(line).await
                                })
                            });

                            match result {
                                Ok(response) => {
                                    let val = response.take_values();
                                    if !val.is_empty() {
                                        let nu_list: Vec<NuValue> = val
                                            .into_iter()
                                            .map(|v| map_db_to_nu(v, call.head))
                                            .collect();
                                        let table_val = NuValue::list(nu_list, call.head);

                                        let _ = nu_cli::evaluate_commands(
                                            &nu_protocol::Spanned { item: "table".to_string(), span: call.head },
                                            &mut engine_state.clone(),
                                            &mut _stack.clone(),
                                            table_val.into_pipeline_data(),
                                            vec![],
                                            nu_cli::EvaluateCommandsOpts::default(),
                                        );
                                    } else {
                                        println!("[]");
                                    }
                                },
                                Err(e) => eprintln!("âŒ System Error: {}", e),
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
            #[cfg(not(all(feature = "ops-shell", not(any(target_os = "android", target_os = "ios")))))]
            {
                return Err(crate::shell_err(
                    "Interactive SQL REPL not compiled",
                    "Pass an inline query argument or rebuild with `--features shell`.",
                    Some(call.head),
                    None,
                ));
            }
        };

        // Capture pipeline input as Value
        let input_val = input.into_value(call.head)?;
        
        let should_bind_in = !matches!(input_val, NuValue::Nothing { .. });

        // We need to block on async DB call here because Command::run is sync
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                // Bind $in variable automatically using serde serialization of Value
                let mut q = self.db.client.query(&query);
                if should_bind_in {
                    // Convert NuValue to JSON Value for SurrealDB compatibility
                    let json_val = serde_json::to_value(input_val).unwrap_or(serde_json::Value::Null);
                    q = q.bind(("in", json_val));
                }
                q.await
            })
        });

        match result {
            Ok(response) => {
                let val = response.take_values();
                let pipeline_data = if val.is_empty() {
                    PipelineData::empty()
                } else {
                    let nu_list = val.into_iter().map(|v| map_db_to_nu(v, call.head)).collect();
                    NuValue::list(nu_list, call.head).into_pipeline_data()
                };
                Ok(pipeline_data)
            },
            Err(e) => {
                 Err(crate::shell_err(
                    "System Error",
                    e.to_string(),
                    Some(call.head),
                    None,
                ))
            }
        }
    }
}

fn map_db_to_nu(v: nexus_db::Value, span: Span) -> NuValue {
    match v {
        nexus_db::Value::None | nexus_db::Value::Null => NuValue::nothing(span),
        nexus_db::Value::Bool(b) => NuValue::bool(b, span),
        nexus_db::Value::Int(i) => NuValue::int(i, span),
        nexus_db::Value::Float(f) => NuValue::float(f, span),
        nexus_db::Value::String(s) | nexus_db::Value::DateTime(s) | nexus_db::Value::Decimal(s) => {
            NuValue::string(s, span)
        }
        nexus_db::Value::Duration(secs) => NuValue::string(format!("{}s", secs), span),
        nexus_db::Value::Bytes(b) => NuValue::binary(b, span),
        nexus_db::Value::RecordId { tb, id } => NuValue::string(format!("{}:{}", tb, id), span),
        nexus_db::Value::Array(arr) => {
            let vals = arr.into_iter().map(|x| map_db_to_nu(x, span)).collect();
            NuValue::list(vals, span)
        }
        nexus_db::Value::Object(obj) => {
            let records: Vec<(String, NuValue)> = obj
                .into_iter()
                .map(|(k, v)| (k, map_db_to_nu(v, span)))
                .collect();
            NuValue::record(records.into_iter().collect(), span)
        }
    }
}
