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
                            Ok(mut response) => {
                                let sur_value: surrealdb::Result<Vec<surrealdb::types::Value>> = response.take(0);
                                match sur_value {
                                    Ok(val) => {
                                        // Recursive mapper from SurrealDB Value -> NuValue
                                        fn map_sur_to_nu(v: surrealdb::types::Value, span: Span) -> NuValue {
                                            match v {
                                                surrealdb::types::Value::None | surrealdb::types::Value::Null => NuValue::nothing(span),
                                                surrealdb::types::Value::Bool(b) => NuValue::bool(b, span),
                                                surrealdb::types::Value::Number(n) => {
                                                    if let Some(i) = n.to_int() { NuValue::int(i, span) }
                                                    else if let Some(f) = n.to_f64() { NuValue::float(f, span) }
                                                    else { NuValue::string(format!("{:?}", n), span) }
                                                },
                                                surrealdb::types::Value::String(s) => NuValue::string(s, span),
                                                surrealdb::types::Value::RecordId(t) => NuValue::string(format!("{}:{:?}", t.table.as_str(), t.key), span),
                                                surrealdb::types::Value::Array(arr) => {
                                                    let vals = arr.into_iter().map(|x| map_sur_to_nu(x, span)).collect();
                                                    NuValue::list(vals, span)
                                                },
                                                surrealdb::types::Value::Object(obj) => {
                                                    let mut records = vec![];
                                                    for (k, v) in obj { records.push((k, map_sur_to_nu(v, span))); }
                                                    NuValue::record(records.into_iter().collect(), span)
                                                },
                                                _ => NuValue::string(format!("{:?}", v), span),
                                            }
                                        }

                                        if !val.is_empty() {
                                            let nu_list: Vec<NuValue> = val.into_iter().map(|v| map_sur_to_nu(v, call.head)).collect();
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
                                    Err(e) => eprintln!("❌ DB Error: {}", e),
                                }
                            },
                            Err(e) => eprintln!("❌ System Error: {}", e),
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
            Ok(mut response) => {
                // Use native SurrealDB types to avoid serialization errors with Record/Thing
                let sur_value: surrealdb::Result<Vec<surrealdb::types::Value>> = response.take(0);
                
                match sur_value {
                    Ok(val) => {
                         // Recursive mapper from SurrealDB Value -> NuValue
                         fn map_surreal_to_nu(v: surrealdb::types::Value, span: Span) -> NuValue {
                             match v {
                                 surrealdb::types::Value::None | surrealdb::types::Value::Null => NuValue::nothing(span),
                                 surrealdb::types::Value::Bool(b) => NuValue::bool(b, span),
                                 surrealdb::types::Value::Number(n) => {
                                     if let Some(i) = n.to_int() {
                                         NuValue::int(i, span)
                                     } else if let Some(f) = n.to_f64() {
                                         NuValue::float(f, span)
                                     } else {
                                         NuValue::string(format!("{:?}", n), span)
                                     }
                                 },
                                 surrealdb::types::Value::String(s) => NuValue::string(s, span),
                                 surrealdb::types::Value::RecordId(t) => NuValue::string(format!("{}:{:?}", t.table.as_str(), t.key), span),
                                 surrealdb::types::Value::Array(arr) => {
                                     let vals = arr.into_iter().map(|x| map_surreal_to_nu(x, span)).collect();
                                     NuValue::list(vals, span)
                                 },
                                 surrealdb::types::Value::Object(obj) => {
                                     let mut records = vec![];
                                     for (k, v) in obj {
                                         records.push((k, map_surreal_to_nu(v, span)));
                                     }
                                     NuValue::record(records.into_iter().collect(), span)
                                 },
                                 _ => NuValue::string(format!("{:?}", v), span),
                             }
                         }

                         let pipeline_data = if val.is_empty() {
                            PipelineData::empty()
                         } else {
                             let nu_list = val.into_iter().map(|v| map_surreal_to_nu(v, call.head)).collect();
                             NuValue::list(nu_list, call.head).into_pipeline_data()
                         };
                         
                         Ok(pipeline_data)
                    }
                    Err(e) => {
                        Err(crate::shell_err(
                            "Database Error",
                            e.to_string(),
                            Some(call.head),
                            None,
                        ))
                    }
                }
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
