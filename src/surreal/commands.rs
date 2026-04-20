/// Nushell commands for SurrealDB integration

use nu_engine::CallExt;
use nu_protocol::{
    engine::{Command, EngineState, Stack},
    Category, Example, PipelineData, ShellError, Signature, SyntaxShape, Type, Value, Span, IntoPipelineData
};
use surrealdb::{engine::local::Db, Surreal};
use reedline::{DefaultPrompt, Reedline, Signal};
use std::sync::{Arc, Mutex};
use crate::surreal::surreal_to_nu;

// Global DB connection
lazy_static::lazy_static! {
    static ref DB_CONNECTION: Arc<Mutex<Option<Surreal<Db>>>> = Arc::new(Mutex::new(None));
}

#[derive(Clone)]
pub struct SurrealCommand;

impl Command for SurrealCommand {
    fn name(&self) -> &str {
        "surreal"
    }

    fn signature(&self) -> Signature {
        Signature::build("surreal")
            .optional("query", SyntaxShape::String, "SurrealQL query to execute immediately")
            .named("conn", SyntaxShape::String, "Connection URL (default: memory)", Some('c'))
            .category(Category::Custom("nexus".into()))
            .input_output_types(vec![(Type::Any, Type::Any)])
    }

    fn description(&self) -> &str {
        "Execute SurrealQL or start an interactive SurrealDB REPL."
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let query: Option<String> = call.opt(engine_state, stack, 0)?;
        let conn_url: Option<String> = call.get_flag(engine_state, stack, "conn")?;
        let span = call.head;

        // Ensure connection
        ensure_connection(conn_url, span)?;

        if let Some(sql) = query {
            // Direct Execution
            execute_query(&sql, span)
        } else {
            // Interactive REPL
            run_repl(span)
                .map(|_| PipelineData::empty())
        }
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "Execute a query",
                example: r#"surreal "SELECT * FROM user""#,
                result: None,
            },
            Example {
                description: "Start interactive REPL",
                example: "surreal",
                result: None,
            },
        ]
    }
}

// Helper Functions

fn ensure_connection(url: Option<String>, span: Span) -> Result<(), ShellError> {
    let mut guard = DB_CONNECTION.lock().unwrap();
    
    if guard.is_none() {
        // Connect
        let db = pollster::block_on(async {
            let db = if let Some(_) = url {
                // TODO: Parse URL for file:// or memory
                Surreal::new::<surrealdb::engine::local::Mem>(()).await
            } else {
                Surreal::new::<surrealdb::engine::local::Mem>(()).await
            };
            
            match db {
                Ok(d) => {
                    let _ = d.use_ns("nexus").use_db("core").await;
                    Ok(d)
                },
                Err(e) => Err(e)
            }
        }).map_err(|e| ShellError::GenericError {
            error: "Failed to connect to SurrealDB".into(),
            msg: e.to_string(),
            span: Some(span),
            help: None,
            inner: vec![],
        })?;
        
        *guard = Some(db);
    }
    Ok(())
}

fn execute_query(sql: &str, span: Span) -> Result<PipelineData, ShellError> {
    let guard = DB_CONNECTION.lock().unwrap();
    let db = guard.as_ref().ok_or_else(|| ShellError::GenericError {
        error: "Not connected".into(),
        msg: "Database connection lost".into(),
        span: Some(span),
        help: None,
        inner: vec![],
    })?;
    
    let result = pollster::block_on(async {
        db.query(sql).await
    });
    
    match result {
        Ok(mut response) => {
            // Extract result
            let result: Vec<serde_json::Value> = response.take(0)
                .map_err(|e| ShellError::GenericError {
                    error: "SurrealDB Result Extraction Failed".into(),
                    msg: e.to_string(),
                    span: Some(span),
                    help: None,
                    inner: vec![],
                })?;
            
            // Convert each row to Nu Value
            let nu_rows: Vec<Value> = result.into_iter()
                .map(|row| surreal_to_nu(row, span))
                .collect();
            
            Ok(Value::list(nu_rows, span).into_pipeline_data())
        },
        Err(e) => Err(ShellError::GenericError {
            error: "Query execution error".into(),
            msg: e.to_string(),
            span: Some(span),
            help: None,
            inner: vec![],
        })
    }
}

fn run_repl(span: Span) -> Result<(), ShellError> {
    println!("Nexus-SurrealDB REPL");
    println!("Type 'exit' to quit");

    let mut line_editor = Reedline::create();
    let prompt = DefaultPrompt::default();

    loop {
        let sig = line_editor.read_line(&prompt);
        match sig {
            Ok(Signal::Success(buffer)) => {
                if buffer.trim() == "exit" {
                    break;
                }
                
                match execute_query(&buffer, span) {
                    Ok(PipelineData::Value(val, _)) => println!("{}", val.to_debug_string()),
                    Ok(_) => println!("<PipelineData>"),
                    Err(e) => println!("Error: {:?}", e),
                }
            }
            Ok(Signal::CtrlD) | Ok(Signal::CtrlC) => {
                break;
            }
            Err(e) => {
                println!("Error: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}
