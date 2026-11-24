use nexus_io::{compute, db, economy, iam, js, shell, storage, ux};

use std::sync::Arc;
use std::time::Instant;
use nu_protocol::engine::{StateWorkingSet, Stack};
use nu_cmd_lang::create_default_context;
use nu_command::add_shell_command_context;
use nu_protocol::{Value, Span};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let is_test = args.contains(&"--test".to_string());
    let launch_gui = args.contains(&"--gui".to_string())
        || std::env::var("NEXUS_GUI").as_deref() == Ok("1");
    let positional_args: Vec<String> = args.iter().skip(1).filter(|a| !a.starts_with("--")).cloned().collect();

    // 0. Native Device GUI Mode (`--gui` or `NEXUS_GUI=1`):
    // Spawns the embedded Nexus-IO gateway on a background thread and opens the OS-native WebView
    // (`WebView2` / `WKWebView` / `WebKitGTK`) on the main OS thread.
    if launch_gui {
        let mut cfg = ux::native_gui::NativeWindowConfig::default();
        if let Ok(url) = std::env::var("NEXUS_GUI_URL") {
            cfg.url = url;
        }
        std::thread::spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for GUI gateway");
            rt.block_on(async {
                let db = Arc::new(db::Database::init().await);
                let bridge = Arc::new(
                    storage::BlobBridge::new(db.clone())
                        .await
                        .expect("Failed to init storage bridge"),
                );
                let gw = ux::UxGateway::new(db, bridge, ux::GatewayConfig::default());
                let _ = gw.start().await;
            });
        });
        ux::native_gui::launch_native_window(cfg)?;
        return Ok(());
    }

    // 1. Hyper-Fast Fluid-First Short-Circuit (Sub-50ms Path)
    // If the task is JS and doesn't require the shared Data Plane, bypass Tokio/DB entirely
    // We also skip short-circuit if --harden is used, as that requires the full command logic
    if positional_args.len() >= 2 && positional_args[0] == "js" && !args.contains(&"--harden".to_string()) && !args.contains(&"-z".to_string()) {
        let mut code = positional_args[1..].join(" ");
        
        // Basic heuristic: if it doesn't mention 'db', 'sql' or 'require', it's likely a pure fluid task
        if !code.contains("db") && !code.contains("sql") && !code.contains("require") {
            // Check if code is a file and read it
            if (code.ends_with(".js") || code.ends_with(".ts")) && std::path::Path::new(&code).exists() {
                if let Ok(content) = std::fs::read_to_string(&code) {
                    code = content;
                }
            }

            // AUTO-AOT CHECK: If code is complex (contains 'function'), skip short-circuit 
            // and fall through to full runtime (JsCommand::run) which handles AOT compilation.
            if code.contains("function") {
                // Do not execute short-circuit.
            } else {

            // Render using a minimal logic context (no DB/IAM required)
            let mut engine_state = create_default_context();
            engine_state = add_shell_command_context(engine_state);
            let mut stack = Stack::new();
            let current_dir = std::env::current_dir().unwrap_or_else(|_| "/".into());
            let current_dir_nu = Value::string(current_dir.to_string_lossy(), Span::unknown());
            
            // Set PWD in both engine env and stack
            stack.add_env_var("PWD".to_string(), current_dir_nu.clone());
            engine_state.add_env_var("PWD".to_string(), current_dir_nu);

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let _guard = rt.enter();
            // Lazy load DB: Pass None initially. The JS runtime will fail if SQL is accessed.
            // This restores the "instant" JS runtime behavior.
            let result = match js::JsClient::oneshot_async_blocking(code, None, Span::unknown()) {
                Ok(v) => v,
                Err(e) => {
                    nu_protocol::report_shell_error(None, &engine_state, &e);
                    std::process::exit(1);
                }
            };
            
            #[cfg(all(feature = "shell", not(any(target_os = "android", target_os = "ios"))))]
            if let Err(e) = nu_cli::evaluate_commands(
                &nu_protocol::Spanned { item: "table".to_string(), span: nu_protocol::Span::unknown() },
                &mut engine_state,
                &mut stack,
                nu_protocol::PipelineData::Value(result, None),
                vec![],
                nu_cli::EvaluateCommandsOpts::default(),
            ) {
                 nu_protocol::report_shell_error(None, &engine_state, &e);
                 std::process::exit(1);
            }
            #[cfg(not(all(feature = "shell", not(any(target_os = "android", target_os = "ios")))))]
            {
                println!("{}", result.to_abbreviated_string(&nu_protocol::Config::default()));
            }
            return Ok(());
            } // End of else (implied by indentation, but explicit check needed)
        }
    }

    // 2. Full-Genesis Fallback (Tokio + SurrealDB + Identity)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
        
    rt.block_on(async_main(args, is_test))
}

async fn async_main(args: Vec<String>, is_test: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _start_time = Instant::now();
    // 2. Parallel Genesis (Full Planes for Complex Tasks)
    let db = Arc::new(db::Database::init().await);
    let js = js::JsClient::new(db.clone());
    let (_bridge, mut engine_state) = tokio::join!(
        async { 
            // We need a temporary DB handle for bridge init before the joint DB is ready, 
            // but Database::init() is async. 
            // Actually, BlobBridge needs the DB. So we must sequence this or use the DB after init.
            // Let's defer bridge init to after DB init.
            // Returning None for now in the join, will init after.
            let res: Option<Arc<storage::BlobBridge>> = None;
            res
        },
        async {
            let engine_state = create_default_context();
            add_shell_command_context(engine_state)
        }
    );
    
    // Now initialize the persistent bridge with the ready DB
    let bridge = Arc::new(storage::BlobBridge::new(db.clone()).await.expect("Failed to init storage bridge"));

    let kernel = Arc::new(iam::kernel::SecurityKernel::new(db.clone()));
    let economy = Arc::new(economy::EconomicKernel::new(db.clone()));
    
    // Initialize Mesh Network lazily (only when `vpn` feature is compiled AND `NEXUS_ENABLE_MESH=1`)
    #[cfg(feature = "vpn")]
    if std::env::var("NEXUS_ENABLE_MESH").as_deref() == Ok("1") {
        let db_clone = db.clone();
        let bridge_clone = bridge.clone();
        tokio::spawn(async move {
            match storage::WireGuardManager::init_mesh(db_clone.clone()).await {
                Ok(Some(interface)) => {
                    println!("✅ Mesh Interface Active. Starting Reactor...");
                    let reactor = Arc::new(storage::MeshReactor::new(
                        db_clone,
                        interface,
                        bridge_clone,
                    ));
                    reactor.start().await;
                }
                Ok(None) => {}
                Err(e) => eprintln!("⚠️  Mesh Initialization Warning: {}", e),
            }
        });
    }

    // 3. Presentation Plane (UX Gateway)
    let gateway_config = ux::GatewayConfig {
        enable_https: false, // Port 443 (Requires domain/cert)
        enable_http: true,   // Port 8080 (Dev redirect)
        ..Default::default()
    };
    
    let gateway = ux::UxGateway::new(db.clone(), bridge.clone(), gateway_config);
    tokio::spawn(async move {
        if let Err(e) = gateway.start().await {
            eprintln!("❌ UX Gateway Error: {}", e);
        }
    });

    let mut working_set = StateWorkingSet::new(&engine_state);
    
    // Guarded Commands with SecurityKernel
    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(js::command::JsCommand { engine: js.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(db::command::SqlCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    // Stub banner to fix REPL error
    #[derive(Clone)]
    struct BannerStub;
    impl nu_protocol::engine::Command for BannerStub {
        fn name(&self) -> &str { "banner" }
        fn description(&self) -> &str { "Nexus-IO Banner Stub" }
        fn signature(&self) -> nu_protocol::Signature { nu_protocol::Signature::build("banner") }
        fn run(&self, _: &nu_protocol::engine::EngineState, _: &mut nu_protocol::engine::Stack, _: &nu_protocol::engine::Call, _: nu_protocol::PipelineData) -> Result<nu_protocol::PipelineData, nu_protocol::ShellError> {
            Ok(nu_protocol::PipelineData::empty())
        }
    }
    working_set.add_decl(Box::new(BannerStub));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(shell::host::HostScanCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(shell::host::HostStorageCommand),
        kernel: kernel.clone(),
    }));
    
    // Storage commands (Garage + WireGuard)
    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StorageInitCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StorageStatusCommand),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StorageBucketCreateCommand { bridge: bridge.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StorageBucketListCommand { bridge: bridge.clone() }),
        kernel: kernel.clone(),
    }));

    // Object commands
    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StoragePutCommand { bridge: bridge.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StorageGetCommand { bridge: bridge.clone() }),
        kernel: kernel.clone(),
    }));
    
    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StoragePeerAddCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(storage::StoragePeerListCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    // Compute commands (Nexus-IO)
    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(compute::command::ComputeScanCommand),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(compute::route_command::ComputeRouteCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(compute::grid_command::ComputeGridCommand { db: db.clone() }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(compute::run_command::ComputeRunCommand { 
            db: db.clone(),
            economy: economy.clone(),
        }),
        kernel: kernel.clone(),
    }));

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(compute::md_runtime::CellDeployCommand {
            db: db.clone(),
            bridge: bridge.clone(),
        }),
        kernel: kernel.clone(),
    }));

    #[cfg(feature = "k8s-bridge")]
    {
        working_set.add_decl(Box::new(iam::GuardedCommand {
            inner: Box::new(compute::k8s_bridge::K8sImportCommand {
                db: db.clone(),
                bridge: bridge.clone(),
            }),
            kernel: kernel.clone(),
        }));

        working_set.add_decl(Box::new(iam::GuardedCommand {
            inner: Box::new(compute::k8s_bridge::K8sExportCommand),
            kernel: kernel.clone(),
        }));
    }

    working_set.add_decl(Box::new(iam::GuardedCommand {
        inner: Box::new(shell::verify_command::VerifyCommand { 
            db: db.clone(),
            bridge: bridge.clone(),
            economy: economy.clone(),
        }),
        kernel: kernel.clone(),
    }));




    
    let delta = working_set.render();
    let _ = engine_state.merge_delta(delta);
    let mut stack = Stack::new();
    let current_dir = std::env::current_dir()?;
    let current_dir_nu = Value::string(current_dir.to_string_lossy(), Span::unknown());
    
    // Set PWD in both engine env and stack
    stack.add_env_var("PWD".to_string(), current_dir_nu.clone());
    engine_state.add_env_var("PWD".to_string(), current_dir_nu);
    
    // Customize REPL Prompt
    stack.add_env_var(
        "PROMPT_INDICATOR".to_string(),
        Value::string("nexus> ".to_string(), Span::unknown())
    );
    stack.add_env_var(
        "PROMPT_INDICATOR_VI_INSERT".to_string(),
        Value::string(": ".to_string(), Span::unknown())
    );
    stack.add_env_var(
        "PROMPT_COMMAND".to_string(),
        Value::string("".to_string(), Span::unknown()) 
    );
    stack.add_env_var(
        "PROMPT_COMMAND_RIGHT".to_string(),
        Value::string("".to_string(), Span::unknown())
    );

    if is_test {
        println!(">> [Test] Verifying System-Native IAM Projection...");
        let mut response = db.client.query("SELECT VALUE username FROM user").await?;
        let users: Vec<String> = response.take(0)?;
        println!(">> [Test] Found {} system users projected into SurrealDB.", users.len());
        for user in users.iter().take(5) {
            println!("   - {}", user);
        }
        if users.len() > 5 { println!("   ... and {} more.", users.len() - 5); }
        
        if !users.is_empty() {
            println!(">> [Test] SUCCESS: System-Native Identity Verified.");
        } else {
            println!(">> [Test] FAIL: No users projected.");
        }
    }
    
    // We don't filter flags here because we want to pass flags like --harden to the commands
    let positional_args: Vec<String> = args.iter().skip(1).filter(|a| *a != "--test").cloned().collect();

    if !positional_args.is_empty() {
        let command = if (positional_args[0] == "sql" || positional_args[0] == "js") && positional_args.len() > 1 {
            // Separate optional flags (starting with -) from the query/code string
            let mut flags = Vec::new();
            let mut query_parts = Vec::new();
            
            for arg in &positional_args[1..] {
                if arg.starts_with("-") {
                    flags.push(arg.clone());
                } else {
                    query_parts.push(arg.clone());
                }
            }
            
            let query = query_parts.join(" ");
            let escaped = query.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$");
            
            let flags_str = if flags.is_empty() { String::new() } else { format!(" {}", flags.join(" ")) };
            format!("{}{} \"{}\"", positional_args[0], flags_str, escaped) 
        } else {
            positional_args.join(" ")
        };

        #[cfg(all(feature = "shell", not(any(target_os = "android", target_os = "ios"))))]
        {
            let command_spanned = nu_protocol::Spanned {
                item: command,
                span: nu_protocol::Span::unknown(),
            };
            let result = nu_cli::evaluate_commands(
                &command_spanned,
                &mut engine_state,
                &mut stack,
                nu_protocol::PipelineData::empty(),
                vec![],
                nu_cli::EvaluateCommandsOpts::default(),
            );

            if let Err(e) = result {
                nu_protocol::report_shell_error(None, &engine_state, &e);
                std::process::exit(1);
            }
        }
        #[cfg(not(all(feature = "shell", not(any(target_os = "android", target_os = "ios")))))]
        {
            let mut working_set = StateWorkingSet::new(&engine_state);
            let block = nu_parser::parse(&mut working_set, None, command.as_bytes(), false);
            if let Some(err) = working_set.parse_errors.first() {
                eprintln!("Parse error: {:?}", err);
                std::process::exit(1);
            }
            let _ = engine_state.merge_delta(working_set.render());
            match nu_engine::eval_block::<nu_protocol::debugger::WithoutDebug>(
                &engine_state,
                &mut stack,
                &block,
                nu_protocol::PipelineData::empty(),
            ) {
                Ok(out) => {
                    if let Ok(val) = out.body.into_value(nu_protocol::Span::unknown()) {
                        if !matches!(val, Value::Nothing { .. }) {
                            println!("{}", val.to_abbreviated_string(&nu_protocol::Config::default()));
                        }
                    }
                }
                Err(e) => {
                    nu_protocol::report_shell_error(None, &engine_state, &e);
                    std::process::exit(1);
                }
            }
        }
    } else {
        #[cfg(all(feature = "shell", not(any(target_os = "android", target_os = "ios"))))]
        {
            let result = nu_cli::evaluate_repl(
                &mut engine_state,
                stack,
                None, 
                None, 
            );

            if let Err(e) = result {
                eprintln!("REPL Error: {:?}", e);
                std::process::exit(1);
            }
        }
        #[cfg(not(all(feature = "shell", not(any(target_os = "android", target_os = "ios")))))]
        {
            println!(
                "🚀 Nexus-IO ({}) ready (headless profile — pass a command or rebuild with `--features shell` for interactive REPL).",
                nexus_io::runtime::CapabilityRegistry::active_profile()
            );
        }
    }

    Ok(())
}
