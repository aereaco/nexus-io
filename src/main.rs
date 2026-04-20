mod js;
mod surreal;
mod plugins;
mod branding;

use nu_protocol::engine::Stack;
use nu_protocol::{Value, Span};
use miette::Result;

fn main() -> Result<()> {
    nu_command::tls::CRYPTO_PROVIDER.default();

    let mut engine_state = nu_cmd_lang::create_default_context();
    let mut stack = Stack::new();
    
    engine_state = nu_command::add_shell_command_context(engine_state);
    engine_state = nu_cmd_extra::add_extra_command_context(engine_state);
    
    // Register Nexus-IO core integrations
    js::register(&mut engine_state)?;
    surreal::register(&mut engine_state)?;
    plugins::register(&mut engine_state)?;
    
    // Manually register core commands that might be missing from default contexts
    {
        let mut working_set = nu_protocol::engine::StateWorkingSet::new(&engine_state);
        working_set.add_decl(Box::new(nu_cli::Print));
        engine_state.merge_delta(working_set.render())?;
    }
    
    for (name, val) in std::env::vars() {
        if name == "PATH" {
            let path_list: Vec<Value> = std::env::split_paths(&val)
                .map(|p| Value::string(p.to_string_lossy().to_string(), Span::unknown()))
                .collect();
            engine_state.add_env_var(name, Value::list(path_list, Span::unknown()));
        } else {
            engine_state.add_env_var(name, Value::string(val, Span::unknown()));
        }
    }

    if engine_state.get_env_var("PWD").is_none() {
        if let Ok(cwd) = std::env::current_dir() {
            engine_state.add_env_var("PWD".into(), Value::string(cwd.to_string_lossy(), Span::unknown()));
        }
    }
    
    branding::apply_config(&mut engine_state, &mut stack)?;
    
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 {
        let positional_args = &args[1..];
        let first_arg = &positional_args[0];

        if first_arg == "-c" || first_arg == "--command" {
            if args.len() > 2 {
                let cmd = args[2].clone();
                let input = nu_protocol::PipelineData::empty();
                nu_cli::eval_source(&mut engine_state, &mut stack, cmd.as_bytes(), "command line", input, false);
            } else {
                eprintln!("Error: -c requires arg");
                std::process::exit(1);
            }
        } else {
            let command = positional_args.join(" ");
            let input = nu_protocol::PipelineData::empty();
            nu_cli::eval_source(&mut engine_state, &mut stack, command.as_bytes(), "command line", input, false);
        }
    } else {
        println!("{}", branding::BANNER);
        nu_cli::evaluate_repl(&mut engine_state, stack, None, None, std::time::Instant::now())?;
    }
    Ok(())
}
