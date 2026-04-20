use nu_protocol::engine::{EngineState, Stack};
use nu_protocol::PipelineData;
use miette::Result;

pub const BANNER: &str = r#"
    ⬢  N E X U S - I O
    Platform Shell v0.1.0
    
    Type 'help' to get started
"#;

/// Apply Nexus-IO branding to Nushell
pub fn apply_config(engine_state: &mut EngineState, stack: &mut Stack) -> Result<()> {
    // Load custom prompt, theme, and config
    // This will source the .nu config files from config/
    
    // Set Nexus-IO environment variables
    std::env::set_var("NEXUS_IO_VERSION", "0.1.0");
    std::env::set_var("NEXUS_IO_HOME", get_nexus_home()?);
    
    // Disable default Nushell banner to prevent "banner command not found" error
    // since we print our own branding banner in main.rs.
    // We use eval_source for a Nushell-native way to update config.
    nu_cli::eval_source(
        engine_state,
        stack,
        b"$env.config.show_banner = false",
        "branding",
        PipelineData::empty(),
        false
    );
    
    Ok(())
}

fn get_nexus_home() -> Result<String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|e| miette::miette!("Could not determine home directory: {}", e))?;
    
    Ok(format!("{}/.nexus", home))
}
