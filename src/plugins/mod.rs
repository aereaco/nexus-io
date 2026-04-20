/// Plugin system foundation for Nexus-IO
/// 
/// Provides registry and installer for Nu plugins

use nu_protocol::engine::{EngineState, StateWorkingSet};
use miette::Result;

mod registry;

// mod registry;

/// Register plugin system commands
pub fn register(engine_state: &mut EngineState) -> Result<()> {
    let mut working_set = StateWorkingSet::new(engine_state);
    
    // Register nexus plugin commands
    working_set.add_decl(Box::new(registry::NexusPluginInstallCommand));
    working_set.add_decl(Box::new(registry::NexusPluginListCommand));
    
    working_set.render();
    
    Ok(())
}
