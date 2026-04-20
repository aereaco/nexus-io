/// QuickJS-NG integration module

pub mod commands;
pub mod core;
pub mod transformer;



use nu_protocol::engine::{EngineState, StateWorkingSet};
use miette::Result;

pub fn register(engine_state: &mut EngineState) -> Result<()> {
    let mut working_set = StateWorkingSet::new(engine_state);
    
    working_set.add_decl(Box::new(commands::JsCommand));
    
    engine_state.merge_delta(working_set.render())?;
    Ok(())
}
