/// SurrealDB plugin registration

use nu_protocol::engine::{EngineState, StateWorkingSet};
use miette::Result;

pub mod commands;
pub mod convert;

pub use convert::surreal_to_nu;

pub fn register(engine_state: &mut EngineState) -> Result<()> {
    let mut working_set = StateWorkingSet::new(engine_state);
    
    working_set.add_decl(Box::new(commands::SurrealCommand));
    
    engine_state.merge_delta(working_set.render())?;
    Ok(())
}
