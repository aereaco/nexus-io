pub mod kernel;

use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{PipelineData, Signature, ShellError};
use nu_engine::CallExt;
use std::sync::Arc;

use crate::iam::kernel::SecurityKernel;

#[derive(Clone)]
pub struct GuardedCommand {
    pub inner: Box<dyn Command>,
    pub kernel: Arc<SecurityKernel>,
}


impl Command for GuardedCommand {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    fn signature(&self) -> Signature {
        self.inner.signature()
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // 1. Get current user
        let username = std::env::var("USER").unwrap_or_else(|_| "guest".into());

        // 2. Collect arguments for content-based blocking
        // Use evaluator-agnostic CallExt to get arguments as strings
        let args: Vec<String> = call.rest(engine_state, stack, 0)?;

        // 3. Invoke SecurityKernel (Blocking check)
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                self.kernel.check_policy(username, self.inner.name(), args, call.head).await
            })
        })?;

        // 4. Delegate to Inner Command
        self.inner.run(engine_state, stack, call, input)
    }
}
