use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, ShellError, Signature, Value, IntoPipelineData};
use crate::compute::NodeResources;

#[derive(Clone)]
pub struct ComputeScanCommand;

impl Command for ComputeScanCommand {
    fn name(&self) -> &str {
        "compute scan"
    }

    fn signature(&self) -> Signature {
        Signature::build("compute scan")
            .category(Category::Custom("nexus".into()))
            .input_output_types(vec![
                (nu_protocol::Type::Nothing, nu_protocol::Type::Record(vec![].into())),
            ])
    }

    fn description(&self) -> &str {
        "Scan local hardware resources (CPU, RAM, GPU)"
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let resources = NodeResources::scan();
        
        let cols = vec![
            "cpu_cores".to_string(),
            "memory_total_mb".to_string(),
            "memory_free_mb".to_string(),
            "gpus".to_string(),
        ];
        
        let vals = vec![
            Value::int(resources.cpu_cores as i64, span),
            Value::filesize(resources.memory_total as i64, span),
            Value::filesize(resources.memory_free as i64, span),
            Value::string(format!("{:?}", resources.gpus), span),
        ];

        Ok(Value::record(cols.into_iter().zip(vals).collect(), span).into_pipeline_data())
    }
}



