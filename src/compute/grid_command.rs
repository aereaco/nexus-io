use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, ShellError, Signature, Value, IntoPipelineData};
use std::sync::Arc;
use crate::db::Database;

#[derive(Clone)]
pub struct ComputeGridCommand {
    pub db: Arc<Database>,
}

impl Command for ComputeGridCommand {
    fn name(&self) -> &str {
        "compute grid"
    }

    fn signature(&self) -> Signature {
        Signature::build("compute grid")
            .category(Category::Custom("nexus".into()))
            .input_output_types(vec![
                (nu_protocol::Type::Nothing, nu_protocol::Type::Table(vec![].into())),
            ])
    }

    fn description(&self) -> &str {
        "View global telemetry and compute capacity of the mesh"
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;

        let results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut rows = Vec::new();

                // Fetch all peers (local and remote) to show the full grid (Object-Native)
                if let Ok(mut resp) = self.db.client.query("SELECT * FROM peer_registry").await {
                    let results: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
                    for val in results {
                        if let Ok(record) = serde_json::from_value::<crate::compute::PeerRecord>(val) {
                            let cols = vec![
                                "node".to_string(),
                                "endpoint".to_string(),
                                "role".to_string(),
                                "cpu".to_string(),
                                "ram_free".to_string(),
                                "gpus".to_string(),
                                "green".to_string(),
                            ];

                            let mut vals = vec![
                                Value::string(record.pubkey, span),
                                Value::string(record.endpoint.unwrap_or_else(|| "mesh".into()), span),
                                Value::string(if record.is_local { "local" } else { "remote" }, span),
                            ];

                            if let Some(res) = record.resources {
                                vals.push(Value::int(res.cpu_cores as i64, span));
                                vals.push(Value::filesize(res.memory_free as i64, span));
                                vals.push(Value::string(format!("{}", res.gpus.len()), span));
                                vals.push(Value::bool(res.is_green, span));
                            } else {
                                vals.push(Value::string("offline", span));
                                vals.push(Value::string("offline", span));
                                vals.push(Value::string("offline", span));
                                vals.push(Value::string("offline", span));
                            }

                            rows.push(Value::record(cols.into_iter().zip(vals).collect(), span));
                        }
                    }
                }
                rows
            })
        });

        Ok(Value::list(results, span).into_pipeline_data())
    }
}
