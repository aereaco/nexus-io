use nu_engine::CallExt;
use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, ShellError, Signature, SyntaxShape, Value, IntoPipelineData};
use std::sync::Arc;
use crate::compute::{InferenceRouter, ComputeRequirements};
use crate::db::Database;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ComputeRouteCommand {
    pub db: Arc<Database>,
}

impl Command for ComputeRouteCommand {
    fn name(&self) -> &str {
        "compute route"
    }

    fn signature(&self) -> Signature {
        Signature::build("compute route")
            .category(Category::Custom("nexus".into()))
            .named("cpu", SyntaxShape::Int, "Minimum CPU cores", Some('c'))
            .named("ram", SyntaxShape::Int, "Minimum RAM (MB)", Some('r'))
            .named("vram", SyntaxShape::Int, "Minimum VRAM (MB)", Some('g'))
            .input_output_types(vec![
                (nu_protocol::Type::Nothing, nu_protocol::Type::Record(vec![].into())),
            ])
    }

    fn description(&self) -> &str {
        "Find the best node for a compute task"
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        
        // Parse args
        let min_cpu: i64 = call.get_flag(engine_state, stack, "cpu")?.unwrap_or(1);
        let min_ram: i64 = call.get_flag(engine_state, stack, "ram")?.unwrap_or(0);
        let min_vram: i64 = call.get_flag(engine_state, stack, "vram")?.unwrap_or(0);

        let req = ComputeRequirements {
            min_cpu: min_cpu as u32,
            min_ram_mb: min_ram as u64,
            min_vram_mb: min_vram as u64,
        };

        // Fetch Grid State (Fluid Object Projection)
        let (peers, resources) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut peers = Vec::new();
                let mut resources = HashMap::new();

                // Fetch all peers from DB (Object-Native Projection)
                if let Ok(mut resp) = self.db.client.query("SELECT * FROM peer_registry").await {
                    let results: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
                    for val in results {
                        if let Ok(record) = serde_json::from_value::<crate::compute::PeerRecord>(val) {
                            // Reconstruct PeerConfig for the router (remote peers only)
                            if !record.is_local {
                                peers.push(crate::storage::wireguard::PeerConfig {
                                    public_key: record.pubkey.clone(),
                                    endpoint: record.endpoint,
                                    _allowed_ips: vec![],
                                });
                            }

                            // Map resources for the routing engine
                            if let Some(res) = record.resources {
                                resources.insert(record.pubkey, res);
                            }
                        }
                    }
                }
                (peers, resources)
            })
        });

        let router = InferenceRouter::from_snapshot(resources);
        match router.select_node(&peers, &req) {
            Some(peer) => {
                let cols = vec!["status".to_string(), "node".to_string(), "endpoint".to_string()];
                let vals = vec![
                    Value::string("found", span),
                    Value::string(peer.public_key, span),
                    Value::string(peer.endpoint.unwrap_or("unknown".into()), span),
                ];
                Ok(Value::record(cols.into_iter().zip(vals).collect(), span).into_pipeline_data())
            },
            None => {
                let cols = vec!["status".to_string(), "error".to_string()];
                let vals = vec![
                    Value::string("not_found", span),
                    Value::string("No node meets requirements", span),
                ];
                Ok(Value::record(cols.into_iter().zip(vals).collect(), span).into_pipeline_data())
            }
        }
    }
}


