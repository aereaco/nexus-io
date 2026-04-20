use nu_engine::CallExt;
use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, ShellError, Signature, SyntaxShape, Value, IntoPipelineData};
use std::sync::Arc;
use crate::compute::{InferenceRouter, ComputeRequirements};
use crate::db::Database;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ComputeRunCommand {
    pub db: Arc<Database>,
    pub economy: Arc<crate::economy::EconomicKernel>,
}

impl Command for ComputeRunCommand {
    fn name(&self) -> &str {
        "compute run"
    }

    fn signature(&self) -> Signature {
        Signature::build("compute run")
            .category(Category::Custom("nexus".into()))
            .required("job_type", SyntaxShape::String, "Type of job (e.g. inference, batch)")
            .named("cpu", SyntaxShape::Int, "Minimum CPU cores", Some('c'))
            .named("ram", SyntaxShape::Int, "Minimum RAM (MB)", Some('r'))
            .named("vram", SyntaxShape::Int, "Minimum VRAM (MB)", Some('g'))
            .input_output_types(vec![
                (nu_protocol::Type::Nothing, nu_protocol::Type::Record(vec![].into())),
            ])
    }

    fn description(&self) -> &str {
        "Schedule and dispatch a compute job to the mesh"
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &nu_protocol::engine::Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        
        let job_type: String = call.req(engine_state, stack, 0)?;
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

                if let Ok(mut resp) = self.db.client.query("SELECT * FROM peer_registry").await {
                    let results: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
                    for val in results {
                        if let Ok(record) = serde_json::from_value::<crate::compute::PeerRecord>(val) {
                            // Remote peers are routing targets
                            if !record.is_local {
                                peers.push(crate::storage::wireguard::PeerConfig {
                                    public_key: record.pubkey.clone(),
                                    endpoint: record.endpoint,
                                    _allowed_ips: vec![],
                                });
                            }

                            // Project capacity state
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
                // 3. Monetization: Calculate cost and process payout
                let pricing = crate::economy::vpr::PricingService::new(Default::default());
                let cost = pricing.estimate_compute_cost(&job_type, 3600); // Assume 1 hour for PoC
                
                let economy = self.economy.clone();
                let job_id = format!("job_{}", rand::random::<u16>());
                let job_id_clone = job_id.clone();
                let node_id = peer.public_key.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = economy.process_compute_payout(
                        &job_id_clone,
                        "user_poc", // Mock user
                        &node_id,
                        cost
                    ).await {
                        eprintln!("❌ Monetization Error: {}", e);
                    }
                });

                let cols = vec![
                    "status".to_string(), 
                    "job_id".to_string(),
                    "target_node".to_string(),
                    "message".to_string()
                ];
                let vals = vec![
                    Value::string("dispatched", span),
                    Value::string(job_id, span),
                    Value::string(peer.public_key.clone(), span),
                    Value::string(format!("Job '{}' scheduled. Cost: {:.4} ZA. Monetization audit active.", job_type, cost), span),
                ];
                Ok(Value::record(cols.into_iter().zip(vals).collect(), span).into_pipeline_data())
            },
            None => {
                let cols = vec!["status".to_string(), "error".to_string()];
                let vals = vec![
                    Value::string("failed", span),
                    Value::string("Capacity overflow: No nodes available meeting requirements.", span),
                ];
                Ok(Value::record(cols.into_iter().zip(vals).collect(), span).into_pipeline_data())
            }
        }
    }
}
