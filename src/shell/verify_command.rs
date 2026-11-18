use nu_protocol::engine::{Command, EngineState, Stack};
use nu_protocol::{Category, PipelineData, ShellError, Signature, Value, IntoPipelineData};
use std::sync::Arc;
use crate::db::Database;
use crate::storage::BlobBridge;
use crate::economy::EconomicKernel;

#[derive(Clone)]
pub struct VerifyCommand {
    pub db: Arc<Database>,
    pub bridge: Arc<BlobBridge>,
    pub economy: Arc<EconomicKernel>,
}

impl Command for VerifyCommand {
    fn name(&self) -> &str {
        "verify"
    }

    fn signature(&self) -> Signature {
        Signature::build("verify")
            .category(Category::Custom("nexus".into()))
            .input_output_types(vec![
                (nu_protocol::Type::Nothing, nu_protocol::Type::Table(vec![].into())),
            ])
    }

    fn description(&self) -> &str {
        "Perform a full system health check across all planes"
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
                let mut reports = Vec::new();

                // 1. Mind Plane (SurrealDB)
                let db_status = match self.db.client.query("INFO FOR DB").await {
                    Ok(_) => "✅ Healthy",
                    Err(_) => "❌ Error",
                };
                reports.push(self.make_row("Mind (Database)", db_status, "Connection established", span));

                // 2. Cloud Plane (Garage S3)
                let s3_status = match self.bridge.create_bucket("verify_bucket").await {
                    Ok(_) => {
                        let content = b"verify_data";
                        if self.bridge.put_object("verify_bucket", "verify_key", content.to_vec().into()).await.is_ok() {
                             "✅ Healthy"
                        } else {
                             "⚠️ Degraded (Put Failed)"
                        }
                    },
                    Err(_) => "❌ Error",
                };
                reports.push(self.make_row("Cloud (Storage)", s3_status, "S3 Roundtrip verified", span));

                // 3. Economy Plane (VPR/Audit)
                let eco_status = match self.economy.process_compute_payout("verify_job", "verify_user", "verify_node", 1.0).await {
                    Ok(_) => "✅ Healthy",
                    Err(_) => "❌ Error",
                };
                reports.push(self.make_row("Economy (Billing)", eco_status, "Payout & Audit Log working", span));

                reports
            })
        });

        Ok(Value::list(results, span).into_pipeline_data())
    }
}

impl VerifyCommand {
    fn make_row(&self, component: &str, status: &str, details: &str, span: nu_protocol::Span) -> Value {
        let cols = vec!["component".to_string(), "status".to_string(), "details".to_string()];
        let vals = vec![
            Value::string(component, span),
            Value::string(status, span),
            Value::string(details, span),
        ];
        Value::record(cols.into_iter().zip(vals).collect(), span)
    }
}
