use anyhow::Result;
#[cfg(feature = "ops-shell")]
use nu_engine::CallExt;
#[cfg(feature = "ops-shell")]
use nu_protocol::engine::{Call, Command, EngineState, Stack};
#[cfg(feature = "ops-shell")]
use nu_protocol::{Category, PipelineData, ShellError, Signature, SyntaxShape, Value};
use std::collections::HashMap;
#[cfg(feature = "ops-shell")]
use std::sync::Arc;

#[cfg(feature = "runtime-wasm")]
use crate::compute::crystal::CrystalEngine;
use crate::db::sql_compiler::compile_sqlite_to_surql;
#[cfg(feature = "ops-shell")]
use crate::db::Database;
use crate::db::StateEngine;
use crate::js::cell::{CellManager, CellPolicy};
#[cfg(feature = "ops-shell")]
use crate::storage::BlobBridge;

/// Declarative backend `SystemNode` parsed from a Markdown (`.md`) service file.
#[derive(Debug, Clone)]
pub struct SystemNode {
    pub name: String,
    pub app: String,
    pub cell_id: String,
    pub policy: CellPolicy,
    pub signals: HashMap<String, String>,
    pub sql_blocks: Vec<String>,
    pub surql_blocks: Vec<String>,
    pub script_blocks: Vec<String>,
    /// Inline WebAssembly Text (`wat`) Crystal blocks (compiled via `CrystalEngine`).
    pub wat_blocks: Vec<String>,
    /// External pre-compiled `.wasm` / `.cwasm` artifact URIs (from Rust, Zig, Go, C, AssemblyScript).
    pub wasm_refs: Vec<String>,
}

/// Parse a declarative Markdown service document into typed `SystemNode`s.
/// Supports:
/// - Frontmatter (`app`, `cell_id`, `policy: pinned | elastic | mobile`)
/// - `## ServiceName` section headers
/// - Fenced `ts` / `js` blocks (executable cell logic)
/// - Fenced `sql` (SQLite) and `surql` (SurrealQL) blocks
/// - Fenced `json` / `yaml` blocks (`data-signal` state declarations)
pub fn parse_markdown_nodes(md: &str) -> Vec<SystemNode> {
    let mut app = "default_app".to_string();
    let mut default_policy = CellPolicy::elastic_default();
    let mut default_cell_id: Option<String> = None;

    let lines: Vec<&str> = md.lines().collect();
    let mut i = 0usize;

    // 1. Optional YAML frontmatter
    if lines.first().map(|l| l.trim()) == Some("---") {
        i = 1;
        while i < lines.len() && lines[i].trim() != "---" {
            if let Some((k, v)) = lines[i].split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().trim_matches(|c| c == '"' || c == '\'');
                match key.as_str() {
                    "app" => app = val.to_string(),
                    "cell_id" => default_cell_id = Some(val.to_string()),
                    "policy" => {
                        default_policy = match val.to_ascii_lowercase().as_str() {
                            "pinned" => CellPolicy::Pinned,
                            "mobile" => CellPolicy::elastic_mobile(),
                            _ => CellPolicy::elastic_default(),
                        };
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        if i < lines.len() {
            i += 1;
        }
    }

    let mut nodes: Vec<SystemNode> = Vec::new();
    let mut current: Option<SystemNode> = None;

    while i < lines.len() {
        let line = lines[i].trim();

        // 2. `## Header` starts a new SystemNode
        if let Some(title) = line.strip_prefix("## ") {
            if let Some(node) = current.take() {
                nodes.push(node);
            }
            let name = title.trim().to_string();
            let slug: String = name
                .to_ascii_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            current = Some(SystemNode {
                name,
                app: app.clone(),
                cell_id: default_cell_id.clone().unwrap_or(slug),
                policy: default_policy.clone(),
                signals: HashMap::new(),
                sql_blocks: Vec::new(),
                surql_blocks: Vec::new(),
                script_blocks: Vec::new(),
                wat_blocks: Vec::new(),
                wasm_refs: Vec::new(),
            });
            i += 1;
            continue;
        }

        // 2b. Optional per-node policy override comment: `<!-- policy: pinned|elastic|mobile -->`
        if let Some(inner) = line
            .strip_prefix("<!--")
            .and_then(|s| s.strip_suffix("-->"))
        {
            if let Some((k, v)) = inner.trim().split_once(':') {
                if k.trim().eq_ignore_ascii_case("policy") {
                    if let Some(node) = current.as_mut() {
                        node.policy = match v.trim().to_ascii_lowercase().as_str() {
                            "pinned" => CellPolicy::Pinned,
                            "mobile" => CellPolicy::elastic_mobile(),
                            _ => CellPolicy::elastic_default(),
                        };
                    }
                    i += 1;
                    continue;
                }
            }
        }

        // 3. Fenced code block
        if let Some(fence_info) = line.strip_prefix("```") {
            let mut fence_parts = fence_info.split_whitespace();
            let lang = fence_parts.next().unwrap_or("").to_ascii_lowercase();
            let fence_rest: Vec<&str> = fence_parts.collect();
            i += 1;
            let mut block = Vec::new();
            while i < lines.len() && !lines[i].trim().starts_with("```") {
                block.push(lines[i]);
                i += 1;
            }
            if i < lines.len() {
                i += 1;
            }
            let content = block.join("\n");

            let node = current.get_or_insert_with(|| SystemNode {
                name: "root".to_string(),
                app: app.clone(),
                cell_id: default_cell_id.clone().unwrap_or_else(|| "root".to_string()),
                policy: default_policy.clone(),
                signals: HashMap::new(),
                sql_blocks: Vec::new(),
                surql_blocks: Vec::new(),
                script_blocks: Vec::new(),
                wat_blocks: Vec::new(),
                wasm_refs: Vec::new(),
            });

            match lang.as_str() {
                "ts" | "typescript" | "js" | "javascript" => node.script_blocks.push(content),
                "sql" | "sqlite" => node.sql_blocks.push(content),
                "surql" | "surrealql" => node.surql_blocks.push(content),
                "wat" => node.wat_blocks.push(content),
                "wasm" | "cwasm" => {
                    // Extract `src="..."` attribute from fence info or non-empty body line
                    let src_attr = fence_rest.iter().find_map(|tok| {
                        tok.strip_prefix("src=")
                            .map(|v| v.trim_matches(|c| c == '"' || c == '\'').to_string())
                    });
                    if let Some(uri) = src_attr {
                        node.wasm_refs.push(uri);
                    } else if !content.trim().is_empty() {
                        node.wasm_refs.push(content.trim().to_string());
                    }
                }
                "json" | "yaml" | "yml" => {
                    let key = format!("signal_{}", node.signals.len());
                    node.signals.insert(key, content);
                }
                _ => {}
            }
            continue;
        }

        i += 1;
    }

    if let Some(node) = current {
        nodes.push(node);
    }

    nodes
}

/// Deploy all `SystemNode`s parsed from a Markdown file into `CellManager` and `StateEngine`.
pub async fn deploy_markdown(
    manager: &CellManager,
    engine: &dyn StateEngine,
    md_source: &str,
) -> Result<Vec<SystemNode>> {
    let nodes = parse_markdown_nodes(md_source);

    for node in &nodes {
        // Execute declarative SQLite schema/seed blocks via AST compiler
        for sql in &node.sql_blocks {
            let compiled = compile_sqlite_to_surql(sql, vec![])?;
            engine
                .query_scoped(&node.app, &node.cell_id, &compiled.surql, compiled.bindings)
                .await?;
        }

        // Execute declarative SurrealQL blocks
        for surql in &node.surql_blocks {
            engine
                .query_scoped(&node.app, &node.cell_id, surql, vec![])
                .await?;
        }

        // Persist initial signals into cell KV
        for (k, v) in &node.signals {
            engine
                .kv_put(
                    &node.app,
                    &node.cell_id,
                    k,
                    nexus_db::Value::String(v.clone()),
                )
                .await?;
        }

        // Wake the cell with combined TS/JS script blocks
        let combined_script = node.script_blocks.join("\n");
        manager
            .wake(&node.app, &node.cell_id, node.policy.clone(), combined_script)
            .await?;
    }

    Ok(nodes)
}

/// Execute an exported `(i64, i64) -> i64` function from the first inline `wat` Crystal block
/// on a `SystemNode` via `CrystalEngine` (pre-compiled AOT + fuel metering).
#[cfg(all(feature = "runtime-wasm", not(target_os = "ios")))]
pub fn execute_node_crystal_i64(
    node: &SystemNode,
    fn_name: &str,
    a: i64,
    b: i64,
    fuel_limit: u64,
) -> Result<i64> {
    let wat = node
        .wat_blocks
        .first()
        .ok_or_else(|| anyhow::anyhow!("SystemNode '{}' has no inline `wat` Crystal block", node.name))?;
    let crystal = CrystalEngine::new()?;
    let aot = crystal.compile_aot(wat.as_bytes())?;
    crystal.run_aot_i64(&aot, fn_name, a, b, fuel_limit)
}

/// Nushell/CLI command: `cell deploy <path.md>` â€” deploys a declarative Markdown service file
/// onto `CellManager` and `StateEngine`.
#[cfg(feature = "ops-shell")]
#[derive(Clone)]
pub struct CellDeployCommand {
    pub db: Arc<Database>,
    pub bridge: Arc<BlobBridge>,
}

#[cfg(feature = "ops-shell")]
impl Command for CellDeployCommand {
    fn name(&self) -> &str {
        "cell deploy"
    }

    fn description(&self) -> &str {
        "Deploy a declarative Markdown (.md) service file into Nexus-IO cells"
    }

    fn signature(&self) -> Signature {
        Signature::build("cell deploy")
            .required("path", SyntaxShape::String, "Path to the .md service file")
            .category(Category::Custom("nexus".into()))
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;
        let path: String = call.req(engine_state, stack, 0)?;
        let md_source = std::fs::read_to_string(&path).map_err(|e| {
            crate::shell_err(
                "Cell Deploy IO Error",
                format!("Failed to read '{}': {}", path, e),
                Some(span),
                None,
            )
        })?;

        let db = self.db.clone();
        let bridge = self.bridge.clone();
        let nodes = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let manager = CellManager::new(db.clone(), bridge);
                deploy_markdown(&manager, db.as_ref(), &md_source).await
            })
        })
        .map_err(|e| {
            crate::shell_err(
                "Cell Deploy Error",
                e.to_string(),
                Some(span),
                None,
            )
        })?;

        let summary: Vec<String> = nodes
            .iter()
            .map(|n| format!("{}/{} ({})", n.app, n.cell_id, n.name))
            .collect();
        let msg = format!("âœ… Deployed {} cell(s): {}", nodes.len(), summary.join(", "));
        Ok(PipelineData::Value(Value::string(msg, span), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::storage::BlobBridge;
    use std::sync::Arc;

    #[test]
    fn deploys_and_executes_markdown_service_node() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let db = Arc::new(Database::open_mem());
                    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
                    let manager = CellManager::new(db.clone(), blobs);

                    let md = r#"---
app: semantic_demo
policy: elastic
---

## Counter Service

```surql
DEFINE TABLE IF NOT EXISTS metrics SCHEMALESS;
```

```js
function record(m) {
    ctx.storage.sql.exec("INSERT INTO metrics (label, val) VALUES (?, ?)", m.label, m.val);
    return ctx.storage.sql.exec("SELECT val FROM metrics").toArray().length;
}
```

```wat
(module
  (func (export "mul") (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.mul))
```

```wasm src="s3://crystals/pricing.wasm"
```
"#;

                    let nodes = deploy_markdown(&manager, db.as_ref(), md).await.unwrap();
                    assert_eq!(nodes.len(), 1);
                    assert_eq!(nodes[0].cell_id, "counter_service");
                    assert_eq!(nodes[0].wasm_refs, vec!["s3://crystals/pricing.wasm"]);

            #[cfg(all(feature = "runtime-wasm", not(target_os = "ios")))]
            {
                let prod = execute_node_crystal_i64(&nodes[0], "mul", 6, 7, 10_000).unwrap();
                assert_eq!(prod, 42);
            }
        });
    }
}
