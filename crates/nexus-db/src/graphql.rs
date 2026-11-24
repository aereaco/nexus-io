use anyhow::{anyhow, Result};
use serde_json::{json, Value as JsonValue};

use crate::NexusDb;

/// Lightweight GraphQL executor (`feature = "graphql"`, `DEFINE CONFIG GRAPHQL AUTO`)
/// translating GraphQL queries directly into `NexusDb` SurrealQL queries.
/// Supports: `{ table { field1 field2 } }` and `query { table(limit: 5) { id name } }`.
pub fn execute_graphql(db: &NexusDb, ns: &str, database: &str, query: &str) -> Result<JsonValue> {
    let trimmed = query.trim();
    let body = trimmed
        .strip_prefix("query")
        .unwrap_or(trimmed)
        .trim();
    let inner = body
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| anyhow!("GraphQL query must be wrapped in '{{ ... }}'"))?
        .trim();

    let open_brace = inner
        .find('{')
        .ok_or_else(|| anyhow!("GraphQL selection set missing '{{'"))?;
    let close_brace = inner
        .rfind('}')
        .ok_or_else(|| anyhow!("GraphQL selection set missing '}}'"))?;

    let header = inner[..open_brace].trim();
    let fields_raw = inner[open_brace + 1..close_brace].trim();

    // Parse optional `(limit: N)` on root field
    let (table, limit_clause) = if let Some(lp) = header.find('(') {
        let tb = header[..lp].trim();
        let args = header[lp + 1..].trim_end_matches(')').trim();
        let lim = args
            .strip_prefix("limit:")
            .and_then(|s| s.trim().parse::<usize>().ok())
            .map(|n| format!(" LIMIT {}", n))
            .unwrap_or_default();
        (tb, lim)
    } else {
        (header, String::new())
    };

    let fields: Vec<&str> = fields_raw
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .collect();
    let proj = if fields.is_empty() {
        "*".to_string()
    } else {
        fields.join(", ")
    };

    let surql = format!("SELECT {} FROM {}{};", proj, table, limit_clause);
    let rows = db.query_scoped(ns, database, &surql, vec![])?;
    let json_rows: Vec<JsonValue> = rows.iter().map(|r| r.to_json()).collect();

    Ok(json!({
        "data": {
            table: json_rows
        }
    }))
}
