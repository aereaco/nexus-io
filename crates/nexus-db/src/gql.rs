use anyhow::{anyhow, Result};

use crate::value::Value;
use crate::NexusDb;

/// ISO GQL (`feature = "gql"`, SurrealDB 4.0) pattern query executor.
/// Translates ISO GQL `MATCH (a:table1)-[:edge]->(b:table2) [WHERE a.field = 'val'] RETURN b.field`
/// directly onto `NexusDb`'s indexed graph traversal engine.
pub fn execute_gql(db: &NexusDb, ns: &str, database: &str, query: &str) -> Result<Vec<Value>> {
    let q = query.trim().trim_end_matches(';').trim();
    let rest = q
        .strip_prefix("MATCH")
        .or_else(|| q.strip_prefix("match"))
        .ok_or_else(|| anyhow!("ISO GQL query must start with MATCH"))?
        .trim();

    let (pattern_and_where, return_part) = split_kw_ci(rest, "RETURN")
        .ok_or_else(|| anyhow!("ISO GQL MATCH requires a RETURN clause"))?;

    let (pattern_part, where_opt) = match split_kw_ci(pattern_and_where, "WHERE") {
        Some((p, w)) => (p.trim(), Some(w.trim())),
        None => (pattern_and_where.trim(), None),
    };

    // Parse `(src_var:src_table)-[:edge]->(dst_var:dst_table)`
    let arrow_pos = pattern_part
        .find("->")
        .ok_or_else(|| anyhow!("ISO GQL pattern must contain '->'"))?;
    let dash_pos = pattern_part[..arrow_pos]
        .find("-[")
        .ok_or_else(|| anyhow!("ISO GQL pattern must contain '-[:edge]->'"))?;

    let src_node = pattern_part[..dash_pos].trim();
    let edge_part = pattern_part[dash_pos + 2..arrow_pos]
        .trim()
        .trim_end_matches(']');
    let dst_node = pattern_part[arrow_pos + 2..].trim();

    let (src_var, src_table) = parse_gql_node(src_node)?;
    let edge = edge_part
        .split(':')
        .nth(1)
        .unwrap_or(edge_part)
        .trim()
        .to_string();
    let (dst_var, dst_table) = parse_gql_node(dst_node)?;

    // Parse projection field (e.g. `b.name` -> `.name`)
    let ret_clean = return_part.trim();
    let tail_field = ret_clean
        .strip_prefix(&format!("{}.", dst_var))
        .map(|f| format!(".{}", f.trim()))
        .unwrap_or_default();

    // Translate optional WHERE `a.name = 'Alice'` -> `WHERE name = 'Alice'`
    let where_sql = if let Some(w) = where_opt {
        let rewritten = w.replace(&format!("{}.", src_var), "");
        format!(" WHERE {}", rewritten)
    } else {
        String::new()
    };

    let surql = format!(
        "SELECT VALUE ->{}->{}{} FROM {}{};",
        edge, dst_table, tail_field, src_table, where_sql
    );
    let rows = db.query_scoped(ns, database, &surql, vec![])?;

    // Flatten array of arrays returned by per-node traversal
    let mut flat = Vec::new();
    for r in rows {
        match r {
            Value::Array(items) => flat.extend(items),
            other => flat.push(other),
        }
    }
    Ok(flat)
}

fn parse_gql_node(s: &str) -> Result<(String, String)> {
    let inner = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .ok_or_else(|| anyhow!("Invalid GQL node '{}'", s))?
        .trim();
    let (var, tb) = inner
        .split_once(':')
        .ok_or_else(|| anyhow!("GQL node '{}' must specify label (var:table)", s))?;
    Ok((var.trim().to_string(), tb.trim().to_string()))
}

fn split_kw_ci<'a>(s: &'a str, kw: &str) -> Option<(&'a str, &'a str)> {
    let upper = s.to_ascii_uppercase();
    let needle = format!(" {} ", kw);
    let idx = upper.find(&needle)?;
    Some((&s[..idx], &s[idx + needle.len()..]))
}
