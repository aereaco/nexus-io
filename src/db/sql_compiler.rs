use anyhow::{anyhow, Result};
use nexus_db::Value as DbValue;

/// Supported relational SQL dialects (executed via Wasm guest DB engines in Nexus-IO).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    Sqlite,
    Postgres,
    Mysql,
}

/// Result of compiling a SQL statement into SurrealQL with named bindings.
#[derive(Debug, Clone)]
pub struct CompiledSql {
    pub surql: String,
    pub bindings: Vec<(String, DbValue)>,
}

/// Relational SQL dialects are executed via real Wasm DB guest engines (`CellDbMode::WasmEngine`)
/// rather than linking a native SQL transpiler into the host microkernel.
pub fn compile_sqlite_to_surql(sql: &str, args: Vec<DbValue>) -> Result<CompiledSql> {
    compile_sql_to_surql(SqlDialect::Sqlite, sql, args)
}

pub fn compile_sql_to_surql(
    dialect: SqlDialect,
    _sql: &str,
    _args: Vec<DbValue>,
) -> Result<CompiledSql> {
    Err(anyhow!(
        "Relational SQL ({:?}) is executed via a Wasm guest DB engine (`CellDbMode::WasmEngine`) in Nexus-IO; use SurrealQL/GraphQL/GQL directly on `nexus-db`",
        dialect
    ))
}

/// Execute a query against `nexus-db` in SurrealQL (always available) or optional
/// `db-graphql` / `db-gql` flavors.
pub fn execute_unified_query(
    db: &nexus_db::NexusDb,
    ns: &str,
    db_name: &str,
    flavor: &str,
    query: &str,
    _params: Vec<DbValue>,
    auth: Option<nexus_db::auth::AuthContext>,
) -> Result<serde_json::Value> {
    match flavor.trim().to_ascii_lowercase().as_str() {
        "" | "surql" | "surreal" | "surrealql" => {
            let rows = match auth {
                Some(ctx) => db.query_scoped_with_auth(ns, db_name, query, vec![], ctx)?,
                None => db.query_scoped(ns, db_name, query, vec![])?,
            };
            Ok(serde_json::Value::Array(
                rows.iter().map(DbValue::to_json).collect(),
            ))
        }
        #[cfg(feature = "db-graphql")]
        "graphql" => match auth {
            Some(ctx) => db.graphql_with_auth(ns, db_name, query, ctx),
            None => db.graphql(ns, db_name, query),
        },
        #[cfg(feature = "db-gql")]
        "gql" => {
            let rows = match auth {
                Some(ctx) => db.gql_with_auth(ns, db_name, query, ctx)?,
                None => db.gql(ns, db_name, query)?,
            };
            Ok(serde_json::Value::Array(
                rows.iter().map(DbValue::to_json).collect(),
            ))
        }
        other => Err(anyhow!(
            "Unsupported nexus-db query flavor '{}' (use surql, graphql [db-graphql], gql [db-gql], or mount a Wasm DB engine via `CellDbMode::WasmEngine`)",
            other
        )),
    }
}
