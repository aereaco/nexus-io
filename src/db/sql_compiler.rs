use anyhow::{anyhow, Result};
use sqlparser::ast::{
    Assignment, AssignmentTarget, BinaryOperator, Expr, ObjectName, Query, SelectItem, SetExpr,
    Statement, TableFactor, Value as SqlValue, Values,
};
use sqlparser::dialect::{Dialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use nexus_db::Value as DbValue;

/// Supported relational SQL dialects compiled uniformly onto `nexus-db` via `sqlparser` AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    Sqlite,
    Postgres,
    Mysql,
}

/// Result of compiling a SQL statement (SQLite / PostgreSQL / MySQL) into SurrealQL with named bindings.
#[derive(Debug, Clone)]
pub struct CompiledSql {
    pub surql: String,
    pub bindings: Vec<(String, DbValue)>,
}

/// Compile SQLite SQL (`ctx.storage.sql.exec(sql, ...args)`) into SurrealQL via `sqlparser` AST.
pub fn compile_sqlite_to_surql(sql: &str, args: Vec<DbValue>) -> Result<CompiledSql> {
    compile_sql_to_surql(SqlDialect::Sqlite, sql, args)
}

/// Unified multi-dialect SQL → SurrealQL compiler (`Sqlite`, `Postgres`, `Mysql`).
pub fn compile_sql_to_surql(
    dialect: SqlDialect,
    sql: &str,
    args: Vec<DbValue>,
) -> Result<CompiledSql> {
    let trimmed = sql.trim();

    // Handle SQLite PRAGMA table_info(tbl) explicitly
    if trimmed.to_ascii_uppercase().starts_with("PRAGMA ") {
        let rest = trimmed[7..].trim().trim_end_matches(';');
        if let Some(inner) = rest
            .strip_prefix("table_info(")
            .or_else(|| rest.strip_prefix("TABLE_INFO("))
            .and_then(|s| s.strip_suffix(')'))
        {
            let tbl = inner.trim().trim_matches(|c| c == '\'' || c == '"' || c == '`');
            return Ok(CompiledSql {
                surql: format!("INFO FOR TABLE {};", tbl),
                bindings: vec![],
            });
        }
        return Ok(CompiledSql {
            surql: "RETURN [];".to_string(),
            bindings: vec![],
        });
    }

    let dialect_impl: Box<dyn Dialect> = match dialect {
        SqlDialect::Sqlite => Box::new(SQLiteDialect {}),
        SqlDialect::Postgres => Box::new(PostgreSqlDialect {}),
        SqlDialect::Mysql => Box::new(MySqlDialect {}),
    };
    let statements = Parser::parse_sql(dialect_impl.as_ref(), trimmed)
        .map_err(|e| anyhow!("{:?} SQL parse error: {}", dialect, e))?;

    let mut out_stmts = Vec::new();
    let mut param_idx = 0usize;
    let mut bindings = Vec::new();

    for stmt in statements {
        let compiled = compile_statement(&stmt, &args, &mut param_idx, &mut bindings)?;
        out_stmts.push(compiled);
    }

    Ok(CompiledSql {
        surql: out_stmts.join(" "),
        bindings,
    })
}

fn table_name(name: &ObjectName) -> String {
    name.0
        .last()
        .map(|p| p.to_string().trim_matches(|c| c == '"' || c == '`' || c == '\'').to_string())
        .unwrap_or_else(|| name.to_string())
}

fn compile_statement(
    stmt: &Statement,
    args: &[DbValue],
    param_idx: &mut usize,
    bindings: &mut Vec<(String, DbValue)>,
) -> Result<String> {
    match stmt {
        Statement::CreateTable(ct) => {
            let tbl = table_name(&ct.name);
            Ok(format!("DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;", tbl))
        }
        Statement::Drop { names, .. } => {
            let mut parts = Vec::new();
            for n in names {
                parts.push(format!("REMOVE TABLE IF EXISTS {};", table_name(n)));
            }
            Ok(parts.join(" "))
        }
        Statement::Insert(ins) => {
            let tbl = match &ins.table {
                sqlparser::ast::TableObject::TableName(name) => table_name(name),
                other => other.to_string(),
            };
            let cols: Vec<String> = ins.columns.iter().map(table_name).collect();
            let is_upsert = ins.or.is_some() || ins.on.is_some();
            let verb = if is_upsert { "UPSERT" } else { "CREATE" };

            let mut stmts = Vec::new();
            if let Some(source) = &ins.source {
                if let SetExpr::Values(Values { rows, .. }) = source.body.as_ref() {
                    for row in rows {
                        let mut assignments = Vec::new();
                        for (i, expr) in row.iter().enumerate() {
                            let col = cols
                                .get(i)
                                .cloned()
                                .unwrap_or_else(|| format!("col_{}", i));
                            let val_sql = compile_expr(expr, args, param_idx, bindings)?;
                            assignments.push(format!("{} = {}", col, val_sql));
                        }
                        stmts.push(format!("{} {} SET {};", verb, tbl, assignments.join(", ")));
                    }
                }
            }
            Ok(stmts.join(" "))
        }
        Statement::Query(q) => compile_query(q, args, param_idx, bindings),
        Statement::Update(upd) => {
            let tbl = match &upd.table.relation {
                TableFactor::Table { name, .. } => table_name(name),
                other => other.to_string(),
            };
            let mut sets = Vec::new();
            for Assignment { target, value } in &upd.assignments {
                let col = match target {
                    AssignmentTarget::ColumnName(name) => table_name(name),
                    other => other.to_string(),
                };
                let val_sql = compile_expr(value, args, param_idx, bindings)?;
                sets.push(format!("{} = {}", col, val_sql));
            }
            let mut sql = format!("UPDATE {} SET {}", tbl, sets.join(", "));
            if let Some(sel) = &upd.selection {
                sql.push_str(&format!(
                    " WHERE {}",
                    compile_expr(sel, args, param_idx, bindings)?
                ));
            }
            sql.push(';');
            Ok(sql)
        }
        Statement::Delete(del) => {
            let tbl = match &del.from {
                sqlparser::ast::FromTable::WithFromKeyword(tables)
                | sqlparser::ast::FromTable::WithoutKeyword(tables) => tables
                    .first()
                    .map(|t| match &t.relation {
                        TableFactor::Table { name, .. } => table_name(name),
                        other => other.to_string(),
                    })
                    .ok_or_else(|| anyhow!("DELETE missing target table"))?,
            };
            let mut sql = format!("DELETE {}", tbl);
            if let Some(sel) = &del.selection {
                sql.push_str(&format!(
                    " WHERE {}",
                    compile_expr(sel, args, param_idx, bindings)?
                ));
            }
            sql.push(';');
            Ok(sql)
        }
        other => Err(anyhow!("Unsupported SQLite statement in SurrealQL adapter: {}", other)),
    }
}

fn compile_query(
    q: &Query,
    args: &[DbValue],
    param_idx: &mut usize,
    bindings: &mut Vec<(String, DbValue)>,
) -> Result<String> {
    let SetExpr::Select(sel) = q.body.as_ref() else {
        return Err(anyhow!("Only SELECT queries are supported in SQLite adapter"));
    };

    let proj: Vec<String> = sel
        .projection
        .iter()
        .map(|item| match item {
            SelectItem::Wildcard(_) => Ok("*".to_string()),
            SelectItem::UnnamedExpr(e) => compile_expr(e, args, param_idx, bindings),
            SelectItem::ExprWithAlias { expr, alias } => {
                Ok(format!("{} AS {}", compile_expr(expr, args, param_idx, bindings)?, alias.value))
            }
            other => Ok(other.to_string()),
        })
        .collect::<Result<Vec<_>>>()?;

    let from_tbl = sel
        .from
        .first()
        .map(|t| match &t.relation {
            TableFactor::Table { name, .. } => table_name(name),
            other => other.to_string(),
        })
        .unwrap_or_default();

    let mut sql = if from_tbl.is_empty() {
        format!("SELECT {}", proj.join(", "))
    } else {
        format!("SELECT {} FROM {}", proj.join(", "), from_tbl)
    };

    if let Some(where_expr) = &sel.selection {
        sql.push_str(&format!(
            " WHERE {}",
            compile_expr(where_expr, args, param_idx, bindings)?
        ));
    }

    if let Some(order_by) = &q.order_by {
        if let sqlparser::ast::OrderByKind::Expressions(exprs) = &order_by.kind {
            if !exprs.is_empty() {
                let orders: Vec<String> = exprs
                    .iter()
                    .map(|o| {
                        let dir = match o.options.sort {
                            Some(sqlparser::ast::OrderBySort::Desc) => " DESC",
                            _ => " ASC",
                        };
                        Ok(format!("{}{}", compile_expr(&o.expr, args, param_idx, bindings)?, dir))
                    })
                    .collect::<Result<Vec<_>>>()?;
                sql.push_str(&format!(" ORDER BY {}", orders.join(", ")));
            }
        }
    }

    if let Some(limit_clause) = &q.limit_clause {
        if let sqlparser::ast::LimitClause::LimitOffset { limit: Some(lim), .. } = limit_clause {
            sql.push_str(&format!(" LIMIT {}", compile_expr(lim, args, param_idx, bindings)?));
        }
    }

    sql.push(';');
    Ok(sql)
}

fn compile_expr(
    expr: &Expr,
    args: &[DbValue],
    param_idx: &mut usize,
    bindings: &mut Vec<(String, DbValue)>,
) -> Result<String> {
    match expr {
        Expr::Identifier(ident) => Ok(ident.value.clone()),
        Expr::CompoundIdentifier(parts) => Ok(parts
            .iter()
            .map(|p| p.value.as_str())
            .collect::<Vec<_>>()
            .join(".")),
        Expr::Value(val_with_span) => match &val_with_span.value {
            SqlValue::Placeholder(ph) => {
                let idx = if let Some(num) = ph.strip_prefix('?').filter(|s| !s.is_empty()) {
                    num.parse::<usize>()
                        .map_err(|_| anyhow!("Invalid positional placeholder {}", ph))?
                        .saturating_sub(1)
                } else {
                    let i = *param_idx;
                    *param_idx += 1;
                    i
                };
                let bind_name = format!("p{}", idx);
                let val = args.get(idx).cloned().unwrap_or(DbValue::Null);
                if !bindings.iter().any(|(k, _)| k == &bind_name) {
                    bindings.push((bind_name.clone(), val));
                }
                Ok(format!("${}", bind_name))
            }
            SqlValue::SingleQuotedString(s) | SqlValue::DoubleQuotedString(s) => {
                Ok(format!("'{}'", s.replace('\'', "\\'")))
            }
            SqlValue::Number(n, _) => Ok(n.clone()),
            SqlValue::Boolean(b) => Ok(b.to_string()),
            SqlValue::Null => Ok("NONE".to_string()),
            other => Ok(other.to_string()),
        },
        Expr::BinaryOp { left, op, right } => {
            let op_str = match op {
                BinaryOperator::Eq => "=",
                BinaryOperator::NotEq => "!=",
                BinaryOperator::Lt => "<",
                BinaryOperator::LtEq => "<=",
                BinaryOperator::Gt => ">",
                BinaryOperator::GtEq => ">=",
                BinaryOperator::And => "AND",
                BinaryOperator::Or => "OR",
                BinaryOperator::Plus => "+",
                BinaryOperator::Minus => "-",
                BinaryOperator::Multiply => "*",
                BinaryOperator::Divide => "/",
                other => return Err(anyhow!("Unsupported SQLite operator: {}", other)),
            };
            Ok(format!(
                "{} {} {}",
                compile_expr(left, args, param_idx, bindings)?,
                op_str,
                compile_expr(right, args, param_idx, bindings)?
            ))
        }
        Expr::Nested(inner) => Ok(format!("({})", compile_expr(inner, args, param_idx, bindings)?)),
        Expr::Function(func) => {
            let name = table_name(&func.name).to_ascii_lowercase();
            let args_sql = match &func.args {
                sqlparser::ast::FunctionArguments::List(list) => list
                    .args
                    .iter()
                    .map(|a| match a {
                        sqlparser::ast::FunctionArg::Unnamed(
                            sqlparser::ast::FunctionArgExpr::Wildcard,
                        ) => Ok("".to_string()),
                        sqlparser::ast::FunctionArg::Unnamed(
                            sqlparser::ast::FunctionArgExpr::Expr(e),
                        ) => compile_expr(e, args, param_idx, bindings),
                        other => Ok(other.to_string()),
                    })
                    .collect::<Result<Vec<_>>>()?
                    .join(", "),
                _ => String::new(),
            };
            if name == "count" {
                Ok(format!("count({})", args_sql))
            } else {
                Ok(format!("{}({})", name, args_sql))
            }
        }
        other => Ok(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_sqlite_crud_with_placeholders() {
        let create = compile_sqlite_to_surql(
            "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, qty INT)",
            vec![],
        )
        .unwrap();
        assert_eq!(create.surql, "DEFINE TABLE IF NOT EXISTS items SCHEMALESS;");

        let insert = compile_sqlite_to_surql(
            "INSERT INTO items (name, qty) VALUES (?, ?)",
            vec![DbValue::String("widget".into()), DbValue::Int(5)],
        )
        .unwrap();
        assert_eq!(insert.surql, "CREATE items SET name = $p0, qty = $p1;");
        assert_eq!(insert.bindings.len(), 2);

        let select = compile_sqlite_to_surql(
            "SELECT name, qty FROM items WHERE qty >= ? ORDER BY qty DESC LIMIT 10",
            vec![DbValue::Int(2)],
        )
        .unwrap();
        assert_eq!(
            select.surql,
            "SELECT name, qty FROM items WHERE qty >= $p0 ORDER BY qty DESC LIMIT 10;"
        );
    }
}
