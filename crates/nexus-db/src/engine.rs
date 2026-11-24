use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::parser::{BinaryOp, Expr, MutationData, Projection, Statement, Target, UnaryOp};
use crate::storage::{
    encode_key, BatchOp, StorageBackend, PREFIX_RECORD, PREFIX_TABLE_META,
};
use crate::value::Value;

const MAX_EXPR_DEPTH: u16 = 64;

/// Volcano-style synchronous iterator yielding document rows.
trait RowIter<'a> {
    fn next_row(&mut self) -> Result<Option<Value>>;
}

struct VecIter {
    rows: std::vec::IntoIter<Value>,
}

impl<'a> RowIter<'a> for VecIter {
    fn next_row(&mut self) -> Result<Option<Value>> {
        Ok(self.rows.next())
    }
}

struct FilterIter<'a, I: RowIter<'a>> {
    inner: I,
    pred: &'a Expr,
    params: &'a HashMap<String, Value>,
    steps: usize,
    budget: usize,
}

impl<'a, I: RowIter<'a>> RowIter<'a> for FilterIter<'a, I> {
    fn next_row(&mut self) -> Result<Option<Value>> {
        while let Some(row) = self.inner.next_row()? {
            self.steps += 1;
            if self.steps > self.budget {
                return Err(anyhow!("Query exceeded step budget ({})", self.budget));
            }
            if eval_expr(self.pred, Some(&row), self.params, 0)?.is_truthy() {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }
}

struct LimitOffsetIter<I> {
    inner: I,
    skipped: usize,
    start: usize,
    yielded: usize,
    limit: Option<usize>,
}

impl<'a, I: RowIter<'a>> RowIter<'a> for LimitOffsetIter<I> {
    fn next_row(&mut self) -> Result<Option<Value>> {
        if let Some(lim) = self.limit {
            if self.yielded >= lim {
                return Ok(None);
            }
        }
        while self.skipped < self.start {
            if self.inner.next_row()?.is_none() {
                return Ok(None);
            }
            self.skipped += 1;
        }
        match self.inner.next_row()? {
            Some(row) => {
                self.yielded += 1;
                Ok(Some(row))
            }
            None => Ok(None),
        }
    }
}

/// Execution context for a scoped `(ns, db)` query batch.
pub struct ExecContext<'a> {
    pub storage: &'a dyn StorageBackend,
    pub ns: String,
    pub db: String,
    pub params: HashMap<String, Value>,
    pub step_budget: usize,
    tx_buffer: Option<Vec<BatchOp>>,
}

impl<'a> ExecContext<'a> {
    pub fn new(
        storage: &'a dyn StorageBackend,
        ns: String,
        db: String,
        params: HashMap<String, Value>,
    ) -> Self {
        Self {
            storage,
            ns,
            db,
            params,
            step_budget: 250_000,
            tx_buffer: None,
        }
    }

    fn put_raw(&mut self, key: Vec<u8>, val: Vec<u8>) -> Result<()> {
        if let Some(buf) = self.tx_buffer.as_mut() {
            buf.push(BatchOp::Put(key, val));
            Ok(())
        } else {
            self.storage.put(&key, &val)
        }
    }

    fn delete_raw(&mut self, key: Vec<u8>) -> Result<()> {
        if let Some(buf) = self.tx_buffer.as_mut() {
            buf.push(BatchOp::Delete(key));
            Ok(())
        } else {
            let _ = self.storage.delete(&key)?;
            Ok(())
        }
    }

    pub fn execute_all(&mut self, stmts: &[Statement]) -> Result<Vec<Value>> {
        let mut last = Vec::new();
        for stmt in stmts {
            last = self.execute_one(stmt)?;
        }
        // Auto-commit if user opened BEGIN without COMMIT? No, leave buffered unless committed.
        Ok(last)
    }

    fn resolve_target(&self, target: &Target) -> Result<(String, Option<String>)> {
        match target {
            Target::Table(tb) => Ok((tb.clone(), None)),
            Target::Record { tb, id } => Ok((tb.clone(), Some(id.clone()))),
            Target::RecordFn { tb_expr, id_expr } => {
                let tb = eval_expr(tb_expr, None, &self.params, 0)?.display_compact();
                let id = eval_expr(id_expr, None, &self.params, 0)?.display_compact();
                Ok((tb, Some(id)))
            }
        }
    }

    fn scan_target(&self, tb: &str, id: Option<&str>) -> Result<Vec<Value>> {
        if let Some(rec_id) = id {
            let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb, rec_id]);
            if let Some(raw) = self.storage.get(&key)? {
                let val: Value = serde_json::from_slice(&raw)?;
                return Ok(vec![val]);
            }
            return Ok(Vec::new());
        }

        let prefix = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb]);
        let entries = self.storage.scan_prefix(&prefix)?;
        let mut rows = Vec::with_capacity(entries.len());
        for (_, raw) in entries {
            rows.push(serde_json::from_slice(&raw)?);
        }
        Ok(rows)
    }

    fn save_record(&mut self, tb: &str, id: &str, mut obj: BTreeMap<String, Value>) -> Result<Value> {
        obj.insert(
            "id".to_string(),
            Value::RecordId {
                tb: tb.to_string(),
                id: id.to_string(),
            },
        );
        let val = Value::Object(obj);
        let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb, id]);
        let bytes = serde_json::to_vec(&val)?;
        self.put_raw(key, bytes)?;
        Ok(val)
    }

    fn apply_mutation_data(
        &self,
        mut base: BTreeMap<String, Value>,
        data: &MutationData,
        current_row: Option<&Value>,
    ) -> Result<BTreeMap<String, Value>> {
        match data {
            MutationData::None => Ok(base),
            MutationData::Set(pairs) => {
                for (k, expr) in pairs {
                    let v = eval_expr(expr, current_row, &self.params, 0)?;
                    base.insert(k.clone(), v);
                }
                Ok(base)
            }
            MutationData::Content(expr) => {
                let v = eval_expr(expr, current_row, &self.params, 0)?;
                match v {
                    Value::Object(map) => Ok(map),
                    other => Err(anyhow!("CONTENT expects an object, got {:?}", other)),
                }
            }
            MutationData::Merge(expr) => {
                let v = eval_expr(expr, current_row, &self.params, 0)?;
                match v {
                    Value::Object(map) => {
                        for (k, val) in map {
                            base.insert(k, val);
                        }
                        Ok(base)
                    }
                    other => Err(anyhow!("MERGE expects an object, got {:?}", other)),
                }
            }
        }
    }

    fn execute_one(&mut self, stmt: &Statement) -> Result<Vec<Value>> {
        match stmt {
            Statement::Use { ns, db } => {
                if let Some(n) = ns {
                    self.ns = n.clone();
                }
                if let Some(d) = db {
                    self.db = d.clone();
                }
                Ok(Vec::new())
            }
            Statement::Begin => {
                self.tx_buffer = Some(Vec::new());
                Ok(Vec::new())
            }
            Statement::Commit => {
                if let Some(ops) = self.tx_buffer.take() {
                    self.storage.apply_batch(ops)?;
                }
                Ok(Vec::new())
            }
            Statement::Cancel => {
                self.tx_buffer = None;
                Ok(Vec::new())
            }
            Statement::DefineTable {
                name,
                schemafull,
                ..
            } => {
                let key = encode_key(PREFIX_TABLE_META, &[&self.ns, &self.db, name]);
                let meta = serde_json::json!({
                    "name": name,
                    "schemafull": schemafull,
                });
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::Create { target, data } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let id = id_opt.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, &tb, &id]);
                if self.storage.get(&key)?.is_some() {
                    return Err(anyhow!("Record {}:{} already exists", tb, id));
                }
                let obj = self.apply_mutation_data(BTreeMap::new(), data, None)?;
                let saved = self.save_record(&tb, &id, obj)?;
                Ok(vec![saved])
            }
            Statement::Insert {
                table,
                columns,
                values,
                objects,
            } => {
                let mut inserted = Vec::new();
                if let Some(cols) = columns {
                    for row_exprs in values {
                        let mut obj = BTreeMap::new();
                        for (col, expr) in cols.iter().zip(row_exprs.iter()) {
                            let val = eval_expr(expr, None, &self.params, 0)?;
                            obj.insert(col.clone(), val);
                        }
                        let id = obj
                            .get("id")
                            .map(|v| match v {
                                Value::RecordId { id, .. } => id.clone(),
                                other => other.display_compact(),
                            })
                            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                        inserted.push(self.save_record(table, &id, obj)?);
                    }
                } else {
                    for expr in objects {
                        let val = eval_expr(expr, None, &self.params, 0)?;
                        let items = match val {
                            Value::Array(arr) => arr,
                            other => vec![other],
                        };
                        for item in items {
                            if let Value::Object(obj) = item {
                                let id = obj
                                    .get("id")
                                    .map(|v| match v {
                                        Value::RecordId { id, .. } => id.clone(),
                                        other => other.display_compact(),
                                    })
                                    .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                                inserted.push(self.save_record(table, &id, obj)?);
                            }
                        }
                    }
                }
                Ok(inserted)
            }
            Statement::Update {
                target,
                data,
                where_clause,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let existing = self.scan_target(&tb, id_opt.as_deref())?;
                let mut updated = Vec::new();
                for row in existing {
                    if let Some(pred) = where_clause {
                        if !eval_expr(pred, Some(&row), &self.params, 0)?.is_truthy() {
                            continue;
                        }
                    }
                    if let Value::Object(map) = &row {
                        let rec_id = match map.get("id") {
                            Some(Value::RecordId { id, .. }) => id.clone(),
                            _ => continue,
                        };
                        let next_map =
                            self.apply_mutation_data(map.clone(), data, Some(&row))?;
                        updated.push(self.save_record(&tb, &rec_id, next_map)?);
                    }
                }
                Ok(updated)
            }
            Statement::Upsert {
                target,
                data,
                where_clause,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let existing = self.scan_target(&tb, id_opt.as_deref())?;
                if existing.is_empty() {
                    let rec_id = id_opt.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                    let next_map = self.apply_mutation_data(BTreeMap::new(), data, None)?;
                    return Ok(vec![self.save_record(&tb, &rec_id, next_map)?]);
                }
                let mut updated = Vec::new();
                for row in existing {
                    if let Some(pred) = where_clause {
                        if !eval_expr(pred, Some(&row), &self.params, 0)?.is_truthy() {
                            continue;
                        }
                    }
                    if let Value::Object(map) = &row {
                        let rec_id = match map.get("id") {
                            Some(Value::RecordId { id, .. }) => id.clone(),
                            _ => continue,
                        };
                        let next_map =
                            self.apply_mutation_data(map.clone(), data, Some(&row))?;
                        updated.push(self.save_record(&tb, &rec_id, next_map)?);
                    }
                }
                Ok(updated)
            }
            Statement::Delete {
                target,
                where_clause,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let existing = self.scan_target(&tb, id_opt.as_deref())?;
                for row in existing {
                    if let Some(pred) = where_clause {
                        if !eval_expr(pred, Some(&row), &self.params, 0)?.is_truthy() {
                            continue;
                        }
                    }
                    if let Value::Object(map) = &row {
                        if let Some(Value::RecordId { id, .. }) = map.get("id") {
                            let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, &tb, id]);
                            self.delete_raw(key)?;
                        }
                    }
                }
                Ok(Vec::new())
            }
            Statement::Select {
                value_only,
                projections,
                target,
                where_clause,
                order_by,
                limit,
                start,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let raw_rows = self.scan_target(&tb, id_opt.as_deref())?;

                // Build synchronous Volcano pipeline: Scan -> Filter -> (Sort) -> LimitOffset -> Project
                let mut filtered: Vec<Value> = if let Some(pred) = where_clause {
                    let mut iter = FilterIter {
                        inner: VecIter {
                            rows: raw_rows.into_iter(),
                        },
                        pred,
                        params: &self.params,
                        steps: 0,
                        budget: self.step_budget,
                    };
                    let mut acc = Vec::new();
                    while let Some(r) = iter.next_row()? {
                        acc.push(r);
                    }
                    acc
                } else {
                    raw_rows
                };

                if let Some((field, asc)) = order_by {
                    filtered.sort_by(|a, b| {
                        let va = extract_field(a, field);
                        let vb = extract_field(b, field);
                        let ord = va.cmp_order(&vb);
                        if *asc {
                            ord
                        } else {
                            ord.reverse()
                        }
                    });
                }

                let mut paged_iter = LimitOffsetIter {
                    inner: VecIter {
                        rows: filtered.into_iter(),
                    },
                    skipped: 0,
                    start: start.unwrap_or(0),
                    yielded: 0,
                    limit: *limit,
                };

                let mut projected = Vec::new();
                while let Some(row) = paged_iter.next_row()? {
                    if *value_only {
                        if let Some(Projection::Expr { expr, .. }) = projections.first() {
                            projected.push(eval_expr(expr, Some(&row), &self.params, 0)?);
                        } else {
                            projected.push(row);
                        }
                    } else if projections.len() == 1 && matches!(projections[0], Projection::All) {
                        projected.push(row);
                    } else {
                        let mut out = BTreeMap::new();
                        for proj in projections {
                            match proj {
                                Projection::All => {
                                    if let Value::Object(m) = &row {
                                        for (k, v) in m {
                                            out.insert(k.clone(), v.clone());
                                        }
                                    }
                                }
                                Projection::Expr { expr, alias } => {
                                    let val = eval_expr(expr, Some(&row), &self.params, 0)?;
                                    let key = alias.clone().unwrap_or_else(|| expr_default_name(expr));
                                    out.insert(key, val);
                                }
                            }
                        }
                        projected.push(Value::Object(out));
                    }
                }

                Ok(projected)
            }
        }
    }
}

fn expr_default_name(expr: &Expr) -> String {
    match expr {
        Expr::Ident(s) => s.clone(),
        Expr::FieldPath(parts) => parts.last().cloned().unwrap_or_else(|| "field".to_string()),
        Expr::FunctionCall { name, .. } => name.clone(),
        _ => "expr".to_string(),
    }
}

fn extract_field(row: &Value, field: &str) -> Value {
    match row {
        Value::Object(map) => map.get(field).cloned().unwrap_or(Value::None),
        _ => Value::None,
    }
}

fn eval_expr(
    expr: &Expr,
    row: Option<&Value>,
    params: &HashMap<String, Value>,
    depth: u16,
) -> Result<Value> {
    if depth > MAX_EXPR_DEPTH {
        return Err(anyhow!(
            "Expression recursion depth exceeded limit ({})",
            MAX_EXPR_DEPTH
        ));
    }

    match expr {
        Expr::None => Ok(Value::None),
        Expr::Null => Ok(Value::Null),
        Expr::Bool(b) => Ok(Value::Bool(*b)),
        Expr::Int(i) => Ok(Value::Int(*i)),
        Expr::Float(f) => Ok(Value::Float(*f)),
        Expr::String(s) => Ok(Value::String(s.clone())),
        Expr::RecordId { tb, id } => Ok(Value::RecordId {
            tb: tb.clone(),
            id: id.clone(),
        }),
        Expr::Param(name) => Ok(params.get(name).cloned().unwrap_or(Value::None)),
        Expr::Ident(name) => Ok(row.map(|r| extract_field(r, name)).unwrap_or(Value::None)),
        Expr::FieldPath(parts) => {
            let mut cur = match row {
                Some(r) => r.clone(),
                None => return Ok(Value::None),
            };
            for p in parts {
                cur = extract_field(&cur, p);
            }
            Ok(cur)
        }
        Expr::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(eval_expr(item, row, params, depth + 1)?);
            }
            Ok(Value::Array(out))
        }
        Expr::Object(pairs) => {
            let mut out = BTreeMap::new();
            for (k, v) in pairs {
                out.insert(k.clone(), eval_expr(v, row, params, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
        Expr::Unary { op, expr } => {
            let v = eval_expr(expr, row, params, depth + 1)?;
            match op {
                UnaryOp::Not => Ok(Value::Bool(!v.is_truthy())),
                UnaryOp::Neg => match v {
                    Value::Int(i) => Ok(Value::Int(-i)),
                    Value::Float(f) => Ok(Value::Float(-f)),
                    _ => Err(anyhow!("Cannot negate non-numeric value {:?}", v)),
                },
            }
        }
        Expr::Binary { left, op, right } => {
            if *op == BinaryOp::And {
                let l = eval_expr(left, row, params, depth + 1)?;
                if !l.is_truthy() {
                    return Ok(Value::Bool(false));
                }
                let r = eval_expr(right, row, params, depth + 1)?;
                return Ok(Value::Bool(r.is_truthy()));
            }
            if *op == BinaryOp::Or {
                let l = eval_expr(left, row, params, depth + 1)?;
                if l.is_truthy() {
                    return Ok(Value::Bool(true));
                }
                let r = eval_expr(right, row, params, depth + 1)?;
                return Ok(Value::Bool(r.is_truthy()));
            }

            let l = eval_expr(left, row, params, depth + 1)?;
            let r = eval_expr(right, row, params, depth + 1)?;
            match op {
                BinaryOp::Eq => Ok(Value::Bool(l == r)),
                BinaryOp::Ne => Ok(Value::Bool(l != r)),
                BinaryOp::Lt => Ok(Value::Bool(l.cmp_order(&r).is_lt())),
                BinaryOp::Le => Ok(Value::Bool(l.cmp_order(&r).is_le())),
                BinaryOp::Gt => Ok(Value::Bool(l.cmp_order(&r).is_gt())),
                BinaryOp::Ge => Ok(Value::Bool(l.cmp_order(&r).is_ge())),
                BinaryOp::Add => match (l, r) {
                    (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a + b)),
                    (Value::String(a), Value::String(b)) => Ok(Value::String(format!("{}{}", a, b))),
                    (a, b) => match (a.as_f64(), b.as_f64()) {
                        (Some(x), Some(y)) => Ok(Value::Float(x + y)),
                        _ => Err(anyhow!("Invalid '+' operands")),
                    },
                },
                BinaryOp::Sub => match (l, r) {
                    (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a - b)),
                    (a, b) => match (a.as_f64(), b.as_f64()) {
                        (Some(x), Some(y)) => Ok(Value::Float(x - y)),
                        _ => Err(anyhow!("Invalid '-' operands")),
                    },
                },
                BinaryOp::Mul => match (l, r) {
                    (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a * b)),
                    (a, b) => match (a.as_f64(), b.as_f64()) {
                        (Some(x), Some(y)) => Ok(Value::Float(x * y)),
                        _ => Err(anyhow!("Invalid '*' operands")),
                    },
                },
                BinaryOp::Div => match (l.as_f64(), r.as_f64()) {
                    (Some(x), Some(y)) if y != 0.0 => Ok(Value::Float(x / y)),
                    _ => Err(anyhow!("Division by zero or invalid '/' operands")),
                },
                BinaryOp::Contains => match (&l, &r) {
                    (Value::String(hay), Value::String(needle)) => Ok(Value::Bool(hay.contains(needle.as_str()))),
                    (Value::Array(arr), item) => Ok(Value::Bool(arr.contains(item))),
                    _ => Ok(Value::Bool(false)),
                },
                BinaryOp::In => match (&l, &r) {
                    (item, Value::Array(arr)) => Ok(Value::Bool(arr.contains(item))),
                    (Value::String(needle), Value::String(hay)) => Ok(Value::Bool(hay.contains(needle.as_str()))),
                    _ => Ok(Value::Bool(false)),
                },
                BinaryOp::And | BinaryOp::Or => unreachable!(),
            }
        }
        Expr::FunctionCall { name, args } => {
            let mut eval_args = Vec::with_capacity(args.len());
            for a in args {
                eval_args.push(eval_expr(a, row, params, depth + 1)?);
            }
            eval_function(name, &eval_args)
        }
    }
}

fn eval_function(name: &str, args: &[Value]) -> Result<Value> {
    match name.to_ascii_lowercase().as_str() {
        "time::now" => Ok(Value::DateTime(Utc::now().to_rfc3339())),
        "type::record" => {
            if args.len() != 2 {
                return Err(anyhow!("type::record expects 2 arguments (table, id)"));
            }
            Ok(Value::RecordId {
                tb: args[0].display_compact(),
                id: args[1].display_compact(),
            })
        }
        "string::lowercase" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::String(s.to_ascii_lowercase()))
        }
        "string::uppercase" => {
            let s = args.first().and_then(|v| v.as_str()).unwrap_or("");
            Ok(Value::String(s.to_ascii_uppercase()))
        }
        "count" => match args.first() {
            Some(Value::Array(a)) => Ok(Value::Int(a.len() as i64)),
            Some(Value::String(s)) => Ok(Value::Int(s.len() as i64)),
            Some(Value::None) | Some(Value::Null) | None => Ok(Value::Int(0)),
            _ => Ok(Value::Int(1)),
        },
        "math::sum" => match args.first() {
            Some(Value::Array(a)) => {
                let sum: f64 = a.iter().filter_map(|v| v.as_f64()).sum();
                Ok(Value::Float(sum))
            }
            _ => Ok(Value::Int(0)),
        },
        other => Err(anyhow!("Unknown SurrealQL function '{}' in Phase 1", other)),
    }
}
