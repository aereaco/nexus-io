use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::live::{LiveAction, LiveBroker};
use crate::parser::{
    BinaryOp, Expr, GraphDir, GraphHop, IndexKind, MutationData, Projection, Statement, Target,
    UnaryOp, VectorMetric,
};
use crate::stdlib::{
    cosine_similarity, euclidean_distance, eval_stdlib, manhattan_distance, tokenize_fts,
    value_to_vec,
};
use crate::storage::{
    encode_key, BatchOp, StorageBackend, PREFIX_EDGE_IN, PREFIX_EDGE_OUT, PREFIX_EVENT_META,
    PREFIX_FIELD_META, PREFIX_FTS, PREFIX_INDEX, PREFIX_INDEX_META, PREFIX_RECORD,
    PREFIX_TABLE_META, PREFIX_VEC,
};
use crate::value::Value;

const MAX_EXPR_DEPTH: u16 = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TableMeta {
    name: String,
    schemafull: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldMeta {
    name: String,
    field_type: Option<String>,
    assert_sql: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexMeta {
    name: String,
    columns: Vec<String>,
    kind: IndexKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventMeta {
    name: String,
    when_sql: String,
    then_sql: String,
}

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
    pub live: &'a LiveBroker,
    pub ns: String,
    pub db: String,
    pub params: HashMap<String, Value>,
    pub step_budget: usize,
    tx_buffer: Option<Vec<BatchOp>>,
}

impl<'a> ExecContext<'a> {
    pub fn new(
        storage: &'a dyn StorageBackend,
        live: &'a LiveBroker,
        ns: String,
        db: String,
        params: HashMap<String, Value>,
    ) -> Self {
        Self {
            storage,
            live,
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
        Ok(last)
    }

    fn resolve_target(&self, target: &Target) -> Result<(String, Option<String>)> {
        match target {
            Target::Table(tb) => Ok((tb.clone(), None)),
            Target::Record { tb, id } => Ok((tb.clone(), Some(id.clone()))),
            Target::RecordFn { tb_expr, id_expr } => {
                let tb = self.eval_expr(tb_expr, None, 0)?.display_compact();
                let id = self.eval_expr(id_expr, None, 0)?.display_compact();
                Ok((tb, Some(id)))
            }
        }
    }

    fn get_record(&self, tb: &str, id: &str) -> Result<Option<Value>> {
        let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb, id]);
        if let Some(raw) = self.storage.get(&key)? {
            return Ok(Some(serde_json::from_slice(&raw)?));
        }
        Ok(None)
    }

    fn scan_target(&self, tb: &str, id: Option<&str>) -> Result<Vec<Value>> {
        if let Some(rec_id) = id {
            return Ok(self.get_record(tb, rec_id)?.into_iter().collect());
        }
        let prefix = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb]);
        let entries = self.storage.scan_prefix(&prefix)?;
        let mut rows = Vec::with_capacity(entries.len());
        for (_, raw) in entries {
            rows.push(serde_json::from_slice(&raw)?);
        }
        Ok(rows)
    }

    fn load_table_meta(&self, tb: &str) -> Result<Option<TableMeta>> {
        let key = encode_key(PREFIX_TABLE_META, &[&self.ns, &self.db, tb]);
        if let Some(raw) = self.storage.get(&key)? {
            return Ok(Some(serde_json::from_slice(&raw)?));
        }
        Ok(None)
    }

    fn load_fields(&self, tb: &str) -> Result<Vec<FieldMeta>> {
        let pfx = encode_key(PREFIX_FIELD_META, &[&self.ns, &self.db, tb]);
        let mut out = Vec::new();
        for (_, raw) in self.storage.scan_prefix(&pfx)? {
            out.push(serde_json::from_slice(&raw)?);
        }
        Ok(out)
    }

    fn load_indexes(&self, tb: &str) -> Result<Vec<IndexMeta>> {
        let pfx = encode_key(PREFIX_INDEX_META, &[&self.ns, &self.db, tb]);
        let mut out = Vec::new();
        for (_, raw) in self.storage.scan_prefix(&pfx)? {
            out.push(serde_json::from_slice(&raw)?);
        }
        Ok(out)
    }

    fn validate_schema(&self, tb: &str, obj: &BTreeMap<String, Value>) -> Result<()> {
        let fields = self.load_fields(tb)?;
        if let Some(meta) = self.load_table_meta(tb)? {
            if meta.schemafull {
                let allowed: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
                for k in obj.keys() {
                    if k != "id" && k != "in" && k != "out" && !allowed.contains(&k.as_str()) {
                        return Err(anyhow!(
                            "Field '{}' is not defined on SCHEMAFULL table '{}'",
                            k,
                            tb
                        ));
                    }
                }
            }
        }
        for f in &fields {
            if let (Some(expected_ty), Some(val)) = (&f.field_type, obj.get(&f.name)) {
                if !matches_field_type(val, expected_ty) {
                    return Err(anyhow!(
                        "Field '{}' on table '{}' expected type '{}', got {:?}",
                        f.name,
                        tb,
                        expected_ty,
                        val
                    ));
                }
            }
        }
        Ok(())
    }

    fn maintain_indexes_on_write(
        &mut self,
        tb: &str,
        rec_id: &str,
        old_row: Option<&BTreeMap<String, Value>>,
        new_row: &BTreeMap<String, Value>,
    ) -> Result<()> {
        let indexes = self.load_indexes(tb)?;
        for idx in indexes {
            // Remove old index entries if updating
            if let Some(old) = old_row {
                self.remove_index_entries(tb, rec_id, &idx, old)?;
            }

            match idx.kind {
                IndexKind::Unique | IndexKind::Standard => {
                    let key_val: String = idx
                        .columns
                        .iter()
                        .map(|c| {
                            new_row
                                .get(c)
                                .map(|v| v.display_compact())
                                .unwrap_or_default()
                        })
                        .collect::<Vec<_>>()
                        .join("|");
                    if idx.kind == IndexKind::Unique {
                        let scan_pfx =
                            encode_key(PREFIX_INDEX, &[&self.ns, &self.db, tb, &idx.name, &key_val]);
                        let existing = self.storage.scan_prefix(&scan_pfx)?;
                        for (k_bytes, _) in existing {
                            let existing_id = extract_last_key_part(&k_bytes);
                            if existing_id != rec_id {
                                return Err(anyhow!(
                                    "UNIQUE index '{}' violation on table '{}' for value '{}'",
                                    idx.name,
                                    tb,
                                    key_val
                                ));
                            }
                        }
                    }
                    let ikey = encode_key(
                        PREFIX_INDEX,
                        &[&self.ns, &self.db, tb, &idx.name, &key_val, rec_id],
                    );
                    self.put_raw(ikey, vec![1])?;
                }
                IndexKind::FtsBm25 => {
                    for col in &idx.columns {
                        if let Some(text) = new_row.get(col).and_then(|v| v.as_str()) {
                            for term in tokenize_fts(text) {
                                let fkey = encode_key(
                                    PREFIX_FTS,
                                    &[&self.ns, &self.db, tb, &idx.name, &term, rec_id],
                                );
                                self.put_raw(fkey, vec![1])?;
                            }
                        }
                    }
                }
                IndexKind::VectorHnsw { dim, .. } => {
                    if let Some(col) = idx.columns.first() {
                        if let Some(vec_val) = new_row.get(col).and_then(value_to_vec) {
                            if vec_val.len() != dim {
                                return Err(anyhow!(
                                    "Vector index '{}' expects dimension {}, got {}",
                                    idx.name,
                                    dim,
                                    vec_val.len()
                                ));
                            }
                            let vkey =
                                encode_key(PREFIX_VEC, &[&self.ns, &self.db, tb, &idx.name, rec_id]);
                            self.put_raw(vkey, serde_json::to_vec(&vec_val)?)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn remove_index_entries(
        &mut self,
        tb: &str,
        rec_id: &str,
        idx: &IndexMeta,
        old: &BTreeMap<String, Value>,
    ) -> Result<()> {
        match idx.kind {
            IndexKind::Unique | IndexKind::Standard => {
                let key_val: String = idx
                    .columns
                    .iter()
                    .map(|c| old.get(c).map(|v| v.display_compact()).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("|");
                let ikey = encode_key(
                    PREFIX_INDEX,
                    &[&self.ns, &self.db, tb, &idx.name, &key_val, rec_id],
                );
                self.delete_raw(ikey)?;
            }
            IndexKind::FtsBm25 => {
                for col in &idx.columns {
                    if let Some(text) = old.get(col).and_then(|v| v.as_str()) {
                        for term in tokenize_fts(text) {
                            let fkey = encode_key(
                                PREFIX_FTS,
                                &[&self.ns, &self.db, tb, &idx.name, &term, rec_id],
                            );
                            self.delete_raw(fkey)?;
                        }
                    }
                }
            }
            IndexKind::VectorHnsw { .. } => {
                let vkey = encode_key(PREFIX_VEC, &[&self.ns, &self.db, tb, &idx.name, rec_id]);
                self.delete_raw(vkey)?;
            }
        }
        Ok(())
    }

    fn save_record(
        &mut self,
        tb: &str,
        id: &str,
        mut obj: BTreeMap<String, Value>,
        action: LiveAction,
    ) -> Result<Value> {
        let old_map = match self.get_record(tb, id)? {
            Some(Value::Object(m)) => Some(m),
            _ => None,
        };
        obj.insert(
            "id".to_string(),
            Value::RecordId {
                tb: tb.to_string(),
                id: id.to_string(),
            },
        );
        self.validate_schema(tb, &obj)?;
        self.maintain_indexes_on_write(tb, id, old_map.as_ref(), &obj)?;

        let val = Value::Object(obj);
        let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb, id]);
        let bytes = serde_json::to_vec(&val)?;
        self.put_raw(key, bytes)?;
        self.live.publish(&self.ns, &self.db, tb, action, &val);
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
                    let v = self.eval_expr(expr, current_row, 0)?;
                    base.insert(k.clone(), v);
                }
                Ok(base)
            }
            MutationData::Content(expr) => {
                let v = self.eval_expr(expr, current_row, 0)?;
                match v {
                    Value::Object(map) => Ok(map),
                    other => Err(anyhow!("CONTENT expects an object, got {:?}", other)),
                }
            }
            MutationData::Merge(expr) => {
                let v = self.eval_expr(expr, current_row, 0)?;
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
            Statement::Let { name, expr } => {
                let val = self.eval_expr(expr, None, 0)?;
                self.params.insert(name.clone(), val);
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
                let meta = TableMeta {
                    name: name.clone(),
                    schemafull: *schemafull,
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineField {
                name,
                table,
                field_type,
                ..
            } => {
                let key = encode_key(PREFIX_FIELD_META, &[&self.ns, &self.db, table, name]);
                let meta = FieldMeta {
                    name: name.clone(),
                    field_type: field_type.clone(),
                    assert_sql: None,
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineIndex {
                name,
                table,
                columns,
                kind,
                ..
            } => {
                let key = encode_key(PREFIX_INDEX_META, &[&self.ns, &self.db, table, name]);
                let meta = IndexMeta {
                    name: name.clone(),
                    columns: columns.clone(),
                    kind: kind.clone(),
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineEvent { name, table, .. } => {
                let key = encode_key(PREFIX_EVENT_META, &[&self.ns, &self.db, table, name]);
                let meta = EventMeta {
                    name: name.clone(),
                    when_sql: String::new(),
                    then_sql: String::new(),
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::LiveSelect { table } => {
                let (live_id, _rx) = self.live.subscribe(&self.ns, &self.db, table);
                Ok(vec![Value::String(live_id)])
            }
            Statement::Kill { live_id } => {
                let id = self.eval_expr(live_id, None, 0)?.display_compact();
                self.live.kill(&id);
                Ok(Vec::new())
            }
            Statement::Relate {
                from,
                edge,
                to,
                data,
            } => {
                let from_val = self.eval_expr(from, None, 0)?;
                let to_val = self.eval_expr(to, None, 0)?;
                let (from_tb, from_id) = match &from_val {
                    Value::RecordId { tb, id } => (tb.clone(), id.clone()),
                    other => {
                        return Err(anyhow!(
                            "RELATE source must be a RecordId, got {:?}",
                            other
                        ))
                    }
                };
                let (to_tb, to_id) = match &to_val {
                    Value::RecordId { tb, id } => (tb.clone(), id.clone()),
                    other => {
                        return Err(anyhow!(
                            "RELATE target must be a RecordId, got {:?}",
                            other
                        ))
                    }
                };

                let edge_id = Uuid::new_v4().simple().to_string();
                let mut obj = self.apply_mutation_data(BTreeMap::new(), data, None)?;
                obj.insert("in".to_string(), from_val);
                obj.insert("out".to_string(), to_val);

                let saved = self.save_record(edge, &edge_id, obj, LiveAction::Create)?;

                // Write outbound & inbound graph adjacency entries
                let from_ref = format!("{}:{}", from_tb, from_id);
                let to_ref = format!("{}:{}", to_tb, to_id);
                let out_key =
                    encode_key(PREFIX_EDGE_OUT, &[&self.ns, &self.db, &from_ref, edge, &edge_id]);
                let in_key =
                    encode_key(PREFIX_EDGE_IN, &[&self.ns, &self.db, &to_ref, edge, &edge_id]);
                self.put_raw(out_key, to_ref.as_bytes().to_vec())?;
                self.put_raw(in_key, from_ref.as_bytes().to_vec())?;

                Ok(vec![saved])
            }
            Statement::Create { target, data } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let id = id_opt.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, &tb, &id]);
                if self.storage.get(&key)?.is_some() {
                    return Err(anyhow!("Record {}:{} already exists", tb, id));
                }
                let obj = self.apply_mutation_data(BTreeMap::new(), data, None)?;
                let saved = self.save_record(&tb, &id, obj, LiveAction::Create)?;
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
                            let val = self.eval_expr(expr, None, 0)?;
                            obj.insert(col.clone(), val);
                        }
                        let id = obj
                            .get("id")
                            .map(|v| match v {
                                Value::RecordId { id, .. } => id.clone(),
                                other => other.display_compact(),
                            })
                            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                        inserted.push(self.save_record(table, &id, obj, LiveAction::Create)?);
                    }
                } else {
                    for expr in objects {
                        let val = self.eval_expr(expr, None, 0)?;
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
                                inserted.push(self.save_record(
                                    table,
                                    &id,
                                    obj,
                                    LiveAction::Create,
                                )?);
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
                        if !self.eval_expr(pred, Some(&row), 0)?.is_truthy() {
                            continue;
                        }
                    }
                    if let Value::Object(map) = &row {
                        let rec_id = match map.get("id") {
                            Some(Value::RecordId { id, .. }) => id.clone(),
                            _ => continue,
                        };
                        let next_map = self.apply_mutation_data(map.clone(), data, Some(&row))?;
                        updated.push(self.save_record(
                            &tb,
                            &rec_id,
                            next_map,
                            LiveAction::Update,
                        )?);
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
                    return Ok(vec![self.save_record(
                        &tb,
                        &rec_id,
                        next_map,
                        LiveAction::Create,
                    )?]);
                }
                let mut updated = Vec::new();
                for row in existing {
                    if let Some(pred) = where_clause {
                        if !self.eval_expr(pred, Some(&row), 0)?.is_truthy() {
                            continue;
                        }
                    }
                    if let Value::Object(map) = &row {
                        let rec_id = match map.get("id") {
                            Some(Value::RecordId { id, .. }) => id.clone(),
                            _ => continue,
                        };
                        let next_map = self.apply_mutation_data(map.clone(), data, Some(&row))?;
                        updated.push(self.save_record(
                            &tb,
                            &rec_id,
                            next_map,
                            LiveAction::Update,
                        )?);
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
                let indexes = self.load_indexes(&tb)?;
                for row in existing {
                    if let Some(pred) = where_clause {
                        if !self.eval_expr(pred, Some(&row), 0)?.is_truthy() {
                            continue;
                        }
                    }
                    if let Value::Object(map) = &row {
                        if let Some(Value::RecordId { id, .. }) = map.get("id") {
                            for idx in &indexes {
                                self.remove_index_entries(&tb, id, idx, map)?;
                            }
                            let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, &tb, id]);
                            self.delete_raw(key)?;
                            self.live
                                .publish(&self.ns, &self.db, &tb, LiveAction::Delete, &row);
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
                group_by,
                order_by,
                limit,
                start,
                fetch,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let raw_rows = self.scan_target(&tb, id_opt.as_deref())?;

                // Special-case Vector KNN `<|K,METRIC|>` in WHERE clause for top-K ranking
                let mut filtered: Vec<Value> = if let Some(Expr::Binary {
                    left,
                    op: BinaryOp::VecKnn { k, metric },
                    right,
                }) = where_clause
                {
                    let query_vec = self
                        .eval_expr(right, None, 0)
                        .ok()
                        .and_then(|v| value_to_vec(&v))
                        .unwrap_or_default();
                    let mut scored: Vec<(f64, Value)> = Vec::new();
                    for row in raw_rows {
                        if let Ok(v) = self.eval_expr(left, Some(&row), 0) {
                            if let Some(rv) = value_to_vec(&v) {
                                let dist = match metric {
                                    VectorMetric::Cosine => 1.0 - cosine_similarity(&rv, &query_vec),
                                    VectorMetric::Euclidean => euclidean_distance(&rv, &query_vec),
                                    VectorMetric::Manhattan => manhattan_distance(&rv, &query_vec),
                                };
                                scored.push((dist, row));
                            }
                        }
                    }
                    scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                    scored.into_iter().take(*k).map(|(_, r)| r).collect()
                } else if let Some(pred) = where_clause {
                    let mut acc = Vec::new();
                    let mut steps = 0usize;
                    for row in raw_rows {
                        steps += 1;
                        if steps > self.step_budget {
                            return Err(anyhow!(
                                "Query exceeded step budget ({})",
                                self.step_budget
                            ));
                        }
                        if self.eval_expr(pred, Some(&row), 0)?.is_truthy() {
                            acc.push(row);
                        }
                    }
                    acc
                } else {
                    raw_rows
                };

                // Optional GROUP BY aggregation
                if !group_by.is_empty() {
                    let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                    for row in filtered {
                        let gkey: String = group_by
                            .iter()
                            .map(|col| extract_field(&row, col).display_compact())
                            .collect::<Vec<_>>()
                            .join("|");
                        groups.entry(gkey).or_default().push(row);
                    }
                    let mut agg_rows = Vec::new();
                    for (_, bucket) in groups {
                        let first = &bucket[0];
                        let mut out = BTreeMap::new();
                        for proj in projections {
                            match proj {
                                Projection::All => {
                                    if let Value::Object(m) = first {
                                        for (k, v) in m {
                                            out.insert(k.clone(), v.clone());
                                        }
                                    }
                                }
                                Projection::Expr { expr, alias } => {
                                    let val = self.eval_group_expr(expr, &bucket)?;
                                    let key =
                                        alias.clone().unwrap_or_else(|| expr_default_name(expr));
                                    out.insert(key, val);
                                }
                            }
                        }
                        agg_rows.push(Value::Object(out));
                    }
                    filtered = agg_rows;
                }

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
                while let Some(mut row) = paged_iter.next_row()? {
                    // Optional FETCH link dereferencing
                    if !fetch.is_empty() {
                        if let Value::Object(ref mut map) = row {
                            for field_name in fetch {
                                if let Some(val) = map.get(field_name).cloned() {
                                    let resolved = self.fetch_value(val)?;
                                    map.insert(field_name.clone(), resolved);
                                }
                            }
                        }
                    }

                    if !group_by.is_empty() {
                        projected.push(row);
                    } else if *value_only {
                        if let Some(Projection::Expr { expr, .. }) = projections.first() {
                            projected.push(self.eval_expr(expr, Some(&row), 0)?);
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
                                    let val = self.eval_expr(expr, Some(&row), 0)?;
                                    let key =
                                        alias.clone().unwrap_or_else(|| expr_default_name(expr));
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

    fn fetch_value(&self, v: Value) -> Result<Value> {
        match v {
            Value::RecordId { tb, id } => Ok(self
                .get_record(&tb, &id)?
                .unwrap_or(Value::RecordId { tb, id })),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.fetch_value(item)?);
                }
                Ok(Value::Array(out))
            }
            other => Ok(other),
        }
    }

    fn eval_group_expr(&self, expr: &Expr, bucket: &[Value]) -> Result<Value> {
        if let Expr::FunctionCall { name, args } = expr {
            match name.to_ascii_lowercase().as_str() {
                "count" => return Ok(Value::Int(bucket.len() as i64)),
                "math::sum" | "math::mean" | "math::min" | "math::max" => {
                    let mut vals = Vec::with_capacity(bucket.len());
                    if let Some(arg) = args.first() {
                        for row in bucket {
                            vals.push(self.eval_expr(arg, Some(row), 0)?);
                        }
                    }
                    return eval_stdlib(name, &[Value::Array(vals)]);
                }
                _ => {}
            }
        }
        self.eval_expr(expr, bucket.first(), 0)
    }

    fn eval_graph_traverse(
        &self,
        hops: &[GraphHop],
        tail_field: Option<&str>,
        row: Option<&Value>,
    ) -> Result<Value> {
        let start_id = match row.and_then(|r| match r {
            Value::Object(m) => m.get("id"),
            Value::RecordId { .. } => Some(r),
            _ => None,
        }) {
            Some(Value::RecordId { tb, id }) => vec![(tb.clone(), id.clone())],
            _ => return Ok(Value::Array(Vec::new())),
        };

        let mut frontier = start_id;
        for hop in hops {
            let mut next_frontier = Vec::new();
            let prefix_byte = match hop.dir {
                GraphDir::Out => PREFIX_EDGE_OUT,
                GraphDir::In => PREFIX_EDGE_IN,
            };
            for (cur_tb, cur_id) in &frontier {
                let cur_ref = format!("{}:{}", cur_tb, cur_id);
                let pfx = encode_key(prefix_byte, &[&self.ns, &self.db, &cur_ref, &hop.edge]);
                for (_, target_bytes) in self.storage.scan_prefix(&pfx)? {
                    let target_str = String::from_utf8_lossy(&target_bytes);
                    if let Some((t_tb, t_id)) = target_str.split_once(':') {
                        if let Some(ref want_tb) = hop.target_table {
                            if want_tb != t_tb {
                                continue;
                            }
                        }
                        next_frontier.push((t_tb.to_string(), t_id.to_string()));
                    }
                }
            }
            frontier = next_frontier;
        }

        let mut out = Vec::with_capacity(frontier.len());
        for (tb, id) in frontier {
            if let Some(field) = tail_field {
                if let Some(rec) = self.get_record(&tb, &id)? {
                    out.push(extract_field(&rec, field));
                }
            } else {
                out.push(Value::RecordId { tb, id });
            }
        }
        Ok(Value::Array(out))
    }

    fn eval_expr(&self, expr: &Expr, row: Option<&Value>, depth: u16) -> Result<Value> {
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
            Expr::Param(name) => Ok(self.params.get(name).cloned().unwrap_or(Value::None)),
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
            Expr::GraphTraverse { hops, tail_field } => {
                self.eval_graph_traverse(hops, tail_field.as_deref(), row)
            }
            Expr::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.eval_expr(item, row, depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            Expr::Object(pairs) => {
                let mut out = BTreeMap::new();
                for (k, v) in pairs {
                    out.insert(k.clone(), self.eval_expr(v, row, depth + 1)?);
                }
                Ok(Value::Object(out))
            }
            Expr::Unary { op, expr } => {
                let v = self.eval_expr(expr, row, depth + 1)?;
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
                    let l = self.eval_expr(left, row, depth + 1)?;
                    if !l.is_truthy() {
                        return Ok(Value::Bool(false));
                    }
                    let r = self.eval_expr(right, row, depth + 1)?;
                    return Ok(Value::Bool(r.is_truthy()));
                }
                if *op == BinaryOp::Or {
                    let l = self.eval_expr(left, row, depth + 1)?;
                    if l.is_truthy() {
                        return Ok(Value::Bool(true));
                    }
                    let r = self.eval_expr(right, row, depth + 1)?;
                    return Ok(Value::Bool(r.is_truthy()));
                }

                let l = self.eval_expr(left, row, depth + 1)?;
                let r = self.eval_expr(right, row, depth + 1)?;
                match op {
                    BinaryOp::Eq => Ok(Value::Bool(l == r)),
                    BinaryOp::Ne => Ok(Value::Bool(l != r)),
                    BinaryOp::Lt => Ok(Value::Bool(l.cmp_order(&r).is_lt())),
                    BinaryOp::Le => Ok(Value::Bool(l.cmp_order(&r).is_le())),
                    BinaryOp::Gt => Ok(Value::Bool(l.cmp_order(&r).is_gt())),
                    BinaryOp::Ge => Ok(Value::Bool(l.cmp_order(&r).is_ge())),
                    BinaryOp::Add => match (l, r) {
                        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a + b)),
                        (Value::String(a), Value::String(b)) => {
                            Ok(Value::String(format!("{}{}", a, b)))
                        }
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
                        (Value::String(hay), Value::String(needle)) => {
                            Ok(Value::Bool(hay.contains(needle.as_str())))
                        }
                        (Value::Array(arr), item) => Ok(Value::Bool(arr.contains(item))),
                        _ => Ok(Value::Bool(false)),
                    },
                    BinaryOp::In => match (&l, &r) {
                        (item, Value::Array(arr)) => Ok(Value::Bool(arr.contains(item))),
                        (Value::String(needle), Value::String(hay)) => {
                            Ok(Value::Bool(hay.contains(needle.as_str())))
                        }
                        _ => Ok(Value::Bool(false)),
                    },
                    BinaryOp::FtsMatch => {
                        let hay_tokens = tokenize_fts(&l.display_compact());
                        let query_tokens = tokenize_fts(&r.display_compact());
                        let matched = !query_tokens.is_empty()
                            && query_tokens.iter().all(|qt| hay_tokens.contains(qt));
                        Ok(Value::Bool(matched))
                    }
                    BinaryOp::VecKnn { .. } => Ok(Value::Bool(true)),
                    BinaryOp::And | BinaryOp::Or => unreachable!(),
                }
            }
            Expr::FunctionCall { name, args } => {
                let mut eval_args = Vec::with_capacity(args.len());
                for a in args {
                    eval_args.push(self.eval_expr(a, row, depth + 1)?);
                }
                eval_stdlib(name, &eval_args)
            }
        }
    }
}

fn matches_field_type(val: &Value, expected: &str) -> bool {
    let base = expected.split('<').next().unwrap_or(expected).to_ascii_lowercase();
    match base.as_str() {
        "any" | "option" => true,
        "string" => matches!(val, Value::String(_)),
        "int" => matches!(val, Value::Int(_)),
        "float" | "number" => matches!(val, Value::Int(_) | Value::Float(_)),
        "bool" => matches!(val, Value::Bool(_)),
        "array" => matches!(val, Value::Array(_)),
        "object" => matches!(val, Value::Object(_)),
        "record" => matches!(val, Value::RecordId { .. }),
        "datetime" => matches!(val, Value::DateTime(_) | Value::String(_)),
        _ => true,
    }
}

fn extract_last_key_part(key: &[u8]) -> String {
    let trimmed = key.strip_suffix(&[0x00]).unwrap_or(key);
    let last = trimmed.rsplit(|&b| b == 0x00).next().unwrap_or(trimmed);
    String::from_utf8_lossy(last).to_string()
}

fn expr_default_name(expr: &Expr) -> String {
    match expr {
        Expr::Ident(s) => s.clone(),
        Expr::FieldPath(parts) => parts.last().cloned().unwrap_or_else(|| "field".to_string()),
        Expr::FunctionCall { name, .. } => name.clone(),
        Expr::GraphTraverse { tail_field, .. } => {
            tail_field.clone().unwrap_or_else(|| "graph".to_string())
        }
        _ => "expr".to_string(),
    }
}

fn extract_field(row: &Value, field: &str) -> Value {
    match row {
        Value::Object(map) => map.get(field).cloned().unwrap_or(Value::None),
        _ => Value::None,
    }
}
