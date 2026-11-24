use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::codec::{decode_value, encode_value};
use crate::live::{LiveAction, LiveBroker};
#[cfg(not(feature = "vector"))]
use crate::parser::VectorMetric;
use crate::parser::{
    BinaryOp, Expr, GraphDir, GraphHop, IndexKind, MutationData, OnDeleteAction, Projection,
    ReturnMode, SetOp, Statement, Target, UnaryOp,
};
#[cfg(not(feature = "vector"))]
use crate::stdlib::{cosine_similarity, euclidean_distance, manhattan_distance};
use crate::stdlib::{eval_stdlib, tokenize_fts, value_to_vec};
use crate::storage::{
    encode_key, BatchOp, StorageBackend, PREFIX_ACCESS_META, PREFIX_ANALYZER_META, PREFIX_API_META,
    PREFIX_BUCKET_META, PREFIX_CHANGEFEED, PREFIX_EDGE_IN, PREFIX_EDGE_OUT, PREFIX_EVENT_META,
    PREFIX_FIELD_META, PREFIX_FTS, PREFIX_FUNCTION_META, PREFIX_INDEX, PREFIX_INDEX_META,
    PREFIX_MODULE_META, PREFIX_PARAM_META, PREFIX_RECORD, PREFIX_SEQUENCE_META, PREFIX_TABLE_META,
    PREFIX_USER_META, PREFIX_VEC, PREFIX_VERSION,
};
use crate::value::Value;

const MAX_EXPR_DEPTH: u16 = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TableMeta {
    name: String,
    schemafull: bool,
    #[serde(default)]
    changefeed: Option<String>,
    #[serde(default)]
    as_view: Option<Statement>,
    #[serde(default)]
    permissions_where: Option<Expr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldMeta {
    name: String,
    field_type: Option<String>,
    assert_expr: Option<Expr>,
    default_expr: Option<Expr>,
    #[serde(default)]
    value_expr: Option<Expr>,
    #[serde(default)]
    computed_expr: Option<Expr>,
    #[serde(default)]
    readonly: bool,
    #[serde(default = "default_on_delete")]
    on_delete: OnDeleteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SequenceMeta {
    name: String,
    batch: i64,
    next_val: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMeta {
    pub path: String,
    pub methods: Vec<String>,
    pub body: Expr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMeta {
    pub name: String,
    pub source: String,
}

fn default_on_delete() -> OnDeleteAction {
    OnDeleteAction::Ignore
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
    when_expr: Expr,
    then_stmt: Statement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FunctionMeta {
    name: String,
    params: Vec<String>,
    body: Expr,
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

/// Execution context with read-your-own-writes transactional overlay (`tx_overlay`).
/// When a transaction is active (`BEGIN ... COMMIT`), all writes stage in `tx_overlay`;
/// any error discards the overlay cleanly with zero partial writes to `redb`/`MemStorage`.
pub struct ExecContext<'a> {
    pub storage: &'a dyn StorageBackend,
    pub live: &'a LiveBroker,
    #[cfg(feature = "ml")]
    pub ml: Option<&'a crate::ml::MlRegistry>,
    pub module_invoker: Option<&'a (dyn Fn(&str, &str, &[Value]) -> Result<Value> + Send + Sync)>,
    pub ns: String,
    pub db: String,
    pub params: HashMap<String, Value>,
    pub step_budget: usize,
    tx_overlay: Option<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    in_event: bool,
    last_fts_score: f64,
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
            #[cfg(feature = "ml")]
            ml: None,
            module_invoker: None,
            ns,
            db,
            params,
            step_budget: 250_000,
            tx_overlay: None,
            in_event: false,
            last_fts_score: 0.0,
        }
    }

    /// Read-your-own-writes `get`: checks active `tx_overlay` before falling through to `storage`.
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(ref overlay) = self.tx_overlay {
            if let Some(entry) = overlay.get(key) {
                return Ok(entry.clone());
            }
        }
        self.storage.get(key)
    }

    /// Read-your-own-writes prefix scan: merges `tx_overlay` puts & tombstones on top of `storage`.
    fn scan_prefix_raw(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let base = self.storage.scan_prefix(prefix)?;
        let Some(ref overlay) = self.tx_overlay else {
            return Ok(base);
        };
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = base.into_iter().collect();
        for (k, v_opt) in overlay.range(prefix.to_vec()..) {
            if !k.starts_with(prefix) {
                break;
            }
            match v_opt {
                Some(v) => {
                    merged.insert(k.clone(), v.clone());
                }
                None => {
                    merged.remove(k);
                }
            }
        }
        Ok(merged.into_iter().collect())
    }

    fn put_raw(&mut self, key: Vec<u8>, val: Vec<u8>) -> Result<()> {
        if let Some(overlay) = self.tx_overlay.as_mut() {
            overlay.insert(key, Some(val));
            Ok(())
        } else {
            self.storage.put(&key, &val)
        }
    }

    fn delete_raw(&mut self, key: Vec<u8>) -> Result<()> {
        if let Some(overlay) = self.tx_overlay.as_mut() {
            overlay.insert(key, None);
            Ok(())
        } else {
            let _ = self.storage.delete(&key)?;
            Ok(())
        }
    }

    fn load_persistent_params(&mut self) -> Result<()> {
        let pfx = encode_key(PREFIX_PARAM_META, &[&self.ns, &self.db]);
        for (k_bytes, raw) in self.scan_prefix_raw(&pfx)? {
            let name = extract_last_key_part(&k_bytes);
            if !self.params.contains_key(&name) {
                if let Ok(val) = decode_value(&raw) {
                    self.params.insert(name, val);
                }
            }
        }
        Ok(())
    }

    pub fn execute_all(&mut self, stmts: &[Statement]) -> Result<Vec<Value>> {
        let _ = self.load_persistent_params();
        let mut last = Vec::new();
        for stmt in stmts {
            match self.execute_one(stmt) {
                Ok(res) => last = res,
                Err(e) => {
                    // Atomic rollback on any error inside an active transaction!
                    if self.tx_overlay.is_some() {
                        self.tx_overlay = None;
                    }
                    return Err(e);
                }
            }
        }
        Ok(last)
    }

    fn resolve_target(&self, target: &Target) -> Result<(String, Option<String>)> {
        match target {
            Target::Table(tb) | Target::RecordRange { tb, .. } => Ok((tb.clone(), None)),
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
        if let Some(raw) = self.get_raw(&key)? {
            return Ok(Some(decode_value(&raw)?));
        }
        Ok(None)
    }

    fn scan_target(&self, tb: &str, id: Option<&str>) -> Result<Vec<Value>> {
        if let Some(rec_id) = id {
            return Ok(self.get_record(tb, rec_id)?.into_iter().collect());
        }
        let prefix = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb]);
        let entries = self.scan_prefix_raw(&prefix)?;
        let mut rows = Vec::with_capacity(entries.len());
        for (_, raw) in entries {
            rows.push(decode_value(&raw)?);
        }
        Ok(rows)
    }

    /// Index-aware Volcano scan planner: chooses `IndexSeek` (`PREFIX_INDEX`), `FtsPostingScan`
    /// (`PREFIX_FTS`), `RecordRange`, `VersionScan`, `MaterializedView`, or `TableScan`.
    fn plan_and_scan(
        &self,
        target: &Target,
        where_clause: Option<&Expr>,
        version: Option<u64>,
    ) -> Result<(String, Vec<Value>)> {
        if let Target::RecordRange { tb, start, end } = target {
            let prefix = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb]);
            let entries = self.scan_prefix_raw(&prefix)?;
            let mut rows = Vec::new();
            for (k_bytes, raw) in entries {
                let rec_id = extract_last_key_part(&k_bytes);
                if rec_id.as_str() >= start.as_str() && rec_id.as_str() <= end.as_str() {
                    rows.push(decode_value(&raw)?);
                }
            }
            return Ok((format!("RecordRangeScan({}:{}..{})", tb, start, end), rows));
        }

        let (tb, id_opt) = self.resolve_target(target)?;

        if let Some(ver) = version {
            let ver_pfx = encode_key(PREFIX_VERSION, &[&self.ns, &self.db, &tb]);
            let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
            for (k_bytes, raw) in self.scan_prefix_raw(&ver_pfx)? {
                let tail = &k_bytes[ver_pfx.len()..];
                let parts: Vec<String> = tail
                    .split(|&b| b == 0x00)
                    .filter(|p| !p.is_empty())
                    .map(|p| String::from_utf8_lossy(p).to_string())
                    .collect();
                if parts.len() >= 2 {
                    let rec_id = &parts[0];
                    if let Some(ref want_id) = id_opt {
                        if want_id != rec_id {
                            continue;
                        }
                    }
                    if let Ok(seq) = parts[1].parse::<u64>() {
                        if seq <= ver {
                            if let Ok(v) = decode_value(&raw) {
                                by_id.insert(rec_id.clone(), v);
                            }
                        }
                    }
                }
            }
            return Ok((
                format!("VersionScan({}@v{})", tb, ver),
                by_id.into_values().collect(),
            ));
        }

        if id_opt.is_none() {
            if let Some(meta) = self.load_table_meta(&tb)? {
                if let Some(view_stmt) = meta.as_view {
                    let mut sub = ExecContext::new(
                        self.storage,
                        self.live,
                        self.ns.clone(),
                        self.db.clone(),
                        self.params.clone(),
                    );
                    return Ok((format!("MaterializedView({})", tb), sub.execute_one(&view_stmt)?));
                }
            }

            // IndexSeek optimization for `WHERE <col> = <literal/$param>`
            if let Some(Expr::Binary {
                left,
                op: BinaryOp::Eq,
                right,
            }) = where_clause
            {
                if let Expr::Ident(col) = left.as_ref() {
                    let indexes = self.load_indexes(&tb)?;
                    for idx in indexes {
                        if matches!(idx.kind, IndexKind::Standard | IndexKind::Unique)
                            && idx.columns.len() == 1
                            && &idx.columns[0] == col
                        {
                            if let Ok(val) = self.eval_expr(right, None, 0) {
                                let key_val = val.display_compact();
                                let scan_pfx = encode_key(
                                    PREFIX_INDEX,
                                    &[&self.ns, &self.db, &tb, &idx.name, &key_val],
                                );
                                let hits = self.scan_prefix_raw(&scan_pfx)?;
                                let mut rows = Vec::with_capacity(hits.len());
                                for (k_bytes, _) in hits {
                                    let rec_id = extract_last_key_part(&k_bytes);
                                    if let Some(rec) = self.get_record(&tb, &rec_id)? {
                                        rows.push(rec);
                                    }
                                }
                                return Ok((format!("IndexSeek({}.{})", tb, idx.name), rows));
                            }
                        }
                    }
                }
            }

            // Persisted FTS posting intersection optimization for `WHERE <col> @@ <query>`
            if let Some(Expr::Binary {
                left,
                op: BinaryOp::FtsMatch,
                right,
            }) = where_clause
            {
                if let Expr::Ident(col) = left.as_ref() {
                    let indexes = self.load_indexes(&tb)?;
                    for idx in indexes {
                        if idx.kind == IndexKind::FtsBm25 && idx.columns.contains(col) {
                            if let Ok(q_val) = self.eval_expr(right, None, 0) {
                                let terms = tokenize_fts(&q_val.display_compact());
                                if !terms.is_empty() {
                                    let mut doc_ids: Option<HashSet<String>> = None;
                                    for term in &terms {
                                        let pfx = encode_key(
                                            PREFIX_FTS,
                                            &[&self.ns, &self.db, &tb, &idx.name, term],
                                        );
                                        let hits: HashSet<String> = self
                                            .scan_prefix_raw(&pfx)?
                                            .into_iter()
                                            .map(|(k, _)| extract_last_key_part(&k))
                                            .collect();
                                        doc_ids = Some(match doc_ids {
                                            Some(prev) => prev.intersection(&hits).cloned().collect(),
                                            None => hits,
                                        });
                                    }
                                    let mut rows = Vec::new();
                                    for rid in doc_ids.unwrap_or_default() {
                                        if let Some(rec) = self.get_record(&tb, &rid)? {
                                            rows.push(rec);
                                        }
                                    }
                                    return Ok((
                                        format!("FtsPostingScan({}.{})", tb, idx.name),
                                        rows,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        let op_name = match &id_opt {
            Some(rid) => format!("RecordGet({}:{})", tb, rid),
            None => format!("TableScan({})", tb),
        };
        Ok((op_name, self.scan_target(&tb, id_opt.as_deref())?))
    }

    fn load_table_meta(&self, tb: &str) -> Result<Option<TableMeta>> {
        let key = encode_key(PREFIX_TABLE_META, &[&self.ns, &self.db, tb]);
        if let Some(raw) = self.get_raw(&key)? {
            return Ok(Some(serde_json::from_slice(&raw)?));
        }
        Ok(None)
    }

    fn load_fields(&self, tb: &str) -> Result<Vec<FieldMeta>> {
        let pfx = encode_key(PREFIX_FIELD_META, &[&self.ns, &self.db, tb]);
        let mut out = Vec::new();
        for (_, raw) in self.scan_prefix_raw(&pfx)? {
            out.push(serde_json::from_slice(&raw)?);
        }
        Ok(out)
    }

    fn load_indexes(&self, tb: &str) -> Result<Vec<IndexMeta>> {
        let pfx = encode_key(PREFIX_INDEX_META, &[&self.ns, &self.db, tb]);
        let mut out = Vec::new();
        for (_, raw) in self.scan_prefix_raw(&pfx)? {
            out.push(serde_json::from_slice(&raw)?);
        }
        Ok(out)
    }

    fn load_events(&self, tb: &str) -> Result<Vec<EventMeta>> {
        let pfx = encode_key(PREFIX_EVENT_META, &[&self.ns, &self.db, tb]);
        let mut out = Vec::new();
        for (_, raw) in self.scan_prefix_raw(&pfx)? {
            out.push(serde_json::from_slice(&raw)?);
        }
        Ok(out)
    }

    fn load_function(&self, name: &str) -> Result<Option<FunctionMeta>> {
        let key = encode_key(PREFIX_FUNCTION_META, &[&self.ns, &self.db, name]);
        if let Some(raw) = self.get_raw(&key)? {
            return Ok(Some(serde_json::from_slice(&raw)?));
        }
        Ok(None)
    }

    fn check_mutation_permission(&self, tb: &str, row: &Value) -> Result<()> {
        if !self.params.contains_key("auth") {
            return Ok(());
        }
        if let Some(meta) = self.load_table_meta(tb)? {
            if let Some(ref perm_expr) = meta.permissions_where {
                if !self.eval_expr(perm_expr, Some(row), 0)?.is_truthy() {
                    return Err(anyhow!(
                        "Permission denied on table '{}' for current $auth",
                        tb
                    ));
                }
            }
        }
        Ok(())
    }

    fn apply_defaults_computed_and_validate(
        &self,
        tb: &str,
        old_map: Option<&BTreeMap<String, Value>>,
        obj: &mut BTreeMap<String, Value>,
    ) -> Result<()> {
        let fields = self.load_fields(tb)?;

        // 0. Enforce READONLY immutability on updates
        if let Some(prev) = old_map {
            for f in &fields {
                if f.readonly {
                    if let Some(old_v) = prev.get(&f.name) {
                        if !matches!(old_v, Value::None | Value::Null) && obj.get(&f.name) != Some(old_v) {
                            return Err(anyhow!(
                                "Field '{}' on table '{}' is READONLY and cannot be modified",
                                f.name,
                                tb
                            ));
                        }
                    }
                }
            }
        }

        // 1. Apply DEFAULT expressions for missing fields
        for f in &fields {
            if !obj.contains_key(&f.name) {
                if let Some(ref def_expr) = f.default_expr {
                    let val = self.eval_expr(def_expr, None, 0)?;
                    obj.insert(f.name.clone(), val);
                }
            }
        }

        // 2. Compute `VALUE <expr>` derived fields
        let row_snapshot = Value::Object(obj.clone());
        for f in &fields {
            if let Some(ref val_expr) = f.value_expr {
                let computed = self.eval_expr(val_expr, Some(&row_snapshot), 0)?;
                obj.insert(f.name.clone(), computed);
            }
        }

        // 3. SCHEMAFULL check
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

        // 4. TYPE and ASSERT checks (binding `$value`)
        for f in &fields {
            if let Some(val) = obj.get(&f.name) {
                if let Some(ref expected_ty) = f.field_type {
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
                if let Some(ref assert_expr) = f.assert_expr {
                    let mut assert_params = self.params.clone();
                    assert_params.insert("value".to_string(), val.clone());
                    let sub_ctx = ExecContext::new(
                        self.storage,
                        self.live,
                        self.ns.clone(),
                        self.db.clone(),
                        assert_params,
                    );
                    let ok = sub_ctx.eval_expr(assert_expr, None, 0)?.is_truthy();
                    if !ok {
                        return Err(anyhow!(
                            "ASSERT constraint failed for field '{}' on table '{}'",
                            f.name,
                            tb
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn fire_events(
        &mut self,
        tb: &str,
        event_kind: &str,
        before: Option<Value>,
        after: Option<Value>,
    ) -> Result<()> {
        if self.in_event {
            return Ok(());
        }
        let events = self.load_events(tb)?;
        if events.is_empty() {
            return Ok(());
        }
        self.in_event = true;
        let saved_params = self.params.clone();
        let value_for_event = after.clone().or_else(|| before.clone()).unwrap_or(Value::None);
        self.params
            .insert("event".to_string(), Value::String(event_kind.to_string()));
        self.params
            .insert("before".to_string(), before.unwrap_or(Value::None));
        self.params
            .insert("after".to_string(), after.unwrap_or(Value::None));
        self.params.insert("value".to_string(), value_for_event);

        let mut err = None;
        for ev in events {
            match self.eval_expr(&ev.when_expr, None, 0) {
                Ok(v) if v.is_truthy() => {
                    if let Err(e) = self.execute_one(&ev.then_stmt) {
                        err = Some(e);
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }

        self.params = saved_params;
        self.in_event = false;
        if let Some(e) = err {
            return Err(e);
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
            if let Some(old) = old_row {
                self.remove_index_entries(tb, rec_id, &idx, old)?;
            }
            self.write_index_entries(tb, rec_id, &idx, new_row)?;
        }
        Ok(())
    }

    fn write_index_entries(
        &mut self,
        tb: &str,
        rec_id: &str,
        idx: &IndexMeta,
        new_row: &BTreeMap<String, Value>,
    ) -> Result<()> {
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
                    let existing = self.scan_prefix_raw(&scan_pfx)?;
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

    fn enforce_references_on_delete(&mut self, deleted_tb: &str, deleted_id: &str) -> Result<()> {
        let deleted_rid = Value::RecordId {
            tb: deleted_tb.to_string(),
            id: deleted_id.to_string(),
        };
        // Scan all defined fields across all tables in `(ns, db)` for `REFERENCE ON DELETE ...`
        let f_pfx = encode_key(PREFIX_FIELD_META, &[&self.ns, &self.db]);
        let all_fields = self.scan_prefix_raw(&f_pfx)?;
        for (k_bytes, raw) in all_fields {
            let Ok(fmeta) = serde_json::from_slice::<FieldMeta>(&raw) else {
                continue;
            };
            if fmeta.on_delete == OnDeleteAction::Ignore {
                continue;
            }
            // Key layout: 0x09 | ns | db | table | field_name
            let tail = &k_bytes[f_pfx.len()..];
            let parts: Vec<String> = tail
                .split(|&b| b == 0x00)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).to_string())
                .collect();
            let Some(ref_tb) = parts.first() else {
                continue;
            };
            let rows = self.scan_target(ref_tb, None)?;
            for row in rows {
                if let Value::Object(mut map) = row {
                    if map.get(&fmeta.name) == Some(&deleted_rid) {
                        let child_id = match map.get("id") {
                            Some(Value::RecordId { id, .. }) => id.clone(),
                            _ => continue,
                        };
                        match fmeta.on_delete {
                            OnDeleteAction::Reject => {
                                return Err(anyhow!(
                                    "Cannot delete {}:{}: referenced by {}:{}",
                                    deleted_tb,
                                    deleted_id,
                                    ref_tb,
                                    child_id
                                ));
                            }
                            OnDeleteAction::Cascade => {
                                let k = encode_key(
                                    PREFIX_RECORD,
                                    &[&self.ns, &self.db, ref_tb, &child_id],
                                );
                                self.delete_raw(k)?;
                            }
                            OnDeleteAction::Unset => {
                                map.remove(&fmeta.name);
                                let _ = self.save_record(
                                    ref_tb,
                                    &child_id,
                                    map,
                                    LiveAction::Update,
                                )?;
                            }
                            OnDeleteAction::Ignore => {}
                        }
                    }
                }
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
    ) -> Result<(Option<Value>, Value)> {
        let old_val = self.get_record(tb, id)?;
        let old_map = match &old_val {
            Some(Value::Object(m)) => Some(m.clone()),
            _ => None,
        };
        obj.insert(
            "id".to_string(),
            Value::RecordId {
                tb: tb.to_string(),
                id: id.to_string(),
            },
        );
        self.apply_defaults_computed_and_validate(tb, old_map.as_ref(), &mut obj)?;
        let candidate = Value::Object(obj.clone());
        self.check_mutation_permission(tb, &candidate)?;
        self.maintain_indexes_on_write(tb, id, old_map.as_ref(), &obj)?;

        let val = Value::Object(obj);
        let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, tb, id]);
        let bytes = encode_value(&val);
        self.put_raw(key, bytes.clone())?;

        // Append MVCC version entry (for `SELECT ... VERSION <seq>`)
        let ver_pfx = encode_key(PREFIX_VERSION, &[&self.ns, &self.db, tb, id]);
        let next_seq = (self.scan_prefix_raw(&ver_pfx)?.len() as u64) + 1;
        let ver_key = encode_key(
            PREFIX_VERSION,
            &[&self.ns, &self.db, tb, id, &format!("{:020}", next_seq)],
        );
        self.put_raw(ver_key, bytes)?;

        // Append Changefeed entry if enabled on table
        if let Some(meta) = self.load_table_meta(tb)? {
            if meta.changefeed.is_some() {
                let cf_pfx = encode_key(PREFIX_CHANGEFEED, &[&self.ns, &self.db, tb]);
                let cf_seq = (self.scan_prefix_raw(&cf_pfx)?.len() as u64) + 1;
                let cf_key = encode_key(
                    PREFIX_CHANGEFEED,
                    &[&self.ns, &self.db, tb, &format!("{:020}", cf_seq)],
                );
                let cf_entry = serde_json::json!({
                    "seq": cf_seq,
                    "action": format!("{:?}", action).to_uppercase(),
                    "record": val.to_json(),
                });
                self.put_raw(cf_key, serde_json::to_vec(&cf_entry)?)?;
            }
        }

        self.live.publish(&self.ns, &self.db, tb, action, &val);

        let ev_name = match action {
            LiveAction::Create => "CREATE",
            LiveAction::Update => "UPDATE",
            LiveAction::Delete => "DELETE",
        };
        self.fire_events(tb, ev_name, old_val.clone(), Some(val.clone()))?;
        Ok((old_val, val))
    }

    fn apply_mutation_data(
        &self,
        mut base: BTreeMap<String, Value>,
        data: &MutationData,
        current_row: Option<&Value>,
    ) -> Result<BTreeMap<String, Value>> {
        match data {
            MutationData::None => Ok(base),
            MutationData::Unset(fields) => {
                for f in fields {
                    base.remove(f);
                }
                Ok(base)
            }
            MutationData::Set(pairs) => {
                for (k, op, expr) in pairs {
                    let v = self.eval_expr(expr, current_row, 0)?;
                    match op {
                        SetOp::Assign => {
                            base.insert(k.clone(), v);
                        }
                        SetOp::AddAssign => {
                            let next = match (base.get(k), v) {
                                (Some(Value::Int(a)), Value::Int(b)) => Value::Int(a + b),
                                (Some(Value::Array(arr)), item) => {
                                    let mut a = arr.clone();
                                    a.push(item);
                                    Value::Array(a)
                                }
                                (Some(a), b) => match (a.as_f64(), b.as_f64()) {
                                    (Some(x), Some(y)) => Value::Float(x + y),
                                    _ => b,
                                },
                                (None, b) => b,
                            };
                            base.insert(k.clone(), next);
                        }
                        SetOp::SubAssign => {
                            let next = match (base.get(k), v) {
                                (Some(Value::Int(a)), Value::Int(b)) => Value::Int(a - b),
                                (Some(Value::Array(arr)), item) => {
                                    let a: Vec<Value> =
                                        arr.iter().filter(|x| *x != &item).cloned().collect();
                                    Value::Array(a)
                                }
                                (Some(a), b) => match (a.as_f64(), b.as_f64()) {
                                    (Some(x), Some(y)) => Value::Float(x - y),
                                    _ => b,
                                },
                                (None, b) => b,
                            };
                            base.insert(k.clone(), next);
                        }
                    }
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
            MutationData::Patch(expr) => {
                let patch_val = self.eval_expr(expr, current_row, 0)?;
                let ops = match patch_val {
                    Value::Array(arr) => arr,
                    other => return Err(anyhow!("PATCH expects an array of ops, got {:?}", other)),
                };
                for op_val in ops {
                    if let Value::Object(op_map) = op_val {
                        let op = op_map
                            .get("op")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let path = op_map
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim_start_matches('/');
                        if path.is_empty() {
                            continue;
                        }
                        match op.as_str() {
                            "add" | "replace" => {
                                if let Some(val) = op_map.get("value") {
                                    base.insert(path.to_string(), val.clone());
                                }
                            }
                            "remove" => {
                                base.remove(path);
                            }
                            _ => {}
                        }
                    }
                }
                Ok(base)
            }
        }
    }

    fn format_return(mode: ReturnMode, before: Option<Value>, after: Option<Value>) -> Option<Value> {
        match mode {
            ReturnMode::None => None,
            ReturnMode::Before => before,
            ReturnMode::After => after,
            ReturnMode::Diff => {
                let mut diffs = Vec::new();
                if let (Some(Value::Object(b)), Some(Value::Object(a))) = (&before, &after) {
                    for (k, v) in a {
                        if b.get(k) != Some(v) {
                            let mut op = BTreeMap::new();
                            op.insert(
                                "op".into(),
                                Value::String(
                                    if b.contains_key(k) { "replace" } else { "add" }.into(),
                                ),
                            );
                            op.insert("path".into(), Value::String(format!("/{}", k)));
                            op.insert("value".into(), v.clone());
                            diffs.push(Value::Object(op));
                        }
                    }
                    for k in b.keys() {
                        if !a.contains_key(k) {
                            let mut op = BTreeMap::new();
                            op.insert("op".into(), Value::String("remove".into()));
                            op.insert("path".into(), Value::String(format!("/{}", k)));
                            diffs.push(Value::Object(op));
                        }
                    }
                }
                Some(Value::Array(diffs))
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
            Statement::DefineParam { name, value } => {
                let val = self.eval_expr(value, None, 0)?;
                let key = encode_key(PREFIX_PARAM_META, &[&self.ns, &self.db, name]);
                self.put_raw(key, encode_value(&val))?;
                self.params.insert(name.clone(), val);
                Ok(Vec::new())
            }
            Statement::Remove { kind, name, table } => {
                match kind.as_str() {
                    "TABLE" => {
                        let mkey = encode_key(PREFIX_TABLE_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(mkey)?;
                        let rpfx = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, name]);
                        for (k, _) in self.scan_prefix_raw(&rpfx)? {
                            self.delete_raw(k)?;
                        }
                    }
                    "FIELD" => {
                        let tb = table.as_deref().unwrap_or("");
                        let k = encode_key(PREFIX_FIELD_META, &[&self.ns, &self.db, tb, name]);
                        self.delete_raw(k)?;
                    }
                    "INDEX" => {
                        let tb = table.as_deref().unwrap_or("");
                        let k = encode_key(PREFIX_INDEX_META, &[&self.ns, &self.db, tb, name]);
                        self.delete_raw(k)?;
                        for pfx_byte in [PREFIX_INDEX, PREFIX_FTS, PREFIX_VEC] {
                            let ipfx = encode_key(pfx_byte, &[&self.ns, &self.db, tb, name]);
                            for (ek, _) in self.scan_prefix_raw(&ipfx)? {
                                self.delete_raw(ek)?;
                            }
                        }
                    }
                    "EVENT" => {
                        let tb = table.as_deref().unwrap_or("");
                        let k = encode_key(PREFIX_EVENT_META, &[&self.ns, &self.db, tb, name]);
                        self.delete_raw(k)?;
                    }
                    "FUNCTION" => {
                        let k = encode_key(PREFIX_FUNCTION_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "USER" => {
                        let k = encode_key(PREFIX_USER_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "ACCESS" => {
                        let k = encode_key(PREFIX_ACCESS_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "ANALYZER" => {
                        let k = encode_key(PREFIX_ANALYZER_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "BUCKET" => {
                        let k = encode_key(PREFIX_BUCKET_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "PARAM" => {
                        let k = encode_key(PREFIX_PARAM_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                        self.params.remove(name);
                    }
                    "SEQUENCE" => {
                        let k = encode_key(PREFIX_SEQUENCE_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "API" => {
                        let k = encode_key(PREFIX_API_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    "MODULE" => {
                        let k = encode_key(PREFIX_MODULE_META, &[&self.ns, &self.db, name]);
                        self.delete_raw(k)?;
                    }
                    other => return Err(anyhow!("Unsupported REMOVE kind '{}'", other)),
                }
                Ok(Vec::new())
            }
            Statement::RebuildIndex { name, table } => {
                let ikey = encode_key(PREFIX_INDEX_META, &[&self.ns, &self.db, table, name]);
                let raw = self
                    .get_raw(&ikey)?
                    .ok_or_else(|| anyhow!("Index '{}' not found on table '{}'", name, table))?;
                let idx: IndexMeta = serde_json::from_slice(&raw)?;
                for pfx_byte in [PREFIX_INDEX, PREFIX_FTS, PREFIX_VEC] {
                    let ipfx = encode_key(pfx_byte, &[&self.ns, &self.db, table, name]);
                    for (ek, _) in self.scan_prefix_raw(&ipfx)? {
                        self.delete_raw(ek)?;
                    }
                }
                let rows = self.scan_target(table, None)?;
                for row in rows {
                    if let Value::Object(map) = row {
                        if let Some(Value::RecordId { id, .. }) = map.get("id") {
                            self.write_index_entries(table, id, &idx, &map)?;
                        }
                    }
                }
                Ok(Vec::new())
            }
            Statement::Return(expr) => Ok(vec![self.eval_expr(expr, None, 0)?]),
            Statement::InfoForDb => {
                let tb_pfx = encode_key(PREFIX_TABLE_META, &[&self.ns, &self.db]);
                let mut tables = BTreeMap::new();
                for (_, raw) in self.scan_prefix_raw(&tb_pfx)? {
                    if let Ok(m) = serde_json::from_slice::<TableMeta>(&raw) {
                        tables.insert(
                            m.name.clone(),
                            Value::String(format!(
                                "DEFINE TABLE {} {}",
                                m.name,
                                if m.schemafull { "SCHEMAFULL" } else { "SCHEMALESS" }
                            )),
                        );
                    }
                }
                let fn_pfx = encode_key(PREFIX_FUNCTION_META, &[&self.ns, &self.db]);
                let mut functions = BTreeMap::new();
                for (_, raw) in self.scan_prefix_raw(&fn_pfx)? {
                    if let Ok(f) = serde_json::from_slice::<FunctionMeta>(&raw) {
                        functions.insert(
                            f.name.clone(),
                            Value::String(format!("DEFINE FUNCTION {}", f.name)),
                        );
                    }
                }
                let mut info = BTreeMap::new();
                info.insert("tables".into(), Value::Object(tables));
                info.insert("functions".into(), Value::Object(functions));
                Ok(vec![Value::Object(info)])
            }
            Statement::InfoForTable(tb) => {
                let mut fields = BTreeMap::new();
                for f in self.load_fields(tb)? {
                    fields.insert(
                        f.name.clone(),
                        Value::String(f.field_type.unwrap_or_else(|| "any".into())),
                    );
                }
                let mut indexes = BTreeMap::new();
                for idx in self.load_indexes(tb)? {
                    indexes.insert(idx.name.clone(), Value::String(format!("{:?}", idx.kind)));
                }
                let mut events = BTreeMap::new();
                for ev in self.load_events(tb)? {
                    events.insert(ev.name.clone(), Value::String(ev.name));
                }
                let mut info = BTreeMap::new();
                info.insert("fields".into(), Value::Object(fields));
                info.insert("indexes".into(), Value::Object(indexes));
                info.insert("events".into(), Value::Object(events));
                Ok(vec![Value::Object(info)])
            }
            Statement::Begin => {
                self.tx_overlay = Some(BTreeMap::new());
                Ok(Vec::new())
            }
            Statement::Commit => {
                if let Some(overlay) = self.tx_overlay.take() {
                    let ops: Vec<BatchOp> = overlay
                        .into_iter()
                        .map(|(k, v_opt)| match v_opt {
                            Some(v) => BatchOp::Put(k, v),
                            None => BatchOp::Delete(k),
                        })
                        .collect();
                    self.storage.apply_batch(ops)?;
                }
                Ok(Vec::new())
            }
            Statement::Cancel => {
                self.tx_overlay = None;
                Ok(Vec::new())
            }
            Statement::DefineTable {
                name,
                schemafull,
                changefeed,
                as_view,
                permissions_where,
                ..
            } => {
                let key = encode_key(PREFIX_TABLE_META, &[&self.ns, &self.db, name]);
                let meta = TableMeta {
                    name: name.clone(),
                    schemafull: *schemafull,
                    changefeed: changefeed.clone(),
                    as_view: as_view.as_deref().cloned(),
                    permissions_where: permissions_where.clone(),
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineBucket { name, backend } => {
                #[cfg(feature = "files")]
                {
                    crate::files::define_bucket(self.storage, &self.ns, &self.db, name, backend)?;
                    Ok(Vec::new())
                }
                #[cfg(not(feature = "files"))]
                {
                    let _ = (name, backend);
                    Err(anyhow!("Enable feature 'files' to use DEFINE BUCKET"))
                }
            }
            Statement::DefineUser {
                name,
                level,
                password,
                roles,
            } => {
                #[cfg(feature = "auth")]
                {
                    crate::auth::save_user(
                        self.storage,
                        &self.ns,
                        &self.db,
                        name,
                        level,
                        password,
                        roles.clone(),
                    )?;
                    Ok(Vec::new())
                }
                #[cfg(not(feature = "auth"))]
                {
                    let _ = (name, level, password, roles);
                    Err(anyhow!("Enable feature 'auth' to use DEFINE USER"))
                }
            }
            Statement::DefineAccess { name, access_type } => {
                #[cfg(feature = "auth")]
                {
                    crate::auth::save_access(
                        self.storage,
                        &self.ns,
                        &self.db,
                        name,
                        access_type,
                        None,
                    )?;
                    Ok(Vec::new())
                }
                #[cfg(not(feature = "auth"))]
                {
                    let _ = (name, access_type);
                    Err(anyhow!("Enable feature 'auth' to use DEFINE ACCESS"))
                }
            }
            Statement::DefineAnalyzer {
                name,
                tokenizers,
                filters,
            } => {
                let key = encode_key(PREFIX_ANALYZER_META, &[&self.ns, &self.db, name]);
                let meta = serde_json::json!({
                    "name": name,
                    "tokenizers": tokenizers,
                    "filters": filters,
                });
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::ShowChanges {
                table,
                since,
                limit,
            } => {
                let cf_pfx = encode_key(PREFIX_CHANGEFEED, &[&self.ns, &self.db, table]);
                let mut out = Vec::new();
                for (_, raw) in self.scan_prefix_raw(&cf_pfx)? {
                    if let Ok(jv) = serde_json::from_slice::<serde_json::Value>(&raw) {
                        let seq = jv.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                        if let Some(min_seq) = since {
                            if seq < *min_seq {
                                continue;
                            }
                        }
                        out.push(Value::from_json(&jv));
                        if let Some(lim) = limit {
                            if out.len() >= *lim {
                                break;
                            }
                        }
                    }
                }
                Ok(out)
            }
            Statement::If {
                cond,
                then_body,
                else_body,
            } => {
                if self.eval_expr(cond, None, 0)?.is_truthy() {
                    self.execute_all(then_body)
                } else {
                    self.execute_all(else_body)
                }
            }
            Statement::For { var, iter, body } => {
                let items = match self.eval_expr(iter, None, 0)? {
                    Value::Array(arr) => arr,
                    other => vec![other],
                };
                let mut last = Vec::new();
                for item in items {
                    self.params.insert(var.clone(), item);
                    last = self.execute_all(body)?;
                }
                Ok(last)
            }
            Statement::Throw(expr) => {
                let msg = self.eval_expr(expr, None, 0)?.display_compact();
                Err(anyhow!("THROW: {}", msg))
            }
            Statement::Sleep(dur) => {
                let secs = crate::stdlib::parse_duration_secs(dur).clamp(0, 5) as u64;
                if secs > 0 {
                    std::thread::sleep(Duration::from_secs(secs));
                }
                Ok(Vec::new())
            }
            Statement::DefineField {
                name,
                table,
                field_type,
                assert_expr,
                default_expr,
                value_expr,
                computed_expr,
                readonly,
                on_delete,
                ..
            } => {
                let key = encode_key(PREFIX_FIELD_META, &[&self.ns, &self.db, table, name]);
                let meta = FieldMeta {
                    name: name.clone(),
                    field_type: field_type.clone(),
                    assert_expr: assert_expr.clone(),
                    default_expr: default_expr.clone(),
                    value_expr: value_expr.clone(),
                    computed_expr: computed_expr.clone(),
                    readonly: *readonly,
                    on_delete: *on_delete,
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineSequence { name, batch, start } => {
                let key = encode_key(PREFIX_SEQUENCE_META, &[&self.ns, &self.db, name]);
                let meta = SequenceMeta {
                    name: name.clone(),
                    batch: *batch,
                    next_val: *start,
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineApi {
                path,
                methods,
                body,
            } => {
                let key = encode_key(PREFIX_API_META, &[&self.ns, &self.db, path]);
                let meta = ApiMeta {
                    path: path.clone(),
                    methods: methods.clone(),
                    body: body.clone(),
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineModule { name, source } => {
                let key = encode_key(PREFIX_MODULE_META, &[&self.ns, &self.db, name]);
                let meta = ModuleMeta {
                    name: name.clone(),
                    source: source.clone(),
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
            Statement::DefineEvent {
                name,
                table,
                when_expr,
                then_stmt,
                ..
            } => {
                let key = encode_key(PREFIX_EVENT_META, &[&self.ns, &self.db, table, name]);
                let meta = EventMeta {
                    name: name.clone(),
                    when_expr: when_expr.clone(),
                    then_stmt: (**then_stmt).clone(),
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::DefineFunction { name, params, body } => {
                let key = encode_key(PREFIX_FUNCTION_META, &[&self.ns, &self.db, name]);
                let meta = FunctionMeta {
                    name: name.clone(),
                    params: params.clone(),
                    body: body.clone(),
                };
                self.put_raw(key, serde_json::to_vec(&meta)?)?;
                Ok(Vec::new())
            }
            Statement::LiveSelect { table, .. } => {
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

                let (_, saved) = self.save_record(edge, &edge_id, obj, LiveAction::Create)?;

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
            Statement::Create { target, data, ret } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let id = id_opt.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, &tb, &id]);
                if self.get_raw(&key)?.is_some() {
                    return Err(anyhow!("Record {}:{} already exists", tb, id));
                }
                let obj = self.apply_mutation_data(BTreeMap::new(), data, None)?;
                let (before, saved) = self.save_record(&tb, &id, obj, LiveAction::Create)?;
                Ok(Self::format_return(*ret, before, Some(saved))
                    .into_iter()
                    .collect())
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
                        let (_, saved) = self.save_record(table, &id, obj, LiveAction::Create)?;
                        inserted.push(saved);
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
                                let (_, saved) =
                                    self.save_record(table, &id, obj, LiveAction::Create)?;
                                inserted.push(saved);
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
                ret,
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
                        let (before, after) =
                            self.save_record(&tb, &rec_id, next_map, LiveAction::Update)?;
                        if let Some(v) = Self::format_return(*ret, before, Some(after)) {
                            updated.push(v);
                        }
                    }
                }
                Ok(updated)
            }
            Statement::Upsert {
                target,
                data,
                where_clause,
                ret,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let existing = self.scan_target(&tb, id_opt.as_deref())?;
                if existing.is_empty() {
                    let rec_id = id_opt.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
                    let next_map = self.apply_mutation_data(BTreeMap::new(), data, None)?;
                    let (before, after) =
                        self.save_record(&tb, &rec_id, next_map, LiveAction::Create)?;
                    return Ok(Self::format_return(*ret, before, Some(after))
                        .into_iter()
                        .collect());
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
                        let (before, after) =
                            self.save_record(&tb, &rec_id, next_map, LiveAction::Update)?;
                        if let Some(v) = Self::format_return(*ret, before, Some(after)) {
                            updated.push(v);
                        }
                    }
                }
                Ok(updated)
            }
            Statement::Delete {
                target,
                where_clause,
                ret,
            } => {
                let (tb, id_opt) = self.resolve_target(target)?;
                let existing = self.scan_target(&tb, id_opt.as_deref())?;
                let indexes = self.load_indexes(&tb)?;
                let mut returned = Vec::new();
                for row in existing {
                    if let Some(pred) = where_clause {
                        if !self.eval_expr(pred, Some(&row), 0)?.is_truthy() {
                            continue;
                        }
                    }
                    self.check_mutation_permission(&tb, &row)?;
                    if let Value::Object(map) = &row {
                        if let Some(Value::RecordId { id, .. }) = map.get("id") {
                            self.enforce_references_on_delete(&tb, id)?;
                            for idx in &indexes {
                                self.remove_index_entries(&tb, id, idx, map)?;
                            }
                            let key = encode_key(PREFIX_RECORD, &[&self.ns, &self.db, &tb, id]);
                            self.delete_raw(key)?;
                            self.live
                                .publish(&self.ns, &self.db, &tb, LiveAction::Delete, &row);
                            self.fire_events(&tb, "DELETE", Some(row.clone()), None)?;
                            if *ret == ReturnMode::Before {
                                returned.push(row);
                            }
                        }
                    }
                }
                Ok(returned)
            }
            Statement::Select {
                value_only,
                projections,
                omit,
                target,
                where_clause,
                split,
                group_by,
                order_by,
                limit,
                start,
                fetch,
                version,
                explain,
                timeout_ms,
            } => {
                let started_at = Instant::now();
                let (tb, _) = self.resolve_target(target)?;
                let (plan_op, mut raw_rows) =
                    self.plan_and_scan(target, where_clause.as_ref(), *version)?;

                if *explain {
                    let mut plan = BTreeMap::new();
                    plan.insert("operation".into(), Value::String(plan_op));
                    plan.insert("rows_scanned".into(), Value::Int(raw_rows.len() as i64));
                    return Ok(vec![Value::Object(plan)]);
                }

                // Evaluate read-time `COMPUTED` fields dynamically on every read
                let computed_fields: Vec<FieldMeta> = self
                    .load_fields(&tb)?
                    .into_iter()
                    .filter(|f| f.computed_expr.is_some())
                    .collect();
                if !computed_fields.is_empty() {
                    for row in &mut raw_rows {
                        let snap = row.clone();
                        if let Value::Object(ref mut map) = row {
                            for cf in &computed_fields {
                                if let Some(ref cexpr) = cf.computed_expr {
                                    if let Ok(cv) = self.eval_expr(cexpr, Some(&snap), 0) {
                                        map.insert(cf.name.clone(), cv);
                                    }
                                }
                            }
                        }
                    }
                }

                // Enforce row-level PERMISSIONS WHERE if defined on table and $auth is set
                if let Some(meta) = self.load_table_meta(&tb)? {
                    if let Some(ref perm_expr) = meta.permissions_where {
                        if self.params.contains_key("auth") {
                            let mut allowed = Vec::new();
                            for r in raw_rows {
                                if self.eval_expr(perm_expr, Some(&r), 0)?.is_truthy() {
                                    allowed.push(r);
                                }
                            }
                            raw_rows = allowed;
                        }
                    }
                }

                // WHERE filter (with HNSW Vector KNN, BM25 FTS scoring, and TIMEOUT check)
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

                    #[cfg(feature = "vector")]
                    {
                        let mut hnsw = crate::vector_hnsw::HnswIndex::new(*metric, 16, 64);
                        let mut by_id: HashMap<String, Value> = HashMap::new();
                        for (idx_i, row) in raw_rows.into_iter().enumerate() {
                            if let Ok(v) = self.eval_expr(left, Some(&row), 0) {
                                if let Some(rv) = value_to_vec(&v) {
                                    let rid = idx_i.to_string();
                                    hnsw.insert(rid.clone(), rv);
                                    by_id.insert(rid, row);
                                }
                            }
                        }
                        hnsw.search_knn(&query_vec, *k, (*k * 4).max(32))
                            .into_iter()
                            .filter_map(|(rid, _)| by_id.remove(&rid))
                            .collect()
                    }
                    #[cfg(not(feature = "vector"))]
                    {
                        let mut scored: Vec<(f64, Value)> = Vec::new();
                        for row in raw_rows {
                            if let Ok(v) = self.eval_expr(left, Some(&row), 0) {
                                if let Some(rv) = value_to_vec(&v) {
                                    let dist = match metric {
                                        VectorMetric::Cosine => {
                                            1.0 - cosine_similarity(&rv, &query_vec)
                                        }
                                        VectorMetric::Euclidean => {
                                            euclidean_distance(&rv, &query_vec)
                                        }
                                        VectorMetric::Manhattan => {
                                            manhattan_distance(&rv, &query_vec)
                                        }
                                    };
                                    scored.push((dist, row));
                                }
                            }
                        }
                        scored.sort_by(|a, b| {
                            a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
                        });
                        scored.into_iter().take(*k).map(|(_, r)| r).collect()
                    }
                } else if let Some(Expr::Binary {
                    left: _fts_left,
                    op: BinaryOp::FtsMatch,
                    right: _fts_right,
                }) = where_clause
                {
                    #[cfg(feature = "fts")]
                    {
                        let query_str = self.eval_expr(_fts_right, None, 0)?.display_compact();
                        let texts: Vec<String> = raw_rows
                            .iter()
                            .map(|r| {
                                self.eval_expr(_fts_left, Some(r), 0)
                                    .map(|v| v.display_compact())
                                    .unwrap_or_default()
                            })
                            .collect();
                        let scorer = crate::search::Bm25Scorer::from_corpus(
                            texts.iter().map(|s| s.as_str()),
                        );
                        let mut scored = Vec::new();
                        for (row, text) in raw_rows.into_iter().zip(texts.iter()) {
                            let sc = scorer.score(text, &query_str);
                            if sc > 0.0 {
                                scored.push((sc, row));
                            }
                        }
                        scored.sort_by(|a, b| {
                            b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal)
                        });
                        if let Some((top_sc, _)) = scored.first() {
                            self.last_fts_score = *top_sc;
                        }
                        scored.into_iter().map(|(_, r)| r).collect()
                    }
                    #[cfg(not(feature = "fts"))]
                    {
                        let mut acc = Vec::new();
                        for row in raw_rows {
                            if self
                                .eval_expr(where_clause.as_ref().unwrap(), Some(&row), 0)?
                                .is_truthy()
                            {
                                acc.push(row);
                            }
                        }
                        acc
                    }
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
                        if let Some(ms) = timeout_ms {
                            if *ms > 0 && started_at.elapsed().as_millis() as u64 > *ms {
                                return Err(anyhow!("Query exceeded TIMEOUT ({}ms)", ms));
                            }
                        }
                        if self.eval_expr(pred, Some(&row), 0)?.is_truthy() {
                            acc.push(row);
                        }
                    }
                    acc
                } else {
                    raw_rows
                };

                // Optional SPLIT ON <array_field>
                if let Some(split_field) = split {
                    let mut expanded = Vec::new();
                    for row in filtered {
                        if let Value::Object(ref map) = row {
                            if let Some(Value::Array(items)) = map.get(split_field) {
                                for item in items {
                                    let mut cloned = map.clone();
                                    cloned.insert(split_field.clone(), item.clone());
                                    expanded.push(Value::Object(cloned));
                                }
                                continue;
                            }
                        }
                        expanded.push(row);
                    }
                    filtered = expanded;
                }

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

                    let mut out_val = if !group_by.is_empty() {
                        row
                    } else if *value_only {
                        if let Some(Projection::Expr { expr, .. }) = projections.first() {
                            self.eval_expr(expr, Some(&row), 0)?
                        } else {
                            row
                        }
                    } else if projections.len() == 1 && matches!(projections[0], Projection::All) {
                        row
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
                        Value::Object(out)
                    };

                    if !omit.is_empty() {
                        if let Value::Object(ref mut map) = out_val {
                            for f in omit {
                                map.remove(f);
                            }
                        }
                    }

                    projected.push(out_val);
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
            let prefix_byte = match hop.dir {
                GraphDir::Out => PREFIX_EDGE_OUT,
                GraphDir::In => PREFIX_EDGE_IN,
            };
            let mut collected: Vec<(String, String)> = Vec::new();
            let mut current_level = frontier.clone();
            let mut visited = HashSet::new();

            for depth in 1..=hop.max_depth.max(1) {
                let mut next_level = Vec::new();
                for (cur_tb, cur_id) in &current_level {
                    let cur_ref = format!("{}:{}", cur_tb, cur_id);
                    let pfx = encode_key(prefix_byte, &[&self.ns, &self.db, &cur_ref, &hop.edge]);
                    for (_, target_bytes) in self.scan_prefix_raw(&pfx)? {
                        let target_str = String::from_utf8_lossy(&target_bytes);
                        if let Some((t_tb, t_id)) = target_str.split_once(':') {
                            if let Some(ref want_tb) = hop.target_table {
                                if want_tb != t_tb {
                                    continue;
                                }
                            }
                            let pair = (t_tb.to_string(), t_id.to_string());
                            if visited.insert(pair.clone()) {
                                next_level.push(pair.clone());
                                if depth >= hop.min_depth {
                                    collected.push(pair);
                                }
                            }
                        }
                    }
                }
                if next_level.is_empty() {
                    break;
                }
                current_level = next_level;
            }
            frontier = collected;
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

    fn eval_closure(&self, params: &[String], body: &Expr, args: &[Value], depth: u16) -> Result<Value> {
        let mut pmap = self.params.clone();
        for (p, v) in params.iter().zip(args.iter()) {
            pmap.insert(p.clone(), v.clone());
        }
        let sub = ExecContext::new(
            self.storage,
            self.live,
            self.ns.clone(),
            self.db.clone(),
            pmap,
        );
        sub.eval_expr(body, None, depth + 1)
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
                if let Some(first) = parts.first() {
                    if let Some(pname) = first.strip_prefix('$') {
                        let mut cur = self.params.get(pname).cloned().unwrap_or(Value::None);
                        for p in &parts[1..] {
                            cur = extract_field(&cur, p);
                        }
                        return Ok(cur);
                    }
                }
                let mut cur = match row {
                    Some(r) => r.clone(),
                    None => return Ok(Value::None),
                };
                for p in parts {
                    cur = extract_field(&cur, p);
                }
                Ok(cur)
            }
            Expr::Index { target, index } => {
                let tv = self.eval_expr(target, row, depth + 1)?;
                let iv = self.eval_expr(index, row, depth + 1)?;
                match (tv, iv) {
                    (Value::Array(arr), Value::Int(i)) => {
                        let idx = if i < 0 {
                            (arr.len() as i64 + i) as usize
                        } else {
                            i as usize
                        };
                        Ok(arr.get(idx).cloned().unwrap_or(Value::None))
                    }
                    (Value::Object(map), Value::String(k)) => {
                        Ok(map.get(&k).cloned().unwrap_or(Value::None))
                    }
                    _ => Ok(Value::None),
                }
            }
            Expr::ArrayFilter { target, pred } => {
                let tv = self.eval_expr(target, row, depth + 1)?;
                if let Value::Array(arr) = tv {
                    let mut out = Vec::new();
                    for item in arr {
                        let mut pmap = self.params.clone();
                        pmap.insert("this".into(), item.clone());
                        let sub = ExecContext::new(
                            self.storage,
                            self.live,
                            self.ns.clone(),
                            self.db.clone(),
                            pmap,
                        );
                        if sub.eval_expr(pred, Some(&item), depth + 1)?.is_truthy() {
                            out.push(item);
                        }
                    }
                    return Ok(Value::Array(out));
                }
                Ok(Value::Array(Vec::new()))
            }
            Expr::Range {
                start,
                end,
                inclusive,
            } => {
                let s = self.eval_expr(start, row, depth + 1)?;
                let e = self.eval_expr(end, row, depth + 1)?;
                if let (Value::Int(a), Value::Int(b)) = (s, e) {
                    let limit = 10_000i64;
                    let upper = if *inclusive { b } else { b - 1 };
                    let mut out = Vec::new();
                    let mut cur = a;
                    while cur <= upper && (out.len() as i64) < limit {
                        out.push(Value::Int(cur));
                        cur += 1;
                    }
                    return Ok(Value::Array(out));
                }
                Ok(Value::Array(Vec::new()))
            }
            Expr::Cast { ty, expr } => {
                let v = self.eval_expr(expr, row, depth + 1)?;
                eval_stdlib(&format!("type::{}", ty.to_ascii_lowercase()), &[v])
            }
            Expr::IfExpr {
                cond,
                then_expr,
                else_expr,
            } => {
                if self.eval_expr(cond, row, depth + 1)?.is_truthy() {
                    self.eval_expr(then_expr, row, depth + 1)
                } else {
                    self.eval_expr(else_expr, row, depth + 1)
                }
            }
            Expr::Closure { .. } => Ok(Value::None),
            Expr::GraphTraverse { hops, tail_field } => {
                self.eval_graph_traverse(hops, tail_field.as_deref(), row)
            }
            Expr::Subquery(sub_stmt) => {
                let mut sub_ctx = ExecContext::new(
                    self.storage,
                    self.live,
                    self.ns.clone(),
                    self.db.clone(),
                    self.params.clone(),
                );
                let rows = sub_ctx.execute_one(sub_stmt)?;
                Ok(Value::Array(rows))
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
                if *op == BinaryOp::NullCoalesce {
                    let l = self.eval_expr(left, row, depth + 1)?;
                    return if matches!(l, Value::None | Value::Null) {
                        self.eval_expr(right, row, depth + 1)
                    } else {
                        Ok(l)
                    };
                }
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
                    BinaryOp::And | BinaryOp::Or | BinaryOp::NullCoalesce => unreachable!(),
                }
            }
            Expr::FunctionCall { name, args } => {
                // Higher-order closure array functions (`array::map`, `array::filter`, `array::any`, `array::all`)
                let lname = name.to_ascii_lowercase();
                if matches!(
                    lname.as_str(),
                    "array::map" | "array::filter" | "array::any" | "array::all"
                ) && args.len() == 2
                {
                    if let Expr::Closure { params, body } = &args[1] {
                        let arr_val = self.eval_expr(&args[0], row, depth + 1)?;
                        if let Value::Array(items) = arr_val {
                            match lname.as_str() {
                                "array::map" => {
                                    let mut out = Vec::with_capacity(items.len());
                                    for it in items {
                                        out.push(self.eval_closure(params, body, &[it], depth)?);
                                    }
                                    return Ok(Value::Array(out));
                                }
                                "array::filter" => {
                                    let mut out = Vec::new();
                                    for it in items {
                                        if self
                                            .eval_closure(params, body, &[it.clone()], depth)?
                                            .is_truthy()
                                        {
                                            out.push(it);
                                        }
                                    }
                                    return Ok(Value::Array(out));
                                }
                                "array::any" => {
                                    for it in items {
                                        if self.eval_closure(params, body, &[it], depth)?.is_truthy()
                                        {
                                            return Ok(Value::Bool(true));
                                        }
                                    }
                                    return Ok(Value::Bool(false));
                                }
                                "array::all" => {
                                    for it in items {
                                        if !self.eval_closure(params, body, &[it], depth)?.is_truthy()
                                        {
                                            return Ok(Value::Bool(false));
                                        }
                                    }
                                    return Ok(Value::Bool(true));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                let mut eval_args = Vec::with_capacity(args.len());
                for a in args {
                    eval_args.push(self.eval_expr(a, row, depth + 1)?);
                }
                if lname == "search::score" {
                    return Ok(Value::Float(self.last_fts_score));
                }
                if lname == "session::ns" {
                    return Ok(Value::String(self.ns.clone()));
                }
                if lname == "session::db" {
                    return Ok(Value::String(self.db.clone()));
                }
                if lname == "graph::shortest_path" {
                    return self.eval_shortest_path(&eval_args);
                }
                if lname == "sequence::nextval" {
                    let seq_name = eval_args
                        .first()
                        .ok_or_else(|| anyhow!("sequence::nextval requires sequence name"))?
                        .display_compact();
                    let skey = encode_key(PREFIX_SEQUENCE_META, &[&self.ns, &self.db, &seq_name]);
                    let raw = self
                        .get_raw(&skey)?
                        .ok_or_else(|| anyhow!("Sequence '{}' is not defined", seq_name))?;
                    let mut meta: SequenceMeta = serde_json::from_slice(&raw)?;
                    let val = meta.next_val;
                    meta.next_val += 1;
                    self.storage.put(&skey, &serde_json::to_vec(&meta)?)?;
                    return Ok(Value::Int(val));
                }
                if name.starts_with("mod::") {
                    // Look up Surrealism module (`mod::my_mod::func` -> module `mod::my_mod`)
                    let parts: Vec<&str> = name.split("::").collect();
                    let mod_name = if parts.len() >= 2 {
                        format!("{}::{}", parts[0], parts[1])
                    } else {
                        name.clone()
                    };
                    let fn_name = parts.last().copied().unwrap_or(name.as_str());
                    let mkey = encode_key(PREFIX_MODULE_META, &[&self.ns, &self.db, &mod_name]);
                    let raw = self
                        .get_raw(&mkey)?
                        .ok_or_else(|| anyhow!("Module '{}' is not defined", mod_name))?;
                    let meta: ModuleMeta = serde_json::from_slice(&raw)?;
                    if let Some(invoker) = self.module_invoker {
                        return invoker(&meta.source, fn_name, &eval_args);
                    }
                    return Err(anyhow!(
                        "Module '{}' registered (source '{}'), attach a Wasm CrystalEngine invoker to execute",
                        mod_name,
                        meta.source
                    ));
                }
                #[cfg(feature = "files")]
                if lname.starts_with("file::") {
                    return crate::files::eval_file_fn(
                        self.storage,
                        &self.ns,
                        &self.db,
                        &lname,
                        &eval_args,
                    );
                }
                #[cfg(feature = "ml")]
                if name.starts_with("ml::") {
                    if let Some(reg) = self.ml {
                        return reg.eval(name, &eval_args);
                    }
                }
                if name.starts_with("fn::") {
                    if let Some(fmeta) = self.load_function(name)? {
                        return self.eval_closure(&fmeta.params, &fmeta.body, &eval_args, depth);
                    }
                }
                eval_stdlib(name, &eval_args)
            }
        }
    }

    fn eval_shortest_path(&self, args: &[Value]) -> Result<Value> {
        let start = args
            .first()
            .ok_or_else(|| anyhow!("graph::shortest_path requires (from, edge, to)"))?
            .display_compact();
        let edge = args
            .get(1)
            .ok_or_else(|| anyhow!("graph::shortest_path requires (from, edge, to)"))?
            .display_compact();
        let goal = args
            .get(2)
            .ok_or_else(|| anyhow!("graph::shortest_path requires (from, edge, to)"))?
            .display_compact();

        let mut queue = std::collections::VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back(vec![start.clone()]);
        visited.insert(start);

        while let Some(path) = queue.pop_front() {
            let curr = path.last().unwrap();
            if curr == &goal {
                let ids: Vec<Value> = path
                    .into_iter()
                    .map(|s| {
                        if let Some((tb, id)) = s.split_once(':') {
                            Value::RecordId {
                                tb: tb.to_string(),
                                id: id.to_string(),
                            }
                        } else {
                            Value::String(s)
                        }
                    })
                    .collect();
                return Ok(Value::Array(ids));
            }
            if path.len() > 16 {
                continue;
            }
            let pfx = encode_key(PREFIX_EDGE_OUT, &[&self.ns, &self.db, curr, &edge]);
            for (_, target_bytes) in self.scan_prefix_raw(&pfx)? {
                let next = String::from_utf8_lossy(&target_bytes).to_string();
                if visited.insert(next.clone()) {
                    let mut next_path = path.clone();
                    next_path.push(next);
                    queue.push_back(next_path);
                }
            }
        }
        Ok(Value::Array(Vec::new()))
    }
}

fn matches_field_type(val: &Value, expected: &str) -> bool {
    let base = expected
        .split('<')
        .next()
        .unwrap_or(expected)
        .to_ascii_lowercase();
    match base.as_str() {
        "any" | "option" => true,
        "string" => matches!(val, Value::String(_)),
        "int" => matches!(val, Value::Int(_)),
        "float" | "number" => matches!(val, Value::Int(_) | Value::Float(_) | Value::Decimal(_)),
        "decimal" => matches!(val, Value::Decimal(_) | Value::Float(_) | Value::Int(_)),
        "duration" => matches!(val, Value::Duration(_) | Value::String(_)),
        "bool" => matches!(val, Value::Bool(_)),
        "array" => matches!(val, Value::Array(_)),
        "object" => matches!(val, Value::Object(_)),
        "record" => matches!(val, Value::RecordId { .. }),
        "datetime" => matches!(val, Value::DateTime(_) | Value::String(_)),
        "bytes" => matches!(val, Value::Bytes(_)),
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
