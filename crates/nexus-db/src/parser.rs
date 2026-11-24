use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Graph traversal direction for `->edge->target` / `<-edge<-source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphDir {
    Out,
    In,
}

/// One hop in a graph traversal expression (e.g. `->knows->person`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphHop {
    pub dir: GraphDir,
    pub edge: String,
    pub target_table: Option<String>,
}

/// Index kind for `DEFINE INDEX`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexKind {
    Standard,
    Unique,
    FtsBm25,
    VectorHnsw { dim: usize, metric: VectorMetric },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VectorMetric {
    Cosine,
    Euclidean,
    Manhattan,
}

/// Return mode for mutation statements (`RETURN NONE | BEFORE | AFTER | DIFF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReturnMode {
    After,
    Before,
    None,
    Diff,
}

/// SurrealQL AST Statements (Full Parity: CRUD, Graph, Schema, Indexes, Events, Functions, Live Queries, Info, Subqueries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    Use {
        ns: Option<String>,
        db: Option<String>,
    },
    Let {
        name: String,
        expr: Expr,
    },
    Return(Expr),
    InfoForDb,
    InfoForTable(String),
    Begin,
    Commit,
    Cancel,
    DefineTable {
        name: String,
        if_not_exists: bool,
        schemafull: bool,
    },
    DefineField {
        name: String,
        table: String,
        if_not_exists: bool,
        field_type: Option<String>,
        assert_expr: Option<Expr>,
        default_expr: Option<Expr>,
    },
    DefineIndex {
        name: String,
        table: String,
        if_not_exists: bool,
        columns: Vec<String>,
        kind: IndexKind,
    },
    DefineEvent {
        name: String,
        table: String,
        if_not_exists: bool,
        when_expr: Expr,
        then_stmt: Box<Statement>,
    },
    DefineFunction {
        name: String,
        params: Vec<String>,
        body: Expr,
    },
    Select {
        value_only: bool,
        projections: Vec<Projection>,
        omit: Vec<String>,
        target: Target,
        where_clause: Option<Expr>,
        split: Option<String>,
        group_by: Vec<String>,
        order_by: Option<(String, bool)>,
        limit: Option<usize>,
        start: Option<usize>,
        fetch: Vec<String>,
    },
    Create {
        target: Target,
        data: MutationData,
        ret: ReturnMode,
    },
    Insert {
        table: String,
        columns: Option<Vec<String>>,
        values: Vec<Vec<Expr>>,
        objects: Vec<Expr>,
    },
    Update {
        target: Target,
        data: MutationData,
        where_clause: Option<Expr>,
        ret: ReturnMode,
    },
    Upsert {
        target: Target,
        data: MutationData,
        where_clause: Option<Expr>,
        ret: ReturnMode,
    },
    Delete {
        target: Target,
        where_clause: Option<Expr>,
        ret: ReturnMode,
    },
    Relate {
        from: Expr,
        edge: String,
        to: Expr,
        data: MutationData,
    },
    LiveSelect {
        table: String,
    },
    Kill {
        live_id: Expr,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Projection {
    All,
    Expr { expr: Expr, alias: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Target {
    Table(String),
    Record { tb: String, id: String },
    RecordFn { tb_expr: Expr, id_expr: Expr },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationData {
    None,
    Set(Vec<(String, Expr)>),
    Content(Expr),
    Merge(Expr),
    Patch(Expr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    None,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Param(String),
    Ident(String),
    FieldPath(Vec<String>),
    RecordId { tb: String, id: String },
    Array(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    FunctionCall { name: String, args: Vec<Expr> },
    GraphTraverse {
        hops: Vec<GraphHop>,
        tail_field: Option<String>,
    },
    Subquery(Box<Statement>),
    Unary { op: UnaryOp, expr: Box<Expr> },
    Binary { left: Box<Expr>, op: BinaryOp, right: Box<Expr> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Contains,
    In,
    FtsMatch,
    VecKnn { k: usize, metric: VectorMetric },
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Param(String),
    Int(i64),
    Float(f64),
    Str(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Semicolon,
    Colon,
    DoubleColon,
    Dot,
    Star,
    Plus,
    Minus,
    Slash,
    Eq,
    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Bang,
    ArrowRight,   // ->
    ArrowLeft,    // <-
    FtsOp,        // @@
    VecKnnOp(usize, VectorMetric), // <|K|> or <|K,COSINE|>
    Eof,
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            chars: src.chars().peekable(),
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        while let Some(&c) = self.chars.peek() {
            if c.is_whitespace() {
                self.chars.next();
                continue;
            }
            // Line comments (`--` or `//`)
            if c == '-' {
                let mut clone = self.chars.clone();
                clone.next();
                if clone.peek() == Some(&'-') {
                    while let Some(ch) = self.chars.next() {
                        if ch == '\n' {
                            break;
                        }
                    }
                    continue;
                }
                if clone.peek() == Some(&'>') {
                    self.chars.next();
                    self.chars.next();
                    tokens.push(Token::ArrowRight);
                    continue;
                }
            }
            if c == '/' {
                let mut clone = self.chars.clone();
                clone.next();
                if clone.peek() == Some(&'/') {
                    while let Some(ch) = self.chars.next() {
                        if ch == '\n' {
                            break;
                        }
                    }
                    continue;
                }
            }

            match c {
                '(' => {
                    self.chars.next();
                    tokens.push(Token::LParen);
                }
                ')' => {
                    self.chars.next();
                    tokens.push(Token::RParen);
                }
                '[' => {
                    self.chars.next();
                    tokens.push(Token::LBracket);
                }
                ']' => {
                    self.chars.next();
                    tokens.push(Token::RBracket);
                }
                '{' => {
                    self.chars.next();
                    tokens.push(Token::LBrace);
                }
                '}' => {
                    self.chars.next();
                    tokens.push(Token::RBrace);
                }
                ',' => {
                    self.chars.next();
                    tokens.push(Token::Comma);
                }
                ';' => {
                    self.chars.next();
                    tokens.push(Token::Semicolon);
                }
                '.' => {
                    self.chars.next();
                    tokens.push(Token::Dot);
                }
                '*' => {
                    self.chars.next();
                    tokens.push(Token::Star);
                }
                '+' => {
                    self.chars.next();
                    tokens.push(Token::Plus);
                }
                '-' => {
                    self.chars.next();
                    tokens.push(Token::Minus);
                }
                '/' => {
                    self.chars.next();
                    tokens.push(Token::Slash);
                }
                '@' => {
                    self.chars.next();
                    if self.chars.peek() == Some(&'@') {
                        self.chars.next();
                        tokens.push(Token::FtsOp);
                    } else {
                        return Err(anyhow!("Expected '@@' full-text operator"));
                    }
                }
                ':' => {
                    self.chars.next();
                    if self.chars.peek() == Some(&':') {
                        self.chars.next();
                        tokens.push(Token::DoubleColon);
                    } else {
                        tokens.push(Token::Colon);
                    }
                }
                '=' => {
                    self.chars.next();
                    if self.chars.peek() == Some(&'=') {
                        self.chars.next();
                        tokens.push(Token::EqEq);
                    } else {
                        tokens.push(Token::Eq);
                    }
                }
                '!' => {
                    self.chars.next();
                    if self.chars.peek() == Some(&'=') {
                        self.chars.next();
                        tokens.push(Token::Ne);
                    } else {
                        tokens.push(Token::Bang);
                    }
                }
                '<' => {
                    self.chars.next();
                    if self.chars.peek() == Some(&'-') {
                        self.chars.next();
                        tokens.push(Token::ArrowLeft);
                    } else if self.chars.peek() == Some(&'|') {
                        self.chars.next();
                        // Parse `<|K|>` or `<|K,COSINE|>` or `<|K,40|>`
                        let mut inner = String::new();
                        while let Some(ch) = self.chars.next() {
                            if ch == '|' && self.chars.peek() == Some(&'>') {
                                self.chars.next();
                                break;
                            }
                            inner.push(ch);
                        }
                        let mut parts = inner.split(',').map(|s| s.trim());
                        let k = parts
                            .next()
                            .and_then(|s| s.parse::<usize>().ok())
                            .unwrap_or(5);
                        let metric = match parts.next().map(|s| s.to_ascii_uppercase()).as_deref() {
                            Some("EUCLIDEAN") => VectorMetric::Euclidean,
                            Some("MANHATTAN") => VectorMetric::Manhattan,
                            _ => VectorMetric::Cosine,
                        };
                        tokens.push(Token::VecKnnOp(k, metric));
                    } else if self.chars.peek() == Some(&'=') {
                        self.chars.next();
                        tokens.push(Token::Le);
                    } else if self.chars.peek() == Some(&'>') {
                        self.chars.next();
                        tokens.push(Token::Ne);
                    } else {
                        tokens.push(Token::Lt);
                    }
                }
                '>' => {
                    self.chars.next();
                    if self.chars.peek() == Some(&'=') {
                        self.chars.next();
                        tokens.push(Token::Ge);
                    } else {
                        tokens.push(Token::Gt);
                    }
                }
                '\'' | '"' => {
                    let quote = self.chars.next().unwrap();
                    let mut s = String::new();
                    while let Some(ch) = self.chars.next() {
                        if ch == '\\' {
                            if let Some(esc) = self.chars.next() {
                                match esc {
                                    'n' => s.push('\n'),
                                    't' => s.push('\t'),
                                    'r' => s.push('\r'),
                                    other => s.push(other),
                                }
                            }
                        } else if ch == quote {
                            break;
                        } else {
                            s.push(ch);
                        }
                    }
                    tokens.push(Token::Str(s));
                }
                '$' => {
                    self.chars.next();
                    let mut name = String::new();
                    while let Some(&ch) = self.chars.peek() {
                        if ch.is_ascii_alphanumeric() || ch == '_' {
                            name.push(ch);
                            self.chars.next();
                        } else {
                            break;
                        }
                    }
                    tokens.push(Token::Param(name));
                }
                '0'..='9' => {
                    let mut num = String::new();
                    let mut is_float = false;
                    while let Some(&ch) = self.chars.peek() {
                        if ch.is_ascii_digit() {
                            num.push(ch);
                            self.chars.next();
                        } else if ch == '.' && !is_float {
                            is_float = true;
                            num.push(ch);
                            self.chars.next();
                        } else {
                            break;
                        }
                    }
                    if is_float {
                        tokens.push(Token::Float(num.parse()?));
                    } else {
                        tokens.push(Token::Int(num.parse()?));
                    }
                }
                '`' => {
                    self.chars.next();
                    let mut ident = String::new();
                    while let Some(ch) = self.chars.next() {
                        if ch == '`' {
                            break;
                        }
                        ident.push(ch);
                    }
                    tokens.push(Token::Ident(ident));
                }
                ch if ch.is_ascii_alphabetic() || ch == '_' => {
                    let mut ident = String::new();
                    while let Some(&n) = self.chars.peek() {
                        if n.is_ascii_alphanumeric() || n == '_' {
                            ident.push(n);
                            self.chars.next();
                        } else {
                            break;
                        }
                    }
                    tokens.push(Token::Ident(ident));
                }
                other => return Err(anyhow!("Unexpected character in SurrealQL: '{}'", other)),
            }
        }
        tokens.push(Token::Eof);
        Ok(tokens)
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn peek_next(&self) -> &Token {
        self.tokens.get(self.pos + 1).unwrap_or(&Token::Eof)
    }

    fn next(&mut self) -> Token {
        let t = self.peek().clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Token::Ident(s) if s.eq_ignore_ascii_case(kw))
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.is_kw(kw) {
            self.next();
            true
        } else {
            false
        }
    }

    fn eat_if_not_exists(&mut self) -> bool {
        if self.eat_kw("IF") {
            let _ = self.eat_kw("NOT");
            let _ = self.eat_kw("EXISTS");
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.next() {
            Token::Ident(s) => Ok(s),
            other => Err(anyhow!("Expected identifier, got {:?}", other)),
        }
    }

    fn parse_all(&mut self) -> Result<Vec<Statement>> {
        let mut stmts = Vec::new();
        while !matches!(self.peek(), Token::Eof) {
            while matches!(self.peek(), Token::Semicolon) {
                self.next();
            }
            if matches!(self.peek(), Token::Eof) {
                break;
            }
            stmts.push(self.parse_statement()?);
            if matches!(self.peek(), Token::Semicolon) {
                self.next();
            }
        }
        Ok(stmts)
    }

    fn parse_statement(&mut self) -> Result<Statement> {
        if self.eat_kw("USE") {
            let mut ns = None;
            let mut db = None;
            if self.eat_kw("NS") || self.eat_kw("NAMESPACE") {
                ns = Some(self.expect_ident()?);
            }
            if self.eat_kw("DB") || self.eat_kw("DATABASE") {
                db = Some(self.expect_ident()?);
            }
            return Ok(Statement::Use { ns, db });
        }
        if self.eat_kw("LET") {
            let name = match self.next() {
                Token::Param(p) | Token::Ident(p) => p,
                other => return Err(anyhow!("Expected $param after LET, got {:?}", other)),
            };
            if !matches!(self.next(), Token::Eq) {
                return Err(anyhow!("Expected '=' in LET statement"));
            }
            let expr = self.parse_expr()?;
            return Ok(Statement::Let { name, expr });
        }
        if self.eat_kw("RETURN") {
            return Ok(Statement::Return(self.parse_expr()?));
        }
        if self.eat_kw("INFO") {
            let _ = self.eat_kw("FOR");
            if self.eat_kw("DB") || self.eat_kw("DATABASE") {
                return Ok(Statement::InfoForDb);
            }
            if self.eat_kw("TABLE") {
                return Ok(Statement::InfoForTable(self.expect_ident()?));
            }
            return Err(anyhow!("Expected DB or TABLE after INFO FOR"));
        }
        if self.eat_kw("BEGIN") {
            let _ = self.eat_kw("TRANSACTION");
            return Ok(Statement::Begin);
        }
        if self.eat_kw("COMMIT") {
            let _ = self.eat_kw("TRANSACTION");
            return Ok(Statement::Commit);
        }
        if self.eat_kw("CANCEL") {
            let _ = self.eat_kw("TRANSACTION");
            return Ok(Statement::Cancel);
        }
        if self.eat_kw("DEFINE") {
            return self.parse_define();
        }
        if self.eat_kw("LIVE") {
            if !self.eat_kw("SELECT") {
                return Err(anyhow!("Expected SELECT after LIVE"));
            }
            if matches!(self.peek(), Token::Star) {
                self.next();
            }
            let _ = self.eat_kw("FROM");
            let table = self.expect_ident()?;
            return Ok(Statement::LiveSelect { table });
        }
        if self.eat_kw("KILL") {
            let live_id = self.parse_expr()?;
            return Ok(Statement::Kill { live_id });
        }
        if self.eat_kw("RELATE") {
            let from = self.parse_primary()?;
            if !matches!(self.next(), Token::ArrowRight) {
                return Err(anyhow!("Expected '->' in RELATE statement"));
            }
            let edge = self.expect_ident()?;
            if !matches!(self.next(), Token::ArrowRight) {
                return Err(anyhow!("Expected second '->' in RELATE statement"));
            }
            let to = self.parse_primary()?;
            let data = self.parse_mutation_data()?;
            return Ok(Statement::Relate {
                from,
                edge,
                to,
                data,
            });
        }
        if self.eat_kw("SELECT") {
            return self.parse_select();
        }
        if self.eat_kw("CREATE") {
            let target = self.parse_target()?;
            let data = self.parse_mutation_data()?;
            let ret = self.parse_return_mode();
            return Ok(Statement::Create { target, data, ret });
        }
        if self.eat_kw("INSERT") {
            let _ = self.eat_kw("INTO");
            let table = self.expect_ident()?;
            if matches!(self.peek(), Token::LParen) {
                self.next();
                let mut cols = Vec::new();
                while !matches!(self.peek(), Token::RParen | Token::Eof) {
                    cols.push(self.expect_ident()?);
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    }
                }
                if matches!(self.peek(), Token::RParen) {
                    self.next();
                }
                let _ = self.eat_kw("VALUES");
                let mut rows = Vec::new();
                loop {
                    if !matches!(self.peek(), Token::LParen) {
                        break;
                    }
                    self.next();
                    let mut vals = Vec::new();
                    while !matches!(self.peek(), Token::RParen | Token::Eof) {
                        vals.push(self.parse_expr()?);
                        if matches!(self.peek(), Token::Comma) {
                            self.next();
                        }
                    }
                    if matches!(self.peek(), Token::RParen) {
                        self.next();
                    }
                    rows.push(vals);
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    } else {
                        break;
                    }
                }
                return Ok(Statement::Insert {
                    table,
                    columns: Some(cols),
                    values: rows,
                    objects: Vec::new(),
                });
            } else {
                let obj = self.parse_expr()?;
                return Ok(Statement::Insert {
                    table,
                    columns: None,
                    values: Vec::new(),
                    objects: vec![obj],
                });
            }
        }
        if self.eat_kw("UPDATE") {
            let target = self.parse_target()?;
            let data = self.parse_mutation_data()?;
            let where_clause = if self.eat_kw("WHERE") {
                Some(self.parse_expr()?)
            } else {
                None
            };
            let ret = self.parse_return_mode();
            return Ok(Statement::Update {
                target,
                data,
                where_clause,
                ret,
            });
        }
        if self.eat_kw("UPSERT") {
            let target = self.parse_target()?;
            let data = self.parse_mutation_data()?;
            let where_clause = if self.eat_kw("WHERE") {
                Some(self.parse_expr()?)
            } else {
                None
            };
            let ret = self.parse_return_mode();
            return Ok(Statement::Upsert {
                target,
                data,
                where_clause,
                ret,
            });
        }
        if self.eat_kw("DELETE") {
            let target = self.parse_target()?;
            let where_clause = if self.eat_kw("WHERE") {
                Some(self.parse_expr()?)
            } else {
                None
            };
            let ret = self.parse_return_mode();
            return Ok(Statement::Delete {
                target,
                where_clause,
                ret,
            });
        }

        Err(anyhow!("Unexpected token at statement start: {:?}", self.peek()))
    }

    fn parse_define(&mut self) -> Result<Statement> {
        if self.eat_kw("TABLE") {
            let if_not_exists = self.eat_if_not_exists();
            let name = self.expect_ident()?;
            let mut schemafull = false;
            if self.eat_kw("SCHEMAFULL") {
                schemafull = true;
            } else {
                let _ = self.eat_kw("SCHEMALESS");
            }
            return Ok(Statement::DefineTable {
                name,
                if_not_exists,
                schemafull,
            });
        }

        if self.eat_kw("FIELD") {
            let if_not_exists = self.eat_if_not_exists();
            let name = self.expect_ident()?;
            let _ = self.eat_kw("ON");
            let _ = self.eat_kw("TABLE");
            let table = self.expect_ident()?;
            let mut field_type = None;
            let mut assert_expr = None;
            let mut default_expr = None;
            loop {
                if self.eat_kw("TYPE") {
                    let mut ty = self.expect_ident()?;
                    if matches!(self.peek(), Token::Lt) {
                        self.next();
                        let inner = self.expect_ident()?;
                        if matches!(self.peek(), Token::Gt) {
                            self.next();
                        }
                        ty = format!("{}<{}>", ty, inner);
                    }
                    field_type = Some(ty);
                } else if self.eat_kw("ASSERT") {
                    assert_expr = Some(self.parse_expr()?);
                } else if self.eat_kw("DEFAULT") {
                    default_expr = Some(self.parse_expr()?);
                } else {
                    break;
                }
            }
            return Ok(Statement::DefineField {
                name,
                table,
                if_not_exists,
                field_type,
                assert_expr,
                default_expr,
            });
        }

        if self.eat_kw("INDEX") {
            let if_not_exists = self.eat_if_not_exists();
            let name = self.expect_ident()?;
            let _ = self.eat_kw("ON");
            let _ = self.eat_kw("TABLE");
            let table = self.expect_ident()?;
            let mut columns = Vec::new();
            if self.eat_kw("FIELDS") || self.eat_kw("COLUMNS") {
                loop {
                    columns.push(self.expect_ident()?);
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    } else {
                        break;
                    }
                }
            }
            let mut kind = IndexKind::Standard;
            if self.eat_kw("UNIQUE") {
                kind = IndexKind::Unique;
            } else if self.eat_kw("SEARCH") {
                // Consume optional ANALYZER <name> BM25
                while !matches!(self.peek(), Token::Semicolon | Token::Eof) {
                    self.next();
                }
                kind = IndexKind::FtsBm25;
            } else if self.eat_kw("HNSW") || self.eat_kw("MTREE") {
                let mut dim = 3usize;
                let mut metric = VectorMetric::Cosine;
                while !matches!(self.peek(), Token::Semicolon | Token::Eof) {
                    if self.eat_kw("DIMENSION") {
                        if let Token::Int(d) = self.next() {
                            dim = d.max(1) as usize;
                        }
                    } else if self.eat_kw("DIST") {
                        if let Ok(m) = self.expect_ident() {
                            metric = match m.to_ascii_uppercase().as_str() {
                                "EUCLIDEAN" => VectorMetric::Euclidean,
                                "MANHATTAN" => VectorMetric::Manhattan,
                                _ => VectorMetric::Cosine,
                            };
                        }
                    } else {
                        self.next();
                    }
                }
                kind = IndexKind::VectorHnsw { dim, metric };
            }
            return Ok(Statement::DefineIndex {
                name,
                table,
                if_not_exists,
                columns,
                kind,
            });
        }

        if self.eat_kw("EVENT") {
            let if_not_exists = self.eat_if_not_exists();
            let name = self.expect_ident()?;
            let _ = self.eat_kw("ON");
            let _ = self.eat_kw("TABLE");
            let table = self.expect_ident()?;
            let _ = self.eat_kw("WHEN");
            let when_expr = self.parse_expr()?;
            let _ = self.eat_kw("THEN");
            let wrapped = matches!(self.peek(), Token::LBrace | Token::LParen);
            if wrapped {
                self.next();
            }
            let then_stmt = self.parse_statement()?;
            if wrapped && matches!(self.peek(), Token::RBrace | Token::RParen) {
                self.next();
            }
            return Ok(Statement::DefineEvent {
                name,
                table,
                if_not_exists,
                when_expr,
                then_stmt: Box::new(then_stmt),
            });
        }

        if self.eat_kw("FUNCTION") {
            let _ = self.eat_if_not_exists();
            let mut full_name = self.expect_ident()?;
            while matches!(self.peek(), Token::DoubleColon) {
                self.next();
                full_name.push_str("::");
                full_name.push_str(&self.expect_ident()?);
            }
            let mut params = Vec::new();
            if matches!(self.peek(), Token::LParen) {
                self.next();
                while !matches!(self.peek(), Token::RParen | Token::Eof) {
                    if let Token::Param(p) | Token::Ident(p) = self.next() {
                        params.push(p);
                    }
                    // Optional `: type` annotation on param
                    if matches!(self.peek(), Token::Colon) {
                        self.next();
                        let _ = self.expect_ident();
                    }
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    }
                }
                if matches!(self.peek(), Token::RParen) {
                    self.next();
                }
            }
            if matches!(self.peek(), Token::LBrace) {
                self.next();
            }
            let _ = self.eat_kw("RETURN");
            let body = self.parse_expr()?;
            if matches!(self.peek(), Token::Semicolon) {
                self.next();
            }
            if matches!(self.peek(), Token::RBrace) {
                self.next();
            }
            return Ok(Statement::DefineFunction {
                name: full_name,
                params,
                body,
            });
        }

        Err(anyhow!("Unsupported DEFINE target"))
    }

    fn parse_return_mode(&mut self) -> ReturnMode {
        if self.eat_kw("RETURN") {
            if self.eat_kw("NONE") {
                return ReturnMode::None;
            }
            if self.eat_kw("BEFORE") {
                return ReturnMode::Before;
            }
            if self.eat_kw("DIFF") {
                return ReturnMode::Diff;
            }
            let _ = self.eat_kw("AFTER");
        }
        ReturnMode::After
    }

    fn parse_select(&mut self) -> Result<Statement> {
        let value_only = self.eat_kw("VALUE");
        let mut projections = Vec::new();
        loop {
            if matches!(self.peek(), Token::Star) {
                self.next();
                projections.push(Projection::All);
            } else {
                let expr = self.parse_expr()?;
                let alias = if self.eat_kw("AS") {
                    Some(self.expect_ident()?)
                } else {
                    None
                };
                projections.push(Projection::Expr { expr, alias });
            }
            if matches!(self.peek(), Token::Comma) {
                self.next();
            } else {
                break;
            }
        }

        let mut omit = Vec::new();
        if self.eat_kw("OMIT") {
            loop {
                omit.push(self.expect_ident()?);
                if matches!(self.peek(), Token::Comma) {
                    self.next();
                } else {
                    break;
                }
            }
        }

        if !self.eat_kw("FROM") {
            return Err(anyhow!("Expected FROM in SELECT"));
        }
        let target = self.parse_target()?;
        let where_clause = if self.eat_kw("WHERE") {
            Some(self.parse_expr()?)
        } else {
            None
        };
        let split = if self.eat_kw("SPLIT") {
            let _ = self.eat_kw("ON");
            Some(self.expect_ident()?)
        } else {
            None
        };
        let mut group_by = Vec::new();
        if self.eat_kw("GROUP") {
            let _ = self.eat_kw("BY");
            if !self.eat_kw("ALL") {
                loop {
                    group_by.push(self.expect_ident()?);
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    } else {
                        break;
                    }
                }
            }
        }
        let order_by = if self.eat_kw("ORDER") {
            let _ = self.eat_kw("BY");
            let field = self.expect_ident()?;
            let asc = if self.eat_kw("DESC") {
                false
            } else {
                let _ = self.eat_kw("ASC");
                true
            };
            Some((field, asc))
        } else {
            None
        };
        let limit = if self.eat_kw("LIMIT") {
            match self.next() {
                Token::Int(n) if n >= 0 => Some(n as usize),
                other => return Err(anyhow!("Expected integer after LIMIT, got {:?}", other)),
            }
        } else {
            None
        };
        let start = if self.eat_kw("START") {
            let _ = self.eat_kw("AT");
            match self.next() {
                Token::Int(n) if n >= 0 => Some(n as usize),
                other => return Err(anyhow!("Expected integer after START, got {:?}", other)),
            }
        } else {
            None
        };
        let mut fetch = Vec::new();
        if self.eat_kw("FETCH") {
            loop {
                fetch.push(self.expect_ident()?);
                if matches!(self.peek(), Token::Comma) {
                    self.next();
                } else {
                    break;
                }
            }
        }

        Ok(Statement::Select {
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
        })
    }

    fn parse_target(&mut self) -> Result<Target> {
        let first = self.expect_ident()?;
        if first.eq_ignore_ascii_case("type") && matches!(self.peek(), Token::DoubleColon) {
            self.next();
            let fn_name = self.expect_ident()?;
            if (fn_name.eq_ignore_ascii_case("record") || fn_name.eq_ignore_ascii_case("thing"))
                && matches!(self.peek(), Token::LParen)
            {
                self.next();
                let tb_expr = self.parse_expr()?;
                if matches!(self.peek(), Token::Comma) {
                    self.next();
                }
                let id_expr = self.parse_expr()?;
                if matches!(self.peek(), Token::RParen) {
                    self.next();
                }
                return Ok(Target::RecordFn { tb_expr, id_expr });
            }
            return Err(anyhow!("Unsupported target function type::{}", fn_name));
        }

        if matches!(self.peek(), Token::Colon) {
            self.next();
            let id = match self.next() {
                Token::Ident(s) | Token::Str(s) => s,
                Token::Int(n) => n.to_string(),
                other => return Err(anyhow!("Expected record id after ':', got {:?}", other)),
            };
            return Ok(Target::Record { tb: first, id });
        }

        Ok(Target::Table(first))
    }

    fn parse_mutation_data(&mut self) -> Result<MutationData> {
        if self.eat_kw("SET") {
            let mut pairs = Vec::new();
            loop {
                let k = self.expect_ident()?;
                if !matches!(self.next(), Token::Eq) {
                    return Err(anyhow!("Expected '=' in SET clause"));
                }
                let v = self.parse_expr()?;
                pairs.push((k, v));
                if matches!(self.peek(), Token::Comma) {
                    self.next();
                } else {
                    break;
                }
            }
            return Ok(MutationData::Set(pairs));
        }
        if self.eat_kw("CONTENT") {
            return Ok(MutationData::Content(self.parse_expr()?));
        }
        if self.eat_kw("MERGE") {
            return Ok(MutationData::Merge(self.parse_expr()?));
        }
        if self.eat_kw("PATCH") {
            return Ok(MutationData::Patch(self.parse_expr()?));
        }
        Ok(MutationData::None)
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while self.eat_kw("OR") {
            let right = self.parse_and()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_cmp()?;
        while self.eat_kw("AND") {
            let right = self.parse_cmp()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_cmp(&mut self) -> Result<Expr> {
        let mut left = self.parse_add()?;
        loop {
            let op = match self.peek().clone() {
                Token::Eq | Token::EqEq => {
                    self.next();
                    BinaryOp::Eq
                }
                Token::Ne => {
                    self.next();
                    BinaryOp::Ne
                }
                Token::Lt => {
                    self.next();
                    BinaryOp::Lt
                }
                Token::Le => {
                    self.next();
                    BinaryOp::Le
                }
                Token::Gt => {
                    self.next();
                    BinaryOp::Gt
                }
                Token::Ge => {
                    self.next();
                    BinaryOp::Ge
                }
                Token::FtsOp => {
                    self.next();
                    BinaryOp::FtsMatch
                }
                Token::VecKnnOp(k, metric) => {
                    self.next();
                    BinaryOp::VecKnn { k, metric }
                }
                Token::Ident(s) if s.eq_ignore_ascii_case("CONTAINS") => {
                    self.next();
                    BinaryOp::Contains
                }
                Token::Ident(s) if s.eq_ignore_ascii_case("IN") => {
                    self.next();
                    BinaryOp::In
                }
                _ => break,
            };
            let right = self.parse_add()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Expr> {
        let mut left = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Token::Plus => {
                    self.next();
                    BinaryOp::Add
                }
                Token::Minus => {
                    self.next();
                    BinaryOp::Sub
                }
                _ => break,
            };
            let right = self.parse_mul()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => {
                    self.next();
                    BinaryOp::Mul
                }
                Token::Slash => {
                    self.next();
                    BinaryOp::Div
                }
                _ => break,
            };
            let right = self.parse_unary()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Token::Bang) || self.is_kw("NOT") {
            self.next();
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(self.parse_unary()?),
            });
        }
        if matches!(self.peek(), Token::Minus) {
            self.next();
            return Ok(Expr::Unary {
                op: UnaryOp::Neg,
                expr: Box::new(self.parse_unary()?),
            });
        }
        self.parse_primary()
    }

    fn parse_graph_traversal(&mut self) -> Result<Expr> {
        let mut hops = Vec::new();
        while matches!(self.peek(), Token::ArrowRight | Token::ArrowLeft) {
            let dir = match self.next() {
                Token::ArrowRight => GraphDir::Out,
                Token::ArrowLeft => GraphDir::In,
                _ => unreachable!(),
            };
            let edge = self.expect_ident()?;
            let mut target_table = None;
            if matches!(self.peek(), Token::ArrowRight | Token::ArrowLeft) {
                self.next();
                if matches!(self.peek(), Token::Ident(_)) {
                    target_table = Some(self.expect_ident()?);
                } else if matches!(self.peek(), Token::Star) {
                    self.next();
                }
            }
            hops.push(GraphHop {
                dir,
                edge,
                target_table,
            });
        }
        let tail_field = if matches!(self.peek(), Token::Dot) {
            self.next();
            if matches!(self.peek(), Token::Star) {
                self.next();
                None
            } else {
                Some(self.expect_ident()?)
            }
        } else {
            None
        };
        Ok(Expr::GraphTraverse { hops, tail_field })
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Token::ArrowRight | Token::ArrowLeft) {
            return self.parse_graph_traversal();
        }

        match self.next() {
            Token::Int(n) => Ok(Expr::Int(n)),
            Token::Float(f) => Ok(Expr::Float(f)),
            Token::Str(s) => Ok(Expr::String(s)),
            Token::Param(p) => {
                if matches!(self.peek(), Token::Dot) {
                    let mut path = vec![format!("${}", p)];
                    while matches!(self.peek(), Token::Dot) {
                        self.next();
                        path.push(self.expect_ident()?);
                    }
                    Ok(Expr::FieldPath(path))
                } else {
                    Ok(Expr::Param(p))
                }
            }
            Token::LParen => {
                if self.is_kw("SELECT") {
                    self.next();
                    let sub = self.parse_select()?;
                    if matches!(self.peek(), Token::RParen) {
                        self.next();
                    }
                    return Ok(Expr::Subquery(Box::new(sub)));
                }
                let inner = self.parse_expr()?;
                if matches!(self.peek(), Token::RParen) {
                    self.next();
                }
                Ok(inner)
            }
            Token::LBracket => {
                let mut items = Vec::new();
                while !matches!(self.peek(), Token::RBracket | Token::Eof) {
                    items.push(self.parse_expr()?);
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    }
                }
                if matches!(self.peek(), Token::RBracket) {
                    self.next();
                }
                Ok(Expr::Array(items))
            }
            Token::LBrace => {
                let mut pairs = Vec::new();
                while !matches!(self.peek(), Token::RBrace | Token::Eof) {
                    let k = match self.next() {
                        Token::Ident(s) | Token::Str(s) => s,
                        other => return Err(anyhow!("Expected object key, got {:?}", other)),
                    };
                    if !matches!(self.next(), Token::Colon) {
                        return Err(anyhow!("Expected ':' after object key '{}'", k));
                    }
                    let v = self.parse_expr()?;
                    pairs.push((k, v));
                    if matches!(self.peek(), Token::Comma) {
                        self.next();
                    }
                }
                if matches!(self.peek(), Token::RBrace) {
                    self.next();
                }
                Ok(Expr::Object(pairs))
            }
            Token::Ident(s) => {
                if s.eq_ignore_ascii_case("TRUE") {
                    return Ok(Expr::Bool(true));
                }
                if s.eq_ignore_ascii_case("FALSE") {
                    return Ok(Expr::Bool(false));
                }
                if s.eq_ignore_ascii_case("NULL") {
                    return Ok(Expr::Null);
                }
                if s.eq_ignore_ascii_case("NONE") {
                    return Ok(Expr::None);
                }

                let mut full_name = s;
                while matches!(self.peek(), Token::DoubleColon) {
                    self.next();
                    let seg = self.expect_ident()?;
                    full_name.push_str("::");
                    full_name.push_str(&seg);
                }

                if matches!(self.peek(), Token::LParen) {
                    self.next();
                    let mut args = Vec::new();
                    while !matches!(self.peek(), Token::RParen | Token::Eof) {
                        if matches!(self.peek(), Token::Star) {
                            self.next();
                            args.push(Expr::Int(1));
                        } else {
                            args.push(self.parse_expr()?);
                        }
                        if matches!(self.peek(), Token::Comma) {
                            self.next();
                        }
                    }
                    if matches!(self.peek(), Token::RParen) {
                        self.next();
                    }
                    return Ok(Expr::FunctionCall {
                        name: full_name,
                        args,
                    });
                }

                if matches!(self.peek(), Token::Colon)
                    && matches!(
                        self.peek_next(),
                        Token::Ident(_) | Token::Int(_) | Token::Str(_)
                    )
                {
                    self.next();
                    let id = match self.next() {
                        Token::Ident(i) | Token::Str(i) => i,
                        Token::Int(n) => n.to_string(),
                        _ => unreachable!(),
                    };
                    return Ok(Expr::RecordId { tb: full_name, id });
                }

                if matches!(self.peek(), Token::Dot) {
                    let mut path = vec![full_name];
                    while matches!(self.peek(), Token::Dot) {
                        self.next();
                        path.push(self.expect_ident()?);
                    }
                    return Ok(Expr::FieldPath(path));
                }

                Ok(Expr::Ident(full_name))
            }
            other => Err(anyhow!("Unexpected token in expression: {:?}", other)),
        }
    }
}

pub fn parse_surql(src: &str) -> Result<Vec<Statement>> {
    let tokens = Lexer::new(src).tokenize()?;
    Parser::new(tokens).parse_all()
}
