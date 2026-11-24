use anyhow::{anyhow, Result};

use crate::value::Value;
use crate::NexusDb;

/// Pure-Rust PostgreSQL v3 Wire Protocol handler (`feature = "pgwire"`, SurrealDB 4.0 parity).
/// Handles standard PG v3 Simple Query (`'Q'`) frames and encodes `RowDescription ('T')`,
/// `DataRow ('D')`, `CommandComplete ('C')`, `ReadyForQuery ('Z')`, and `ErrorResponse ('E')`.
pub struct PgWireSession {
    db: NexusDb,
    pub ns: String,
    pub database: String,
}

impl PgWireSession {
    pub fn new(db: NexusDb, ns: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
        }
    }

    /// Encode standard PG v3 startup handshake response (`AuthenticationOk` + `ReadyForQuery`).
    pub fn startup_response(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // AuthenticationOk: 'R', len=8, code=0
        out.push(b'R');
        out.extend_from_slice(&8i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        write_ready_for_query(&mut out);
        out
    }

    /// Build a PG v3 Simple Query (`'Q'`) request frame (useful for clients & tests).
    pub fn encode_query_frame(sql: &str) -> Vec<u8> {
        let payload_len = (4 + sql.len() + 1) as i32;
        let mut buf = Vec::with_capacity(1 + payload_len as usize);
        buf.push(b'Q');
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(sql.as_bytes());
        buf.push(0);
        buf
    }

    /// Process a single PG v3 frontend message frame (`'Q'` Simple Query or `'X'` Terminate)
    /// and return the encoded PG v3 backend response frames.
    pub fn handle_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 5 {
            return Err(anyhow!("Truncated PostgreSQL wire frame"));
        }
        let msg_type = frame[0];
        let len = i32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        if frame.len() < 1 + len {
            return Err(anyhow!("Incomplete PostgreSQL wire frame payload"));
        }
        let payload = &frame[5..1 + len];

        let mut out = Vec::new();
        match msg_type {
            b'Q' => {
                let sql = String::from_utf8_lossy(payload.strip_suffix(&[0]).unwrap_or(payload))
                    .to_string();
                match self.db.query_scoped(&self.ns, &self.database, &sql, vec![]) {
                    Ok(rows) => {
                        encode_result_set(&rows, &mut out);
                        write_command_complete(&format!("SELECT {}", rows.len()), &mut out);
                    }
                    Err(e) => {
                        write_error_response(&e.to_string(), &mut out);
                    }
                }
                write_ready_for_query(&mut out);
            }
            b'X' => {
                // Terminate
            }
            other => {
                write_error_response(
                    &format!("Unsupported PG message type '{}'", other as char),
                    &mut out,
                );
                write_ready_for_query(&mut out);
            }
        }
        Ok(out)
    }
}

fn encode_result_set(rows: &[Value], out: &mut Vec<u8>) {
    // Derive columns from first Object row, or single `value` column for scalars
    let cols: Vec<String> = match rows.first() {
        Some(Value::Object(map)) => map.keys().cloned().collect(),
        Some(_) => vec!["value".to_string()],
        None => Vec::new(),
    };

    if cols.is_empty() {
        return;
    }

    // RowDescription ('T')
    let mut desc = Vec::new();
    desc.extend_from_slice(&(cols.len() as i16).to_be_bytes());
    for col in &cols {
        desc.extend_from_slice(col.as_bytes());
        desc.push(0);
        desc.extend_from_slice(&0i32.to_be_bytes()); // table OID
        desc.extend_from_slice(&0i16.to_be_bytes()); // attr num
        desc.extend_from_slice(&25i32.to_be_bytes()); // TEXT OID = 25
        desc.extend_from_slice(&(-1i16).to_be_bytes()); // typelen
        desc.extend_from_slice(&(-1i32).to_be_bytes()); // typemod
        desc.extend_from_slice(&0i16.to_be_bytes()); // text format
    }
    write_msg(b'T', &desc, out);

    // DataRow ('D')
    for row in rows {
        let mut rbuf = Vec::new();
        rbuf.extend_from_slice(&(cols.len() as i16).to_be_bytes());
        match row {
            Value::Object(map) => {
                for col in &cols {
                    match map.get(col) {
                        Some(Value::Null) | Some(Value::None) | None => {
                            rbuf.extend_from_slice(&(-1i32).to_be_bytes());
                        }
                        Some(v) => {
                            let s = v.display_compact();
                            rbuf.extend_from_slice(&(s.len() as i32).to_be_bytes());
                            rbuf.extend_from_slice(s.as_bytes());
                        }
                    }
                }
            }
            scalar => {
                let s = scalar.display_compact();
                rbuf.extend_from_slice(&(s.len() as i32).to_be_bytes());
                rbuf.extend_from_slice(s.as_bytes());
            }
        }
        write_msg(b'D', &rbuf, out);
    }
}

fn write_command_complete(tag: &str, out: &mut Vec<u8>) {
    let mut body = tag.as_bytes().to_vec();
    body.push(0);
    write_msg(b'C', &body, out);
}

fn write_error_response(msg: &str, out: &mut Vec<u8>) {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"ERROR\0");
    body.push(b'M');
    body.extend_from_slice(msg.as_bytes());
    body.push(0);
    body.push(0);
    write_msg(b'E', &body, out);
}

fn write_ready_for_query(out: &mut Vec<u8>) {
    write_msg(b'Z', &[b'I'], out);
}

fn write_msg(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    out.extend_from_slice(&((4 + body.len()) as i32).to_be_bytes());
    out.extend_from_slice(body);
}
