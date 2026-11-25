use anyhow::{anyhow, Result};
use std::collections::HashMap;

use crate::value::Value;
use crate::NexusDb;

/// Parsed PostgreSQL v3 startup packet (`SSLRequest` or normal `user`/`database` startup).
#[derive(Debug, Clone)]
pub enum StartupPacket {
    SslRequest,
    Startup {
        user: String,
        database: String,
        ns: String,
        params: HashMap<String, String>,
    },
}

/// Pure-Rust PostgreSQL v3 Wire Protocol handler (`feature = "pgwire"`).
/// Supports:
/// - `SSLRequest` (`80877103`) rejection (`'N'`) for clean plaintext loopback negotiation
/// - Cleartext Password Authentication (`R` code `3` + `'p'` `PasswordMessage`) backed by `nexus-db` RBAC
/// - Proper length-prefixed TCP message framing (`extract_next_frame`)
/// - Simple Query (`'Q'`) and Terminate (`'X'`) frames
pub struct PgWireSession {
    db: NexusDb,
    pub ns: String,
    pub database: String,
    pub require_auth: bool,
    pub authenticated: bool,
    pub pending_user: Option<String>,
    #[cfg(feature = "auth")]
    pub auth: Option<crate::auth::AuthContext>,
}

impl PgWireSession {
    /// Embedded trusted session (no password prompt; for in-process tests).
    pub fn new(db: NexusDb, ns: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
            require_auth: false,
            authenticated: true,
            pending_user: None,
            #[cfg(feature = "auth")]
            auth: None,
        }
    }

    /// Networked session requiring `AuthenticationCleartextPassword` (`'p'`) before any `'Q'` query.
    pub fn new_authenticated(
        db: NexusDb,
        ns: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
            require_auth: true,
            authenticated: false,
            pending_user: Some(user.into()),
            #[cfg(feature = "auth")]
            auth: None,
        }
    }

    /// Parse a PG v3 startup packet (4-byte big-endian length + 4-byte protocol/SSL code + NUL-separated kv pairs).
    /// Returns `Ok(Some((consumed_bytes, StartupPacket)))` when a full startup packet is buffered, or `Ok(None)` if more bytes are needed.
    pub fn parse_startup_packet(buf: &[u8]) -> Result<Option<(usize, StartupPacket)>> {
        if buf.len() < 8 {
            return Ok(None);
        }
        let total_len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if total_len < 8 || total_len > 16_384 {
            return Err(anyhow!("Invalid PG startup packet length {}", total_len));
        }
        if buf.len() < total_len {
            return Ok(None);
        }
        let code = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if code == 80_877_103 {
            return Ok(Some((total_len, StartupPacket::SslRequest)));
        }
        let mut params = HashMap::new();
        let mut parts = buf[8..total_len].split(|&b| b == 0);
        while let Some(k) = parts.next() {
            if k.is_empty() {
                break;
            }
            if let Some(v) = parts.next() {
                params.insert(
                    String::from_utf8_lossy(k).to_string(),
                    String::from_utf8_lossy(v).to_string(),
                );
            }
        }
        let user = params
            .get("user")
            .cloned()
            .unwrap_or_else(|| "postgres".to_string());
        let database = params
            .get("database")
            .cloned()
            .unwrap_or_else(|| "system".to_string());
        let ns = params
            .get("options")
            .and_then(|o| o.strip_prefix("ns=").map(String::from))
            .unwrap_or_else(|| "nexus".to_string());
        Ok(Some((
            total_len,
            StartupPacket::Startup {
                user,
                database,
                ns,
                params,
            },
        )))
    }

    /// Extract one complete length-prefixed PG v3 frontend message (`[tag: u8][len: i32 BE][body: len-4]`)
    /// from a streaming TCP buffer, properly handling fragmented or coalesced reads.
    pub fn extract_next_frame(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        if buf.len() < 5 {
            return Ok(None);
        }
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if len < 4 || len > 16 * 1024 * 1024 {
            return Err(anyhow!("Invalid PG wire frame length {}", len));
        }
        let total = 1 + (len as usize);
        if buf.len() < total {
            return Ok(None);
        }
        let frame = buf.drain(..total).collect();
        Ok(Some(frame))
    }

    /// Encode initial handshake response:
    /// - If `require_auth` is true: sends `AuthenticationCleartextPassword` (`R` code `3`)
    /// - Otherwise: sends `AuthenticationOk` (`R` code `0`) + `ReadyForQuery` (`Z`)
    pub fn startup_response(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.require_auth && !self.authenticated {
            // AuthenticationCleartextPassword: 'R', len=8, code=3
            out.push(b'R');
            out.extend_from_slice(&8i32.to_be_bytes());
            out.extend_from_slice(&3i32.to_be_bytes());
            return out;
        }
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

    /// Build a PG v3 PasswordMessage (`'p'`) frame (useful for clients & tests).
    pub fn encode_password_frame(password: &str) -> Vec<u8> {
        let payload_len = (4 + password.len() + 1) as i32;
        let mut buf = Vec::with_capacity(1 + payload_len as usize);
        buf.push(b'p');
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(password.as_bytes());
        buf.push(0);
        buf
    }

    /// Process a single PG v3 frontend message frame (`'p'` Password, `'Q'` Simple Query, or `'X'` Terminate).
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
            b'p' => {
                let password =
                    String::from_utf8_lossy(payload.strip_suffix(&[0]).unwrap_or(payload))
                        .to_string();
                let user = self.pending_user.clone().unwrap_or_default();
                #[cfg(feature = "auth")]
                {
                    match self.db.signin_user(&self.ns, &self.database, &user, &password) {
                        Ok((_jwt, ctx)) => {
                            self.auth = Some(ctx);
                            self.authenticated = true;
                            out.push(b'R');
                            out.extend_from_slice(&8i32.to_be_bytes());
                            out.extend_from_slice(&0i32.to_be_bytes());
                            write_ready_for_query(&mut out);
                        }
                        Err(e) => {
                            write_error_response(&format!("password authentication failed: {}", e), &mut out);
                        }
                    }
                }
                #[cfg(not(feature = "auth"))]
                {
                    let _ = (user, password);
                    write_error_response("auth feature not compiled", &mut out);
                }
            }
            b'Q' => {
                if self.require_auth && !self.authenticated {
                    write_error_response("authentication required before executing queries", &mut out);
                    write_ready_for_query(&mut out);
                    return Ok(out);
                }
                let sql = String::from_utf8_lossy(payload.strip_suffix(&[0]).unwrap_or(payload))
                    .to_string();
                let exec = {
                    #[cfg(feature = "auth")]
                    if let Some(ref auth) = self.auth {
                        self.db.query_scoped_with_auth(
                            &self.ns,
                            &self.database,
                            &sql,
                            vec![],
                            auth.clone(),
                        )
                    } else {
                        self.db.query_scoped(&self.ns, &self.database, &sql, vec![])
                    }
                    #[cfg(not(feature = "auth"))]
                    {
                        self.db.query_scoped(&self.ns, &self.database, &sql, vec![])
                    }
                };
                match exec {
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
