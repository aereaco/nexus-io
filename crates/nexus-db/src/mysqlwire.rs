//! Pure-Rust MySQL v10 Wire Protocol handler (`feature = "mysqlwire"`).
//!
//! Supports:
//! - Initial `HandshakeV10` server greeting (`mysql_clear_password` / `mysql_native_password`)
//! - `HandshakeResponse41` client authentication backed by `nexus-db` RBAC (`signin_user`)
//! - Streaming 4-byte MySQL TCP packet framing (`[len: u24 LE][seq: u8][payload]`)
//! - `COM_QUIT (0x01)`, `COM_INIT_DB (0x02)`, `COM_QUERY (0x03)`, `COM_PING (0x0e)`
//! - Standard MySQL `OK`, `ERR`, `EOF`, `ColumnDefinition41`, and `ProtocolText::ResultsetRow` packets

use anyhow::{anyhow, Result};

use crate::value::Value;
use crate::NexusDb;

const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;

/// Stateful MySQL v10 wire-protocol session backed by `NexusDb` with RBAC enforcement.
pub struct MySqlWireSession {
    db: NexusDb,
    pub ns: String,
    pub database: String,
    pub connection_id: u32,
    pub require_auth: bool,
    pub authenticated: bool,
    #[cfg(feature = "auth")]
    pub auth: Option<crate::auth::AuthContext>,
}

impl MySqlWireSession {
    /// Trusted in-process session (for embedded tests).
    pub fn new(db: NexusDb, ns: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
            connection_id: 1,
            require_auth: false,
            authenticated: true,
            #[cfg(feature = "auth")]
            auth: None,
        }
    }

    /// Networked session requiring `HandshakeResponse41` authentication against `nexus-db`.
    pub fn new_authenticated(
        db: NexusDb,
        ns: impl Into<String>,
        database: impl Into<String>,
        connection_id: u32,
    ) -> Self {
        Self {
            db,
            ns: ns.into(),
            database: database.into(),
            connection_id,
            require_auth: true,
            authenticated: false,
            #[cfg(feature = "auth")]
            auth: None,
        }
    }

    /// Extract one complete MySQL packet (`[len: 3B LE][seq: 1B][payload: len]`) from a TCP stream buffer.
    /// Returns `(seq_id, payload)`.
    pub fn extract_next_packet(buf: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = (buf[0] as usize) | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16);
        let seq = buf[3];
        if buf.len() < 4 + len {
            return Ok(None);
        }
        buf.drain(..4);
        let payload: Vec<u8> = buf.drain(..len).collect();
        Ok(Some((seq, payload)))
    }

    /// Build a framed MySQL packet (`[len: 3B LE][seq: 1B][payload]`).
    pub fn encode_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = Vec::with_capacity(4 + len);
        out.push((len & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(seq);
        out.extend_from_slice(payload);
        out
    }

    /// Encode initial MySQL `HandshakeV10` greeting packet (`seq = 0`).
    pub fn handshake_greeting(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(10); // protocol version 10
        p.extend_from_slice(b"8.0.36-nexus-db\0");
        p.extend_from_slice(&self.connection_id.to_le_bytes());
        p.extend_from_slice(b"12345678"); // auth-plugin-data-part-1 (8 bytes)
        p.push(0x00); // filler
        let caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB;
        p.extend_from_slice(&((caps & 0xFFFF) as u16).to_le_bytes());
        p.push(0x21); // utf8_general_ci
        p.extend_from_slice(&0x0002u16.to_le_bytes()); // SERVER_STATUS_AUTOCOMMIT
        p.extend_from_slice(&(((caps >> 16) & 0xFFFF) as u16).to_le_bytes());
        p.push(21); // auth plugin data len
        p.extend_from_slice(&[0u8; 10]); // reserved
        p.extend_from_slice(b"901234567890\0"); // auth-plugin-data-part-2 (13 bytes)
        p.extend_from_slice(b"mysql_clear_password\0");
        Self::encode_packet(0, &p)
    }

    /// Build a `HandshakeResponse41` client packet (useful for tests & internal clients).
    pub fn encode_handshake_response(user: &str, password: &str, database: &str) -> Vec<u8> {
        let mut p = Vec::new();
        let caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&16_777_216u32.to_le_bytes()); // max packet size
        p.push(0x21); // charset
        p.extend_from_slice(&[0u8; 23]); // reserved
        p.extend_from_slice(user.as_bytes());
        p.push(0);
        p.push(password.len() as u8);
        p.extend_from_slice(password.as_bytes());
        p.extend_from_slice(database.as_bytes());
        p.push(0);
        Self::encode_packet(1, &p)
    }

    /// Build a `COM_QUERY (0x03)` client packet (useful for tests & clients).
    pub fn encode_query_packet(sql: &str) -> Vec<u8> {
        let mut p = Vec::with_capacity(1 + sql.len());
        p.push(0x03);
        p.extend_from_slice(sql.as_bytes());
        Self::encode_packet(0, &p)
    }

    /// Handle a client `HandshakeResponse41` packet and authenticate against `nexus-db`.
    pub fn handle_handshake_response(&mut self, seq: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 32 {
            return Err(anyhow!("Truncated MySQL HandshakeResponse41"));
        }
        let client_flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let mut pos = 32usize;

        // NUL-terminated username
        let user_end = payload[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| pos + i)
            .unwrap_or(payload.len());
        let user = String::from_utf8_lossy(&payload[pos..user_end]).to_string();
        pos = (user_end + 1).min(payload.len());

        // Length-prefixed or NUL-terminated auth response
        let password = if pos < payload.len() {
            if (client_flags & CLIENT_SECURE_CONNECTION) != 0 {
                let auth_len = payload[pos] as usize;
                pos += 1;
                let end = (pos + auth_len).min(payload.len());
                let pw = String::from_utf8_lossy(&payload[pos..end])
                    .trim_end_matches('\0')
                    .to_string();
                pos = end;
                pw
            } else {
                let end = payload[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| pos + i)
                    .unwrap_or(payload.len());
                let pw = String::from_utf8_lossy(&payload[pos..end]).to_string();
                pos = (end + 1).min(payload.len());
                pw
            }
        } else {
            String::new()
        };

        // Optional database name
        if (client_flags & CLIENT_CONNECT_WITH_DB) != 0 && pos < payload.len() {
            let db_end = payload[pos..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| pos + i)
                .unwrap_or(payload.len());
            let db_name = String::from_utf8_lossy(&payload[pos..db_end]).to_string();
            if !db_name.is_empty() {
                self.database = db_name;
            }
        }

        if !self.require_auth {
            self.authenticated = true;
            return Ok(encode_ok_packet(seq.wrapping_add(1), 0));
        }

        #[cfg(feature = "auth")]
        {
            match self.db.signin_user(&self.ns, &self.database, &user, &password) {
                Ok((_jwt, ctx)) => {
                    self.auth = Some(ctx);
                    self.authenticated = true;
                    Ok(encode_ok_packet(seq.wrapping_add(1), 0))
                }
                Err(e) => Ok(encode_err_packet(
                    seq.wrapping_add(1),
                    1045,
                    "28000",
                    &format!("Access denied for user '{}': {}", user, e),
                )),
            }
        }
        #[cfg(not(feature = "auth"))]
        {
            let _ = (user, password);
            Ok(encode_err_packet(
                seq.wrapping_add(1),
                1045,
                "28000",
                "auth feature not compiled",
            ))
        }
    }

    /// Process a MySQL command packet (`COM_QUIT`, `COM_INIT_DB`, `COM_QUERY`, `COM_PING`).
    /// Returns `(should_close, response_bytes)`.
    pub fn handle_command(&mut self, seq: u8, payload: &[u8]) -> Result<(bool, Vec<u8>)> {
        let Some(&cmd) = payload.first() else {
            return Ok((false, Vec::new()));
        };
        let next_seq = seq.wrapping_add(1);
        match cmd {
            0x01 => Ok((true, Vec::new())), // COM_QUIT
            0x0e => Ok((false, encode_ok_packet(next_seq, 0))), // COM_PING
            0x02 => {
                // COM_INIT_DB
                let new_db = String::from_utf8_lossy(&payload[1..]).trim().to_string();
                if !new_db.is_empty() {
                    self.database = new_db;
                }
                Ok((false, encode_ok_packet(next_seq, 0)))
            }
            0x03 => {
                // COM_QUERY
                if self.require_auth && !self.authenticated {
                    return Ok((
                        false,
                        encode_err_packet(next_seq, 1045, "28000", "Authentication required"),
                    ));
                }
                let sql = String::from_utf8_lossy(&payload[1..]).trim().to_string();
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
                    Ok(rows) => Ok((false, encode_resultset(next_seq, &rows))),
                    Err(e) => Ok((false, encode_err_packet(next_seq, 1064, "42000", &e.to_string()))),
                }
            }
            other => Ok((
                false,
                encode_err_packet(
                    next_seq,
                    1047,
                    "08S01",
                    &format!("Unsupported MySQL command 0x{:02x}", other),
                ),
            )),
        }
    }
}

fn encode_lenenc_int(n: u64, out: &mut Vec<u8>) {
    if n < 251 {
        out.push(n as u8);
    } else if n < 65_536 {
        out.push(0xFC);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n < 16_777_216 {
        out.push(0xFD);
        out.push((n & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
        out.push(((n >> 16) & 0xFF) as u8);
    } else {
        out.push(0xFE);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn encode_lenenc_str(s: &str, out: &mut Vec<u8>) {
    encode_lenenc_int(s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

fn encode_ok_packet(seq: u8, affected_rows: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0x00); // OK header
    encode_lenenc_int(affected_rows, &mut p);
    encode_lenenc_int(0, &mut p); // last_insert_id
    p.extend_from_slice(&0x0002u16.to_le_bytes()); // status_flags
    p.extend_from_slice(&0u16.to_le_bytes()); // warnings
    MySqlWireSession::encode_packet(seq, &p)
}

fn encode_eof_packet(seq: u8) -> Vec<u8> {
    let p = [0xFE, 0x00, 0x00, 0x02, 0x00];
    MySqlWireSession::encode_packet(seq, &p)
}

fn encode_err_packet(seq: u8, code: u16, sql_state: &str, msg: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0xFF); // ERR header
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    p.extend_from_slice(sql_state.as_bytes().get(..5).unwrap_or(b"HY000"));
    p.extend_from_slice(msg.as_bytes());
    MySqlWireSession::encode_packet(seq, &p)
}

fn encode_resultset(mut seq: u8, rows: &[Value]) -> Vec<u8> {
    let cols: Vec<String> = match rows.first() {
        Some(Value::Object(map)) => map.keys().cloned().collect(),
        Some(_) => vec!["value".to_string()],
        None => return encode_ok_packet(seq, 0),
    };

    let mut out = Vec::new();
    // 1. Column count packet
    let mut cnt = Vec::new();
    encode_lenenc_int(cols.len() as u64, &mut cnt);
    out.extend_from_slice(&MySqlWireSession::encode_packet(seq, &cnt));
    seq = seq.wrapping_add(1);

    // 2. ColumnDefinition41 packets
    for col in &cols {
        let mut def = Vec::new();
        encode_lenenc_str("def", &mut def);
        encode_lenenc_str("", &mut def); // schema
        encode_lenenc_str("", &mut def); // table
        encode_lenenc_str("", &mut def); // org_table
        encode_lenenc_str(col, &mut def); // name
        encode_lenenc_str(col, &mut def); // org_name
        def.push(0x0c); // length of fixed-length fields
        def.extend_from_slice(&0x21u16.to_le_bytes()); // charset utf8
        def.extend_from_slice(&255u32.to_le_bytes()); // column_length
        def.push(0xFD); // MYSQL_TYPE_VAR_STRING
        def.extend_from_slice(&0u16.to_le_bytes()); // flags
        def.push(0); // decimals
        def.extend_from_slice(&0u16.to_le_bytes()); // filler
        out.extend_from_slice(&MySqlWireSession::encode_packet(seq, &def));
        seq = seq.wrapping_add(1);
    }

    // 3. EOF after column defs
    out.extend_from_slice(&encode_eof_packet(seq));
    seq = seq.wrapping_add(1);

    // 4. ProtocolText::ResultsetRow packets
    for row in rows {
        let mut rbuf = Vec::new();
        match row {
            Value::Object(map) => {
                for col in &cols {
                    match map.get(col) {
                        Some(Value::Null) | Some(Value::None) | None => rbuf.push(0xFB),
                        Some(v) => encode_lenenc_str(&v.display_compact(), &mut rbuf),
                    }
                }
            }
            scalar => encode_lenenc_str(&scalar.display_compact(), &mut rbuf),
        }
        out.extend_from_slice(&MySqlWireSession::encode_packet(seq, &rbuf));
        seq = seq.wrapping_add(1);
    }

    // 5. Final EOF
    out.extend_from_slice(&encode_eof_packet(seq));
    out
}
