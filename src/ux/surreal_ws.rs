// SurrealDB-compatible WebSocket RPC Handler powered directly by `nexus_db::rpc::RpcSession`.
// Inherits the canonical `AuthContext` attached by `IamMiddleware` (no anonymous WS sessions).

use futures::{SinkExt, StreamExt};
use nexus_db::auth::AuthContext;
use salvo::async_trait;
use salvo::prelude::*;
use salvo::websocket::{Message, WebSocket, WebSocketUpgrade};
use std::sync::Arc;

use crate::db::Database;
use crate::ux::iam::depot_auth_context;
use crate::ux::surreal_http::extract_ns_db;

/// WebSocket handler exposing SurrealDB JSON-RPC 2.0 & CBOR wire protocol over `/rpc`.
#[derive(Clone)]
pub struct WebSocketHandler {
    pub db: Arc<Database>,
}

#[async_trait]
impl Handler for WebSocketHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let db = self.db.clone();
        let (ns, database) = extract_ns_db(req);
        let auth = depot_auth_context(depot);
        let _ = WebSocketUpgrade::new()
            .upgrade(req, res, move |ws| {
                handle_websocket_connection(ws, db, ns, database, auth)
            })
            .await;
    }
}

async fn handle_websocket_connection(
    ws: WebSocket,
    db: Arc<Database>,
    ns: String,
    database: String,
    auth: Option<AuthContext>,
) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut session = db.inner.rpc_session(&ns, &database);
    // Propagate canonical authenticated identity from `IamMiddleware` into `RpcSession`
    session.auth = auth;
    let mut live_tick = tokio::time::interval(std::time::Duration::from_millis(50));

    loop {
        tokio::select! {
            maybe_msg = ws_rx.next() => {
                let Some(Ok(msg)) = maybe_msg else {
                    break;
                };
                if msg.is_text() {
                    let text = String::from_utf8_lossy(msg.as_bytes());
                    let reply = session.handle_json(&text);
                    if ws_tx.send(Message::text(reply)).await.is_err() {
                        break;
                    }
                } else if msg.is_binary() {
                    let reply_bytes = session.handle_cbor(msg.as_bytes());
                    if ws_tx.send(Message::binary(reply_bytes)).await.is_err() {
                        break;
                    }
                } else if msg.is_close() {
                    break;
                }
            }
            _ = live_tick.tick() => {
                for frame in session.drain_live_notifications() {
                    if ws_tx.send(Message::text(frame)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}
