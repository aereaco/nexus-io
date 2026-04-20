// SurrealDB WebSocket Handler - Direct RPC Protocol Implementation
// Bridges browser WebSocket connections to embedded SurrealDB client

use salvo::websocket::{Message, WebSocket, WebSocketUpgrade};
use salvo::prelude::*;
use salvo::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tokio::sync::mpsc;
use futures::{StreamExt, SinkExt};
use uuid::Uuid;
use std::collections::HashMap;

use crate::db::Database;

/// JSON-RPC 2.0 Request format
#[derive(Debug, Deserialize)]
struct RpcRequest {
    id: Option<JsonValue>,
    method: String,
    params: Vec<JsonValue>,
}

/// JSON-RPC 2.0 Response format
#[derive(Debug, Serialize)]
struct RpcResponse {
    id: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// JSON-RPC 2.0 Notification format (for LIVE events)
#[derive(Debug, Serialize)]
struct RpcNotification {
    method: String,
    params: Vec<JsonValue>,
}

///WebSocket handler struct that holds database reference
#[derive(Clone)]
pub struct WebSocketHandler {
    pub db: Arc<Database>,
}

#[async_trait]
impl Handler for WebSocketHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let db = self.db.clone();
        let _ = WebSocketUpgrade::new()
            .upgrade(req, res, move |ws| handle_websocket_connection(ws, db))
            .await;
    }
}

/// Handle individual WebSocket connection
async fn handle_websocket_connection(ws: WebSocket, db: Arc<Database>) {
    println!("🔌 WebSocket connection established");

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, mut rx) = mpsc::channel::<String>(100);
    
    // Task to manage active live query subscriptions
    let mut live_queries: HashMap<Uuid, tokio::task::JoinHandle<()>> = HashMap::new();

    // 1. WebSocket Sender Task
    // Reads from internal channel and pushes to actual WebSocket
    let sender_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = ws_tx.send(Message::text(msg)).await {
                eprintln!("❌ Failed to send WebSocket message: {}", e);
                break;
            }
        }
    });

    // 2. Main Receiver Loop
    // Reads from WebSocket and processes RPC calls
    while let Some(Ok(msg)) = ws_rx.next().await {
        if msg.is_text() {
            let text = String::from_utf8_lossy(msg.as_bytes());
            
            // Handle RPC message
            let db_clone = db.clone();
            let tx_clone = tx.clone();
            
            // We process RPCs one by one for now to maintain order and simplicity
            // but we could spawn them if we wanted multi-concurrency per WS
            handle_rpc_message_stream(&text, &db_clone, &tx_clone, &mut live_queries).await;
            
        } else if msg.is_close() {
            println!("👋 WebSocket connection closed");
            break;
        }
    }

    // Cleanup: stop all live streams
    println!("🧹 Cleaning up WebSocket session ({} active live queries)", live_queries.len());
    for (_, handle) in live_queries {
        handle.abort();
    }
    
    sender_task.abort();
}

/// Process RPC message and send response(s) to channel
async fn handle_rpc_message_stream(
    text: &str, 
    db: &Database, 
    tx: &mpsc::Sender<String>,
    live_queries: &mut HashMap<Uuid, tokio::task::JoinHandle<()>>,
) {
    // Parse RPC request
    let request: RpcRequest = match serde_json::from_str(text) {
        Ok(req) => req,
        Err(e) => {
            let resp = serde_json::to_string(&RpcResponse {
                id: None,
                result: None,
                error: Some(RpcError {
                    code: -32700,
                    message: format!("Parse error: {}", e),
                }),
            }).unwrap();
            let _ = tx.send(resp).await;
            return;
        }
    };

    // Handle RPC method
    // Note: handle_query will now handle spawning live stream tasks if needed
    let response = match request.method.as_str() {
        "query" => handle_query_stream(request.id, request.params, db, tx, live_queries).await,
        "ping" => handle_ping(request.id),
        "use" => handle_use(request.id, request.params).await,
        "signin" => handle_signin(request.id, request.params, db).await,
        "signup" => handle_signup(request.id, request.params, db).await,
        "authenticate" => handle_authenticate(request.id, request.params, db).await,
        "invalidate" => handle_invalidate(request.id),
        _ => RpcResponse {
            id: request.id,
            result: None,
            error: Some(RpcError {
                code: -32601,
                message: format!("Method not found: {}", request.method),
            }),
        },
    };

    let resp_text = serde_json::to_string(&response).unwrap();
    let _ = tx.send(resp_text).await;
}

// ============================================================================
// RPC Method Handlers
// ============================================================================

async fn handle_query_stream(
    id: Option<JsonValue>,
    params: Vec<JsonValue>,
    db: &Database,
    _tx: &mpsc::Sender<String>,
    _live_queries: &mut HashMap<Uuid, tokio::task::JoinHandle<()>>,
) -> RpcResponse {
    // Extract SQL query from params
    let sql = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return RpcResponse {
                id,
                result: None,
                error: Some(RpcError {
                    code: -32602,
                    message: "Invalid params: expected SQL string".to_string(),
                }),
            };
        }
    };

    // Extract bindings (optional second parameter)
    let bindings: Option<serde_json::Map<String, JsonValue>> = params
        .get(1)
        .and_then(|v| v.as_object())
        .cloned();

    // Execute query against embedded SurrealDB
    let mut query = db.client.query(sql);

    // Bind variables if provided
    if let Some(vars) = bindings {
        for (key, value) in vars {
            query = query.bind((key, value));
        }
    }

    match query.await {
        Ok(mut response) => {
            // In SurrealDB 3.0-beta.2, take(0) returns the raw result.
            // For LIVE SELECT, the result is the Uuid of the live query.
            let live_id: Option<uuid::Uuid> = match response.take::<Vec<uuid::Uuid>>(0) {
                Ok(mut v) => v.pop(),
                Err(_) => None,
            };

            if let Some(uuid) = live_id {
                println!("📡 LIVE SELECT detected: {}", uuid);
                
                // TODO: Re-implement live subscription for SurrealDB 3.0-beta.2
                // The 'subscribe' method is currently missing/changed in this beta.
                
                // Fallback: return the UUID but no internal streaming for now
                return RpcResponse {
                    id,
                    result: Some(serde_json::json!(uuid)),
                    error: None,
                };
            }

            // Normal query result
            let result: Result<Vec<JsonValue>, _> = response.take(0);

            match result {
                Ok(data) => RpcResponse {
                    id,
                    result: Some(serde_json::json!(data)),
                    error: None,
                },
                Err(e) => RpcResponse {
                    id,
                    result: None,
                    error: Some(RpcError {
                        code: -32000,
                        message: format!("Query error: {}", e),
                    }),
                },
            }
        }
        Err(e) => RpcResponse {
            id,
            result: None,
            error: Some(RpcError {
                code: -32000,
                message: format!("Database error: {}", e),
            }),
        },
    }
}

fn handle_ping(id: Option<JsonValue>) -> RpcResponse {
    RpcResponse {
        id,
        result: Some(serde_json::json!("pong")),
        error: None,
    }
}

async fn handle_use(id: Option<JsonValue>, params: Vec<JsonValue>) -> RpcResponse {
    // Extract NS and DB from params
    let ns = params.get(0).and_then(|v| v.as_str());
    let db_name = params.get(1).and_then(|v| v.as_str());

    if let (Some(ns), Some(db)) = (ns, db_name) {
        println!("🚀 Switching to NS: {}, DB: {}", ns, db);
        // Note: ns/db switching in the embedded client usually happens via use_ns/use_db
        // ForPoC, we assume the client is already configured or we would need a per-session client
        RpcResponse {
            id,
            result: Some(serde_json::json!(null)),
            error: None,
        }
    } else {
        RpcResponse {
            id,
            result: None,
            error: Some(RpcError {
                code: -32602,
                message: "Invalid params: expected namespace and database strings".to_string(),
            }),
        }
    }
}

async fn handle_signin(id: Option<JsonValue>, params: Vec<JsonValue>, _db: &Database) -> RpcResponse {
    // Extract credentials from params (usually a map for scope auth)
    let credentials = params.get(0).cloned().unwrap_or(JsonValue::Null);

    // In a real implementation, we would call db.client.signin(credentials).await
    // For PoC, we'll simulate a successful signin and return a mock token
    // that the IamMiddleware can later validate.
    
    // TODO: Transition to actual SurrealDB scope authentication
    println!("🔐 IAM: Sign-in request: {:?}", credentials);

    RpcResponse {
        id,
        result: Some(serde_json::json!({
            "token": "nexus_session_token_mock_123"
        })),
        error: None,
    }
}

async fn handle_signup(id: Option<JsonValue>, params: Vec<JsonValue>, _db: &Database) -> RpcResponse {
    let credentials = params.get(0).cloned().unwrap_or(JsonValue::Null);
    
    println!("👤 IAM: Sign-up request: {:?}", credentials);

    RpcResponse {
        id,
        result: Some(serde_json::json!({
            "token": "nexus_session_token_mock_123"
        })),
        error: None,
    }
}

async fn handle_authenticate(id: Option<JsonValue>, params: Vec<JsonValue>, _db: &Database) -> RpcResponse {
    let token = params.get(0).and_then(|v| v.as_str());

    if let Some(token) = token {
        println!("🔑 IAM: Authenticating with token: {}", token);
        // Validating via SurrealDB session would happen here
        RpcResponse {
            id,
            result: Some(serde_json::json!(true)),
            error: None,
        }
    } else {
        RpcResponse {
            id,
            result: None,
            error: Some(RpcError {
                code: -32602,
                message: "Invalid params: expected token string".to_string(),
            }),
        }
    }
}

fn handle_invalidate(id: Option<JsonValue>) -> RpcResponse {
    println!("🔓 IAM: Session invalidated");
    RpcResponse {
        id,
        result: Some(serde_json::json!(null)),
        error: None,
    }
}
