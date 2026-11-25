// UX Gateway - Salvo-based multi-port reverse proxy
// Architecture: HTTPS (443) + HTTP (80) + Optional direct access ports

use salvo::prelude::*;
use std::sync::Arc;

use crate::db::Database;
use crate::js::cell::CellManager;
use crate::storage::BlobBridge;
use crate::ux::cell_router::CellGatewayHandler;
use crate::ux::surreal_ws::WebSocketHandler;
use crate::ux::s3_proxy::S3ProxyHandler;

/// Gateway configuration - controls which ports are exposed
#[derive(Clone)]
pub struct GatewayConfig {
    pub enable_https: bool,          // Port 443 (primary gateway)
    pub enable_http: bool,           // Port 80 (ACME + redirects)
    pub enable_surreal_direct: bool, // Port 8000 (direct DB access)
    pub enable_pgwire: bool,         // Port 5432 (PostgreSQL v3 wire protocol)
    pub pgwire_port: u16,            // Default 5432
    pub enable_mysqlwire: bool,      // Port 3306 (MySQL v10 wire protocol)
    pub mysqlwire_port: u16,         // Default 3306
    pub enable_s3_direct: bool,      // Port 3900 (S3 API)
    pub enable_metrics: bool,        // Port 9090 (Prometheus)
    pub acme_domain: Option<String>, // Domain for ACME certs
    pub acme_email: Option<String>,  // Contact email for Let's Encrypt
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enable_https: true,
            enable_http: true,
            enable_surreal_direct: false,
            enable_pgwire: std::env::var("NEXUS_ENABLE_PGWIRE").as_deref() == Ok("1"),
            pgwire_port: std::env::var("NEXUS_PGWIRE_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5432),
            enable_mysqlwire: std::env::var("NEXUS_ENABLE_MYSQLWIRE").as_deref() == Ok("1"),
            mysqlwire_port: std::env::var("NEXUS_MYSQLWIRE_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3306),
            enable_s3_direct: false,
            enable_metrics: false,
            acme_domain: None,
            acme_email: None,
        }
    }
}

/// UX Gateway - The browser's entry point to the Nexus-IO kernel
#[derive(Clone)]
pub struct UxGateway {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
    cells: Arc<CellManager>,
    config: GatewayConfig,
}

impl UxGateway {
    pub fn new(db: Arc<Database>, garage: Arc<BlobBridge>, config: GatewayConfig) -> Self {
        let cells = Arc::new(CellManager::new(db.clone(), garage.clone()));
        Self { db, garage, cells, config }
    }

    /// Start all configured gateway listeners
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🌐 Nexus-IO Gateway starting...");
        println!("   HTTPS (443): {}", if self.config.enable_https { "✅" } else { "❌" });
        println!("   HTTP (80):   {}", if self.config.enable_http { "✅" } else { "❌" });
        println!("   DB Direct:   {}", if self.config.enable_surreal_direct { "✅" } else { "❌" });
        println!("   S3 Direct:   {}", if self.config.enable_s3_direct { "✅" } else { "❌" });
        println!("   Metrics:     {}", if self.config.enable_metrics { "✅" } else { "❌" });

        let mut handles = vec![];

        // Port 443: HTTPS Gateway (primary)
        if self.config.enable_https {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_https().await {
                    eprintln!("❌ HTTPS gateway error: {}", e);
                }
            }));
        }

        // Port 5432: PostgreSQL v3 Wire Protocol (`PgWireSession`) — disabled by default
        #[cfg(feature = "pgwire")]
        if self.config.enable_pgwire {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_pgwire().await {
                    eprintln!("❌ PgWire listener error: {}", e);
                }
            }));
        }

        // Port 3306: MySQL v10 Wire Protocol (`MySqlWireSession`) — disabled by default
        #[cfg(feature = "mysqlwire")]
        if self.config.enable_mysqlwire {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_mysqlwire().await {
                    eprintln!("❌ MySQL wire listener error: {}", e);
                }
            }));
        }

        // Port 80: HTTP Redirect + ACME challenges
        if self.config.enable_http {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_http().await {
                    eprintln!("❌ HTTP redirect error: {}", e);
                }
            }));
        }

        // Optional: Port 8000 (SurrealDB direct)
        if self.config.enable_surreal_direct {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_surreal_direct().await {
                    eprintln!("❌ SurrealDB direct access error: {}", e);
                }
            }));
        }

        // Optional: Port 3900 (Garage S3 direct)
        if self.config.enable_s3_direct {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_s3_direct().await {
                    eprintln!("❌ S3 direct access error: {}", e);
                }
            }));
        }

        // Optional: Port 9090 (Metrics)
        if self.config.enable_metrics {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_metrics().await {
                    eprintln!("❌ Metrics server error: {}", e);
                }
            }));
        }

        // Wait for all services
        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    /// Primary gateway listener:
    /// - Uses real Rustls HTTPS/TLS ONLY when `NEXUS_TLS_CERT` + `NEXUS_TLS_KEY` PEM files are configured.
    /// - Otherwise runs an explicitly labeled plaintext dev HTTP listener on `127.0.0.1:8443` (or `NEXUS_HTTP_BIND`).
    async fn serve_https(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = self.build_main_router();

        if let (Ok(cert_path), Ok(key_path)) = (
            std::env::var("NEXUS_TLS_CERT"),
            std::env::var("NEXUS_TLS_KEY"),
        ) {
            let bind_addr =
                std::env::var("NEXUS_HTTPS_BIND").unwrap_or_else(|_| "0.0.0.0:443".to_string());
            let cert = std::fs::read(&cert_path)?;
            let key = std::fs::read(&key_path)?;
            let config = salvo::conn::rustls::RustlsConfig::new(
                salvo::conn::rustls::Keycert::new().cert(cert).key(key),
            );
            let acceptor = TcpListener::new(bind_addr.clone()).rustls(config).bind().await;
            println!("🔒 HTTPS/TLS Gateway listening on https://{}", bind_addr);
            Server::new(acceptor).serve(router).await;
            return Ok(());
        }

        let dev_bind =
            std::env::var("NEXUS_HTTP_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
        println!(
            "⚠️  Dev HTTP Gateway (TLS DISABLED — plaintext) listening on http://{}",
            dev_bind
        );
        println!("   Set NEXUS_TLS_CERT and NEXUS_TLS_KEY to enable real HTTPS/TLS.");
        let acceptor = TcpListener::new(dev_bind).bind().await;
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 80: HTTP redirect to HTTPS + ACME challenges
    async fn serve_http(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .get(redirect_to_https)
            .push(Router::with_path("<**rest>").get(redirect_to_https));

        let acceptor = TcpListener::new("0.0.0.0:8080").bind().await;
        println!("✅ HTTP Redirect listening on 0.0.0.0:8080 (dev: using 8080 instead of 80)");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 5432 (configurable): PostgreSQL v3 Wire Protocol TCP listener (`psql`, `pg`, Prisma, Drizzle).
    /// Binds loopback (`127.0.0.1`) by default, handles `SSLRequest`, enforces `AuthenticationCleartextPassword`
    /// backed by `nexus-db` RBAC, and uses streaming length-prefixed TCP framing.
    #[cfg(feature = "pgwire")]
    async fn serve_pgwire(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nexus_db::pgwire::{PgWireSession, StartupPacket};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let bind_host =
            std::env::var("NEXUS_PGWIRE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let addr = format!("{}:{}", bind_host, self.config.pgwire_port);
        let trust_local = std::env::var("NEXUS_PGWIRE_TRUST_LOCAL").as_deref() == Ok("1");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!(
            "🐘 PostgreSQL v3 Wire Protocol (PgWire) listening on {} (auth: {})",
            addr,
            if trust_local { "trust-local" } else { "password-required" }
        );

        loop {
            let (mut socket, _) = listener.accept().await?;
            let db = self.db.clone();
            tokio::spawn(async move {
                let mut stream_buf: Vec<u8> = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];

                // 1. Read & parse PG v3 startup packet (handling optional SSLRequest first)
                let (ns, database, user) = loop {
                    match PgWireSession::parse_startup_packet(&stream_buf) {
                        Ok(Some((consumed, StartupPacket::SslRequest))) => {
                            stream_buf.drain(..consumed);
                            if socket.write_all(b"N").await.is_err() {
                                return;
                            }
                        }
                        Ok(Some((consumed, StartupPacket::Startup { user, database, ns, .. }))) => {
                            stream_buf.drain(..consumed);
                            break (ns, database, user);
                        }
                        Ok(None) => {
                            let Ok(n) = socket.read(&mut chunk).await else { return; };
                            if n == 0 {
                                return;
                            }
                            stream_buf.extend_from_slice(&chunk[..n]);
                        }
                        Err(_) => return,
                    }
                };

                let mut pg = if trust_local {
                    PgWireSession::new(db.inner.clone(), ns, database)
                } else {
                    PgWireSession::new_authenticated(db.inner.clone(), ns, database, user)
                };

                if socket.write_all(&pg.startup_response()).await.is_err() {
                    return;
                }

                // 2. Streaming length-prefixed PG v3 message loop (handles fragmented & coalesced TCP reads)
                loop {
                    loop {
                        match PgWireSession::extract_next_frame(&mut stream_buf) {
                            Ok(Some(frame)) => {
                                let is_terminate = frame.first() == Some(&b'X');
                                match pg.handle_frame(&frame) {
                                    Ok(reply) => {
                                        if !reply.is_empty() && socket.write_all(&reply).await.is_err() {
                                            return;
                                        }
                                        if is_terminate {
                                            return;
                                        }
                                    }
                                    Err(_) => return,
                                }
                            }
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }

                    let Ok(n) = socket.read(&mut chunk).await else { return; };
                    if n == 0 {
                        return;
                    }
                    stream_buf.extend_from_slice(&chunk[..n]);
                }
            });
        }
    }

    /// Port 3306 (configurable): MySQL v10 Wire Protocol TCP listener (`mysql`, MySQL2, Prisma, Drizzle).
    /// Binds loopback (`127.0.0.1`) by default, requires `HandshakeResponse41` auth backed by `nexus-db` RBAC,
    /// and uses streaming 4-byte MySQL packet framing.
    #[cfg(feature = "mysqlwire")]
    async fn serve_mysqlwire(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nexus_db::mysqlwire::MySqlWireSession;
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        static CONN_ID: AtomicU32 = AtomicU32::new(1);
        let bind_host =
            std::env::var("NEXUS_MYSQLWIRE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let addr = format!("{}:{}", bind_host, self.config.mysqlwire_port);
        let trust_local = std::env::var("NEXUS_MYSQLWIRE_TRUST_LOCAL").as_deref() == Ok("1");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!(
            "🐬 MySQL v10 Wire Protocol (MySqlWire) listening on {} (auth: {})",
            addr,
            if trust_local { "trust-local" } else { "password-required" }
        );

        loop {
            let (mut socket, _) = listener.accept().await?;
            let db = self.db.clone();
            let cid = CONN_ID.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut my = if trust_local {
                    MySqlWireSession::new(db.inner.clone(), "nexus", "system")
                } else {
                    MySqlWireSession::new_authenticated(db.inner.clone(), "nexus", "system", cid)
                };
                if socket.write_all(&my.handshake_greeting()).await.is_err() {
                    return;
                }

                let mut stream_buf: Vec<u8> = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];
                let mut handshake_done = false;

                loop {
                    loop {
                        match MySqlWireSession::extract_next_packet(&mut stream_buf) {
                            Ok(Some((seq, payload))) => {
                                if !handshake_done {
                                    handshake_done = true;
                                    match my.handle_handshake_response(seq, &payload) {
                                        Ok(resp) => {
                                            if socket.write_all(&resp).await.is_err() || !my.authenticated {
                                                return;
                                            }
                                        }
                                        Err(_) => return,
                                    }
                                } else {
                                    match my.handle_command(seq, &payload) {
                                        Ok((close, resp)) => {
                                            if !resp.is_empty() && socket.write_all(&resp).await.is_err() {
                                                return;
                                            }
                                            if close {
                                                return;
                                            }
                                        }
                                        Err(_) => return,
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }

                    let Ok(n) = socket.read(&mut chunk).await else { return; };
                    if n == 0 {
                        return;
                    }
                    stream_buf.extend_from_slice(&chunk[..n]);
                }
            });
        }
    }

    /// Port 8000: Direct SurrealDB access (optional)
    async fn serve_surreal_direct(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .push(Router::with_path("/rpc").post(surreal_rpc_handler));

        let acceptor = TcpListener::new("0.0.0.0:8000").bind().await;
        println!("✅ SurrealDB Direct Access listening on 0.0.0.0:8000");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 3900: Direct S3 API access (optional)
    async fn serve_s3_direct(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .push(Router::with_path("<**path>")
                .get(s3_get_handler)
                .put(s3_put_handler)
                .delete(s3_delete_handler)
            );

        let acceptor = TcpListener::new("0.0.0.0:3900").bind().await;
        println!("✅ S3 Direct Access listening on 0.0.0.0:3900");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 9090: Prometheus metrics (optional)
    async fn serve_metrics(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .get(metrics_handler);

        let acceptor = TcpListener::new("127.0.0.1:9090").bind().await;
        println!("✅ Metrics listening on 127.0.0.1:9090");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Build the main application router
    fn build_main_router(&self) -> Router {
        let router = Router::new()
            // Static PWA files
            .push(Router::with_path("/").get(serve_static))
            
            // WebSocket & HTTP JSON-RPC / CBOR Signal Hub (SurrealDB SDK wire protocol)
            .push({
                let db = self.db.clone();
                let ws_handler = WebSocketHandler { db: db.clone() };
                let http_rpc = crate::ux::surreal_http::SurrealHttpRpcHandler { db: db.clone() };
                let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                Router::with_path("/rpc")
                    .hoop(iam)
                    .get(ws_handler)
                    .post(http_rpc)
            })
            // SurrealDB-compatible HTTP REST API (/sql, /signin, /signup, /export, /import, /key, /api)
            .push(
                Router::with_path("/sql")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::SurrealSqlHandler { db: self.db.clone() }),
            )
            .push(Router::with_path("/signin").post(crate::ux::surreal_http::SurrealAuthHandler { db: self.db.clone(), is_signup: false }))
            .push(Router::with_path("/signup").post(crate::ux::surreal_http::SurrealAuthHandler { db: self.db.clone(), is_signup: true }))
            .push(
                Router::with_path("/export")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: false })
                    .post(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: false }),
            )
            .push(
                Router::with_path("/import")
                    .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                    .post(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: true }),
            )
            .push(
                Router::with_path("/key/<table:str>")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .post(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .delete(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() }),
            )
            .push(
                Router::with_path("/key/<table:str>/<id:str>")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .put(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .patch(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .delete(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() }),
            )
            .push(Router::with_path("/api/<ns:str>/<db:str>/<**path>")
                .get(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                .post(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                .put(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                .delete(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() }))
            // Public health/readiness/version + Observability metrics
            .push(Router::with_path("/status").get(crate::ux::surreal_http::surreal_status))
            .push(Router::with_path("/ready").get(crate::ux::surreal_http::surreal_ready))
            .push(Router::with_path("/version").get(crate::ux::surreal_http::surreal_version))
            .push(Router::with_path("/_nexus/metrics").get(serve_metrics))
            // Unified External Multi-Flavor Query API (`POST /query`, `POST /cells/:app/:cell_id/query`)
            .push(
                Router::with_path("/query")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::UnifiedQueryHandler {
                        db: self.db.clone(),
                        cells: self.cells.clone(),
                        default_flavor: "surql",
                    }),
            )
            .push(
                Router::with_path("/cells/<app:str>/<cell_id:str>/query")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::UnifiedQueryHandler {
                        db: self.db.clone(),
                        cells: self.cells.clone(),
                        default_flavor: "surql",
                    }),
            )
            // Privileged Multi-node WAL replication transport (Admin tier)
            .push(
                Router::with_path("/_nexus/wal/entries")
                    .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                    .get(crate::ux::surreal_http::WalReplicationHandler { db: self.db.clone(), is_apply: false }),
            )
            .push(
                Router::with_path("/_nexus/wal/apply")
                    .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                    .post(crate::ux::surreal_http::WalReplicationHandler { db: self.db.clone(), is_apply: true }),
            );

        #[cfg(feature = "graphql")]
        let router = router.push(
            Router::with_path("/graphql")
                .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                .post(crate::ux::surreal_http::UnifiedQueryHandler {
                    db: self.db.clone(),
                    cells: self.cells.clone(),
                    default_flavor: "graphql",
                }),
        );

        #[cfg(feature = "sqlite-hrana")]
        let router = router.push(
            Router::with_path("/v2/pipeline")
                .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                .post(crate::ux::surreal_http::SqliteHranaHandler { db: self.db.clone() }),
        );

        router
            
            // S3 Proxy (browser-friendly)
            .push({
                let db = self.db.clone();
                let garage = self.garage.clone();
                let s3_handler = S3ProxyHandler { garage };
                let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                Router::with_path("/s3/<**path>")
                    .hoop(iam)
                    .get(s3_handler.clone())
                    .put(s3_handler.clone())
                    .delete(s3_handler.clone())
                    .head(s3_handler)
            })
            
            // Unified Cell Ingress (/cells/<app>/<cell_id> & POST /cells/deploy-md)
            .push({
                let db = self.db.clone();
                let cell_handler = CellGatewayHandler {
                    db: db.clone(),
                    cells: self.cells.clone(),
                };
                let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                Router::with_path("/cells/<**path>")
                    .hoop(iam)
                    .get(cell_handler.clone())
                    .post(cell_handler.clone())
                    .put(cell_handler.clone())
                    .delete(cell_handler)
            })
            
            // Health check & runtime capability diagnostics
            .push(Router::with_path("/health").get(health_check))
            .push(Router::with_path("/_nexus/capabilities").get(capabilities_handler))
    }
}

#[handler]
async fn serve_metrics(res: &mut Response) {
    res.render(Json(crate::observability::global_metrics().snapshot()));
}

#[handler]
async fn capabilities_handler(res: &mut Response) {
    let reg = crate::runtime::CapabilityRegistry::new();
    reg.set_state("database", crate::runtime::CapabilityState::Active, Some("nexus-db".into()));
    reg.set_state("gateway", crate::runtime::CapabilityState::Active, Some("salvo".into()));
    reg.set_state("cells", crate::runtime::CapabilityState::Active, Some("wasmtime".into()));
    res.render(Json(reg.snapshot_json()));
}

// ============================================================================
// Route Handlers
// ============================================================================

#[handler]
async fn serve_static(res: &mut Response) {
    res.render(Text::Html(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nexus-IO Gateway</title>
  <style>
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      max-width: 900px; 
      margin: 60px auto; 
      padding: 0 20px;
      line-height: 1.6;
      color: #333;
    }
    h1 { 
      color: #2563eb; 
      font-size: 2.5em;
      margin-bottom: 0.3em;
    }
    h2 {
      color: #1e40af;
      margin-top: 1.5em;
      border-bottom: 2px solid #e5e7eb;
      padding-bottom: 0.3em;
    }
    .status { 
      background: #10b981; 
      color: white; 
      padding: 8px 16px; 
      border-radius: 6px;
      display: inline-block;
      font-weight: 600;
    }
    code { 
      background: #f3f4f6; 
      padding: 3px 8px; 
      border-radius: 4px; 
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
    }
    ul { line-height: 2; }
    .feature { margin: 10px 0; }
  </style>
</head>
<body>
  <h1>🌐 Nexus-IO Gateway</h1>
  <p><span class="status">● ONLINE</span></p>
  
  <h2>Available Routes</h2>
  <ul>
    <li class="feature"><code>/</code> - Static PWA (this page)</li>
    <li class="feature"><code>/rpc</code> - WebSocket Signal Hub (SurrealDB LIVE queries) - <em>TODO</em></li>
    <li class="feature"><code>/s3/*</code> - S3 API Proxy (Garage storage) - <em>TODO</em></li>
    <li class="feature"><code>/health</code> - Health check endpoint</li>
  </ul>
  
  <h2>Gateway Features</h2>
  <ul>
    <li class="feature">✅ Multi-port architecture (443, 80, optional direct access)</li>
    <li class="feature">✅ Salvo framework with built-in ACME support</li>
    <li class="feature">🚧 HTTP/3 support (planned)</li>
    <li class="feature">🚧 OpenAPI auto-generation (planned)</li>
    <li class="feature">🚧 WebSocket upgrades (in progress)</li>
    <li class="feature">🚧 S3 proxy to Garage (in progress)</li>
  </ul>

  <h2>Next Steps</h2>
  <p>The gateway foundation is established. Upcoming implementations:</p>
  <ol>
    <li>ACME/Let's Encrypt integration with production domain</li>
    <li>WebSocket upgrade for SurrealDB LIVE queries</li>
    <li>S3 proxy layer to Garage storage</li>
    <li>IAM session validation across all routes</li>
  </ol>
</body>
</html>"#,
    ));
}

#[handler]
async fn health_check(res: &mut Response) {
    res.render(Json(serde_json::json!({
        "status": "ok",
        "service": "nexus-io-gateway",
        "version": env!("CARGO_PKG_VERSION"),
    })));
}

#[handler]
async fn redirect_to_https(req: &mut Request, res: &mut Response) {
    let host = req.header::<String>("host").unwrap_or_else(|| "localhost".to_string());
    let path = req.uri().path();
    let target = format!("https://{}{}", host, path);
    
    res.status_code(StatusCode::MOVED_PERMANENTLY);
    res.add_header("Location", target, true).ok();
}

// Optional port handlers (stubs for now)

#[handler]
async fn surreal_rpc_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct SurrealDB RPC not yet implemented"));
}

#[handler]
async fn s3_get_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct S3 GET not yet implemented"));
}

#[handler]
async fn s3_put_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct S3 PUT not yet implemented"));
}

#[handler]
async fn s3_delete_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct S3 DELETE not yet implemented"));
}

#[handler]
async fn metrics_handler(res: &mut Response) {
    // TODO: Integrate with prometheus crate
    res.render(Text::Plain("# Nexus-IO Metrics\n# TODO: Implement Prometheus integration"));
}
