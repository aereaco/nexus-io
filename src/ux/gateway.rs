// UX Gateway - Salvo-based multi-port reverse proxy
// Architecture: HTTPS (443) + HTTP (80) + Optional direct access ports

use salvo::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::db::Database;
use crate::js::cell::CellManager;
use crate::storage::cas_store::{CasStore, ReconciliationReport, DEFAULT_DELETE_CLAIM_TTL_MS};
use crate::storage::BlobBridge;
use crate::ux::cell_router::CellGatewayHandler;
use crate::ux::surreal_ws::WebSocketHandler;
use crate::ux::s3_proxy::S3ProxyHandler;

/// Fail-closed middleware that blocks storage-dependent routes with `503 Service Unavailable`
/// until `UxGateway::reconcile_storage_on_boot()` has completed durably.
#[derive(Clone)]
struct BootRecoveryGateMiddleware {
    storage_ready: Arc<AtomicBool>,
}

#[async_trait]
impl Handler for BootRecoveryGateMiddleware {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if !self.storage_ready.load(Ordering::SeqCst) {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Json(serde_json::json!({
                "error": "Storage boot recovery has not completed yet"
            })));
            ctrl.skip_rest();
        }
    }
}

/// Readiness probe (`/ready`): returns `503 Service Unavailable` until startup storage
/// reconciliation completes, and `200 OK` once ready (distinct from `/health` liveness).
#[derive(Clone)]
struct ReadinessHandler {
    storage_ready: Arc<AtomicBool>,
}

#[async_trait]
impl Handler for ReadinessHandler {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        if self.storage_ready.load(Ordering::SeqCst) {
            res.status_code(StatusCode::OK);
            res.render(Json(serde_json::json!({ "ready": true })));
        } else {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Json(serde_json::json!({
                "ready": false,
                "reason": "storage_boot_recovery_pending"
            })));
        }
    }
}

/// Gateway configuration — strictly opt-in service activation and bind policies.
/// **Zero-trust default:** `GatewayConfig::default()` enables zero application/data/web/proxy
/// services (only `/health`, `/ready`, `/status`, `/version`, and `/_nexus/capabilities` probes).
#[derive(Clone)]
pub struct GatewayConfig {
    pub enable_https: bool,          // Primary gateway listener (HTTPS when TLS configured, else dev HTTP)
    pub enable_http: bool,           // Port 80/8080 HTTP->HTTPS redirect (opt-in)
    pub bind_addr: Option<String>,   // Explicit bind address (default: 127.0.0.1:8443 in dev / 0.0.0.0:443 with TLS)
    pub enable_rpc: bool,            // /rpc, /sql, /query, /signin, /signup, /signout, /_nexus/auth/me, /export, /import, /key/*, /api/*
    pub enable_cells: bool,          // /cells/*, /_nexus/deploy*, /_nexus/apps/*
    pub enable_s3: bool,             // /s3/*
    pub enable_web: bool,            // Static web app & SPA serving (requires `serve-web` + explicit `web_root`)
    pub enable_proxy: bool,          // /proxy/* reverse proxy (requires `serve-proxy`)
    pub enable_graphql: bool,        // /graphql (requires `db-graphql`)
    pub enable_sqlite: bool,         // /v2/pipeline (requires `db-sqlite`)
    pub enable_surreal_direct: bool, // Port 8000 (direct DB access)
    pub enable_pgwire: bool,         // Port 5432 (PostgreSQL v3 wire protocol)
    pub pgwire_port: u16,            // Default 5432
    pub enable_mysqlwire: bool,      // Port 3306 (MySQL v10 wire protocol)
    pub mysqlwire_port: u16,         // Default 3306
    pub enable_s3_direct: bool,      // Port 3900 (S3 API)
    pub enable_metrics: bool,        // Port 9090 (Prometheus) & /_nexus/metrics
    pub acme_domain: Option<String>, // Domain for ACME certs
    pub acme_email: Option<String>,  // Contact email for Let's Encrypt
    pub web_root: Option<std::path::PathBuf>,
    pub dist_root: Option<std::path::PathBuf>,
    pub spa_fallback: bool,
    pub coop_header: Option<String>,
    pub coep_header: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enable_https: true,
            enable_http: false,
            bind_addr: None,
            enable_rpc: false,
            enable_cells: false,
            enable_s3: false,
            enable_web: false,
            enable_proxy: false,
            enable_graphql: false,
            enable_sqlite: false,
            enable_surreal_direct: false,
            enable_pgwire: false,
            pgwire_port: 5432,
            enable_mysqlwire: false,
            mysqlwire_port: 3306,
            enable_s3_direct: false,
            enable_metrics: false,
            acme_domain: None,
            acme_email: None,
            web_root: None,
            dist_root: None,
            spa_fallback: true,
            coop_header: Some("same-origin".to_string()),
            coep_header: Some("credentialless".to_string()),
        }
    }
}

impl GatewayConfig {
    /// Convenience constructor for programmatic embedders and tests that explicitly opt into
    /// the core data-plane services (`rpc`, `cells`, `s3`) without web/proxy serving.
    pub fn all_core() -> Self {
        Self {
            enable_rpc: true,
            enable_cells: true,
            enable_s3: true,
            enable_metrics: true,
            ..Self::default()
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
    storage_ready: Arc<AtomicBool>,
}

impl UxGateway {
    pub fn new(db: Arc<Database>, garage: Arc<BlobBridge>, config: GatewayConfig) -> Self {
        let cells = Arc::new(CellManager::new(db.clone(), garage.clone()));
        Self {
            db,
            garage,
            cells,
            config,
            storage_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Startup invariant: run `CasStore::reconcile_on_boot()` across both durable CAS buckets
    /// (`nexus-wasm-db` and `nexus-runtimes`) to replay any incomplete write-ahead `OwnershipTx`
    /// journals and recover expired `DeleteClaim`s BEFORE the gateway accepts cell work.
    pub async fn reconcile_storage_on_boot(
        &self,
    ) -> anyhow::Result<(ReconciliationReport, ReconciliationReport)> {
        let cas = CasStore::new(self.garage.clone());
        let empty = std::collections::HashSet::new();
        let db_rep = cas
            .reconcile_on_boot(
                "nexus-wasm-db",
                "blobs/",
                &empty,
                DEFAULT_DELETE_CLAIM_TTL_MS,
                false,
            )
            .await?;
        let rt_rep = cas
            .reconcile_on_boot(
                "nexus-runtimes",
                "cid/",
                &empty,
                DEFAULT_DELETE_CLAIM_TTL_MS,
                false,
            )
            .await?;
        let restored_cells = self.cells.restore_persisted_workloads().await.unwrap_or(0);
        if restored_cells > 0 {
            println!("🔄 Restored {} persisted Wasm cell workload(s)", restored_cells);
        }
        self.storage_ready.store(true, Ordering::SeqCst);
        Ok((db_rep, rt_rep))
    }

    pub fn is_storage_ready(&self) -> bool {
        self.storage_ready.load(Ordering::SeqCst)
    }

    /// Start all configured gateway listeners (always completes storage boot recovery first).
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let (db_rep, rt_rep) = self.reconcile_storage_on_boot().await?;
        if !db_rep.skipped || !rt_rep.skipped {
            println!(
                "🔄 Storage boot recovery complete (wasm-db tx={}, claims={}; runtimes tx={}, claims={})",
                db_rep.tx_replayed,
                db_rep.expired_claims_recovered,
                rt_rep.tx_replayed,
                rt_rep.expired_claims_recovered
            );
        }

        println!("🌐 Nexus-IO Gateway starting (explicit opt-in services):");
        println!("   RPC / DB:    {}", if self.config.enable_rpc { "✅" } else { "❌" });
        println!("   Wasm Cells:  {}", if self.config.enable_cells { "✅" } else { "❌" });
        println!("   S3 Storage:  {}", if self.config.enable_s3 { "✅" } else { "❌" });
        println!("   Web Server:  {}", if self.config.enable_web { "✅" } else { "❌" });
        println!("   Web Proxy:   {}", if self.config.enable_proxy { "✅" } else { "❌" });
        println!("   Metrics:     {}", if self.config.enable_metrics { "✅" } else { "❌" });

        let mut handles = vec![];

        // Port 443: HTTPS Gateway (primary)
        if self.config.enable_https {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_https().await {
                    eprintln!("âŒ HTTPS gateway error: {}", e);
                }
            }));
        }

        // Port 5432: PostgreSQL v3 Wire Protocol (`PgWireSession`) — disabled by default
        #[cfg(feature = "db-pgwire")]
        if self.config.enable_pgwire {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_pgwire().await {
                    eprintln!("âŒ PgWire listener error: {}", e);
                }
            }));
        }

        // Port 3306: MySQL v10 Wire Protocol (`MySqlWireSession`) — disabled by default
        #[cfg(feature = "db-mysqlwire")]
        if self.config.enable_mysqlwire {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_mysqlwire().await {
                    eprintln!("âŒ MySQL wire listener error: {}", e);
                }
            }));
        }

        // Port 80: HTTP Redirect + ACME challenges
        if self.config.enable_http {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_http().await {
                    eprintln!("âŒ HTTP redirect error: {}", e);
                }
            }));
        }

        // Optional: Port 8000 (SurrealDB direct)
        if self.config.enable_surreal_direct {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_surreal_direct().await {
                    eprintln!("âŒ SurrealDB direct access error: {}", e);
                }
            }));
        }

        // Optional: Port 3900 (Garage S3 direct)
        if self.config.enable_s3_direct {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_s3_direct().await {
                    eprintln!("âŒ S3 direct access error: {}", e);
                }
            }));
        }

        // Optional: Port 9090 (Metrics)
        if self.config.enable_metrics {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_metrics().await {
                    eprintln!("âŒ Metrics server error: {}", e);
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
            let bind_addr = self
                .config
                .bind_addr
                .clone()
                .or_else(|| std::env::var("NEXUS_HTTPS_BIND").ok())
                .unwrap_or_else(|| "0.0.0.0:443".to_string());
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

        let dev_bind = self
            .config
            .bind_addr
            .clone()
            .or_else(|| std::env::var("NEXUS_HTTP_BIND").ok())
            .unwrap_or_else(|| "127.0.0.1:8443".to_string());
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
    #[cfg(feature = "db-pgwire")]
    async fn serve_pgwire(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nexus_db::pgwire::{PgWireSession, StartupPacket};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let bind_host =
            std::env::var("NEXUS_PGWIRE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let is_loopback_bind = matches!(bind_host.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !is_loopback_bind {
            return Err(format!(
                "Refusing plaintext PgWire bind on non-loopback host '{}': remote wire-protocol access requires TLS",
                bind_host
            )
            .into());
        }
        let addr = format!("{}:{}", bind_host, self.config.pgwire_port);
        let trust_local_env = std::env::var("NEXUS_PGWIRE_TRUST_LOCAL").as_deref() == Ok("1");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!(
            "🐘 PostgreSQL v3 Wire Protocol (PgWire) listening on {} (auth: {})",
            addr,
            if trust_local_env { "trust-loopback-only" } else { "password-required" }
        );

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            let trust_local = trust_local_env && peer_addr.ip().is_loopback();
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
    #[cfg(feature = "db-mysqlwire")]
    async fn serve_mysqlwire(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nexus_db::mysqlwire::MySqlWireSession;
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        static CONN_ID: AtomicU32 = AtomicU32::new(1);
        let bind_host =
            std::env::var("NEXUS_MYSQLWIRE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let is_loopback_bind = matches!(bind_host.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !is_loopback_bind {
            return Err(format!(
                "Refusing plaintext MySqlWire bind on non-loopback host '{}': remote wire-protocol access requires TLS",
                bind_host
            )
            .into());
        }
        let addr = format!("{}:{}", bind_host, self.config.mysqlwire_port);
        let trust_local_env = std::env::var("NEXUS_MYSQLWIRE_TRUST_LOCAL").as_deref() == Ok("1");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!(
            "🐬 MySQL v10 Wire Protocol (MySqlWire) listening on {} (auth: {})",
            addr,
            if trust_local_env { "trust-loopback-only" } else { "password-required" }
        );

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            let trust_local = trust_local_env && peer_addr.ip().is_loopback();
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

    /// Build the main application router.
    /// Every storage-dependent route (`/rpc`, `/sql`, `/export`, `/import`, `/key/*`, `/api/*`,
    /// `/query`, `/cells/*`, `/s3/*`, `/graphql`, `/v2/pipeline`) is guarded by
    /// `BootRecoveryGateMiddleware` (`503` until `reconcile_storage_on_boot()` succeeds).
    fn build_main_router(&self) -> Router {
        let gate = BootRecoveryGateMiddleware {
            storage_ready: self.storage_ready.clone(),
        };

        // Baseline operational probes (always available so orchestrators can monitor node health)
        let mut router = Router::new()
            .push(Router::with_path("/health").get(health_check))
            .push(Router::with_path("/status").get(crate::ux::surreal_http::surreal_status))
            .push(Router::with_path("/ready").get(ReadinessHandler {
                storage_ready: self.storage_ready.clone(),
            }))
            .push(Router::with_path("/version").get(crate::ux::surreal_http::surreal_version))
            .push(Router::with_path("/_nexus/capabilities").get(capabilities_handler));

        if self.config.enable_metrics {
            router = router.push(Router::with_path("/_nexus/metrics").get(serve_metrics));
        }

        // Opt-in RPC / Database / IAM Authentication surface
        if self.config.enable_rpc {
            router = router
                .push({
                    let db = self.db.clone();
                    let ws_handler = WebSocketHandler { db: db.clone() };
                    let http_rpc = crate::ux::surreal_http::SurrealHttpRpcHandler { db: db.clone() };
                    let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                    Router::with_path("/rpc")
                        .hoop(gate.clone())
                        .hoop(iam)
                        .get(ws_handler)
                        .post(http_rpc)
                })
                .push(
                    Router::with_path("/sql")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(crate::ux::surreal_http::SurrealSqlHandler { db: self.db.clone() }),
                )
                .push(Router::with_path("/signin").post(crate::ux::surreal_http::SurrealAuthHandler { db: self.db.clone(), is_signup: false }))
                .push(Router::with_path("/signup").post(crate::ux::surreal_http::SurrealAuthHandler { db: self.db.clone(), is_signup: true }))
                .push(Router::with_path("/signout").post(crate::ux::surreal_http::SurrealSignoutHandler))
                .push(Router::with_path("/_nexus/auth/me").get(crate::ux::surreal_http::AuthMeHandler { db: self.db.clone() }))
                .push(
                    Router::with_path("/_nexus/auth/password")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(crate::ux::surreal_http::ChangeOwnPasswordHandler { db: self.db.clone() }),
                )
                .push(Router::with_path("/_nexus/setup/status").get(crate::ux::surreal_http::SetupStatusHandler { db: self.db.clone() }))
                .push(Router::with_path("/_nexus/setup/bootstrap").post(crate::ux::surreal_http::SetupBootstrapHandler { db: self.db.clone() }))
                .push(
                    Router::with_path("/_nexus/iam/users")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .get(crate::ux::surreal_http::IamUsersHandler { db: self.db.clone() })
                        .post(crate::ux::surreal_http::IamUsersHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/users/{name}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .put(crate::ux::surreal_http::IamUserItemHandler { db: self.db.clone() })
                        .patch(crate::ux::surreal_http::IamUserItemHandler { db: self.db.clone() })
                        .delete(crate::ux::surreal_http::IamUserItemHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/policies/apply")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .post(crate::ux::surreal_http::IamPolicyApplyHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/export")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: false })
                        .post(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: false }),
                )
                .push(
                    Router::with_path("/import")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .post(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: true }),
                )
                .push(
                    Router::with_path("/key/{table}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                        .post(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                        .delete(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/key/{table}/{id}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                        .put(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                        .patch(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                        .delete(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/api/{ns}/{db}/{**path}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                        .post(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                        .put(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                        .delete(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/query")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(crate::ux::surreal_http::UnifiedQueryHandler {
                            db: self.db.clone(),
                            cells: self.cells.clone(),
                            default_flavor: "surql",
                        }),
                )
                .push(
                    Router::with_path("/_nexus/wal/entries")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .get(crate::ux::surreal_http::WalReplicationHandler { db: self.db.clone(), is_apply: false }),
                )
                .push(
                    Router::with_path("/_nexus/wal/apply")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .post(crate::ux::surreal_http::WalReplicationHandler { db: self.db.clone(), is_apply: true }),
                )
                .push(
                    Router::with_path("/_nexus/mesh/status")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(MeshStatusHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        }),
                )
                .push(
                    Router::with_path("/_nexus/mesh/gossip")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(MeshGossipHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        }),
                )
                .push(
                    Router::with_path("/_nexus/mesh/blobs/{cid}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(MeshBlobTransferHandler {
                            garage: self.garage.clone(),
                        })
                        .put(MeshBlobTransferHandler {
                            garage: self.garage.clone(),
                        }),
                )
                .push(
                    Router::with_path("/_nexus/hardware")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(HardwareListHandler),
                )
                .push(
                    Router::with_path("/_nexus/hardware/call")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(HardwareCallHandler),
                )
                .push(
                    Router::with_path("/v2")
                        .get(OciV2PingHandler),
                )
                .push(
                    Router::with_path("/v2/")
                        .get(OciV2PingHandler),
                )
                .push(
                    Router::with_path("/v2/{ns}/{repo}/blobs/{digest}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(RegistryBlobHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        })
                        .put(RegistryBlobHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        }),
                )
                .push(
                    Router::with_path("/v2/{ns}/{repo}/manifests/{reference}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(RegistryManifestHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        })
                        .put(RegistryManifestHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        }),
                )
                .push(
                    Router::with_path("/_nexus/registry/packages")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(RegistryPackagesHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        }),
                )
                .push(
                    Router::with_path("/_nexus/registry/install")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(RegistryInstallHandler {
                            db: self.db.clone(),
                            garage: self.garage.clone(),
                        }),
                );
        }

        // Opt-in GraphQL endpoint
        #[cfg(feature = "db-graphql")]
        if self.config.enable_graphql {
            router = router.push(
                Router::with_path("/graphql")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::UnifiedQueryHandler {
                        db: self.db.clone(),
                        cells: self.cells.clone(),
                        default_flavor: "graphql",
                    }),
            );
        }

        // Opt-in SQLite Hrana endpoint
        #[cfg(feature = "db-sqlite")]
        if self.config.enable_sqlite {
            router = router.push(
                Router::with_path("/v2/pipeline")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::SqliteHranaHandler { db: self.db.clone() }),
            );
        }

        // Opt-in Reverse Proxy surface
        #[cfg(feature = "serve-proxy")]
        if self.config.enable_proxy {
            router = router.push(
                Router::with_path("/proxy/{upstream}/{**path}")
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::reverse_proxy::ReverseProxyHandler::from_env())
                    .post(crate::ux::reverse_proxy::ReverseProxyHandler::from_env())
                    .put(crate::ux::reverse_proxy::ReverseProxyHandler::from_env())
                    .delete(crate::ux::reverse_proxy::ReverseProxyHandler::from_env()),
            );
        }

        // Opt-in S3 Object Storage Proxy surface
        if self.config.enable_s3 {
            let db = self.db.clone();
            let garage = self.garage.clone();
            let s3_handler = S3ProxyHandler { garage };
            let iam = crate::ux::iam::IamMiddleware::authenticated(db);
            router = router.push(
                Router::with_path("/s3/{**path}")
                    .hoop(gate.clone())
                    .hoop(iam)
                    .get(s3_handler.clone())
                    .put(s3_handler.clone())
                    .delete(s3_handler.clone())
                    .head(s3_handler),
            );
        }

        // Opt-in Wasmtime Cell Ingress & AppManifest Deploy surface
        if self.config.enable_cells {
            router = router.push(
                Router::with_path("/_nexus/cells")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::CellsListHandler { cells: self.cells.clone() }),
            );
            router = router.push(
                Router::with_path("/cells/{app}/{cell_id}/query")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::UnifiedQueryHandler {
                        db: self.db.clone(),
                        cells: self.cells.clone(),
                        default_flavor: "surql",
                    }),
            );

            #[cfg(feature = "runtime-wasm")]
            {
                router = router
                    .push(
                        Router::with_path("/_nexus/deploy")
                            .hoop(gate.clone())
                            .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                            .post(DeploySubmitHandler {
                                cells: self.cells.clone(),
                                garage: self.garage.clone(),
                            }),
                    )
                    .push(
                        Router::with_path("/_nexus/deploy/{operation_id}")
                            .hoop(gate.clone())
                            .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                            .get(DeployOperationHandler {
                                garage: self.garage.clone(),
                            }),
                    )
                    .push(
                        Router::with_path("/_nexus/apps/{app_id}")
                            .hoop(gate.clone())
                            .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                            .get(DeployedAppHandler {
                                garage: self.garage.clone(),
                            }),
                    );
            }

            let db = self.db.clone();
            let cell_handler = CellGatewayHandler {
                db: db.clone(),
                cells: self.cells.clone(),
            };
            let iam = crate::ux::iam::IamMiddleware::authenticated(db);
            router = router.push(
                Router::with_path("/cells/{**path}")
                    .hoop(gate)
                    .hoop(iam)
                    .get(cell_handler.clone())
                    .post(cell_handler.clone())
                    .put(cell_handler.clone())
                    .delete(cell_handler),
            );
        }

        // Opt-in Static Web Application & SPA Fallback (mounted LAST, ONLY when explicitly declared)
        #[cfg(feature = "serve-web")]
        if self.config.enable_web {
            let web_handler = WebStaticHandler::from_config(&self.config);
            let dist_handler = DistStaticHandler::from_config(&self.config);
            router = router
                .push(Router::with_path("/dist/{**path}").get(dist_handler))
                .push(Router::with_path("/web/{**path}").get(web_handler.clone()))
                .push(Router::with_path("/").get(web_handler.clone()))
                .push(Router::with_path("/{**path}").get(web_handler));
        }

        router
    }

    /// Expose the configured Salvo router for programmatic embedding and integration tests.
    ///
    /// **Embedder contract:** Storage-dependent routes fail closed (`503 Service Unavailable`)
    /// and `/ready` reports `503` until the embedder explicitly invokes
    /// `self.reconcile_storage_on_boot().await?`.
    pub fn router(&self) -> Router {
        self.build_main_router()
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct DeploySubmitHandler {
    cells: Arc<CellManager>,
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for DeploySubmitHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::compute::manifest::{AppManifest, ManifestReconciler};
        use crate::iam::capabilities::{Capability, CapabilitySet};

        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller_caps = CapabilitySet::from_auth_context(auth.as_ref());
        if !caller_caps.has(Capability::CellSpawn) {
            crate::observability::global_metrics().inc_iam_auth_denial();
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({
                "error": "Missing required capability `cell.spawn` for /_nexus/deploy"
            })));
            return;
        }

        let Ok(raw_body) = req.payload_with_max_size(1024 * 1024).await else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "Failed to read manifest body" })));
            return;
        };
        let Ok(body_str) = std::str::from_utf8(raw_body) else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "Manifest body must be valid UTF-8" })));
            return;
        };

        let trimmed = body_str.trim();
        let parsed = if trimmed.starts_with('{') {
            AppManifest::from_json(trimmed)
        } else {
            AppManifest::from_toml(trimmed)
        };
        let manifest = match parsed {
            Ok(m) => m,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
                return;
            }
        };
        let validated = match manifest.validate() {
            Ok(v) => v,
            Err(e) => {
                res.status_code(StatusCode::UNPROCESSABLE_ENTITY);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
                return;
            }
        };

        match ManifestReconciler::apply(
            &self.cells,
            &self.garage,
            &validated,
            &CapabilitySet::admin_all(),
            auth.as_ref(),
        )
        .await
        {
            Ok(op) => {
                res.status_code(StatusCode::ACCEPTED);
                res.render(Json(op));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct DeployOperationHandler {
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for DeployOperationHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let op_id = req.param::<String>("operation_id").unwrap_or_default();
        match crate::compute::manifest::ManifestReconciler::get_operation(&self.garage, &op_id).await
        {
            Ok(Some(op)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(op));
            }
            Ok(None) => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(serde_json::json!({ "error": "Deployment operation not found" })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct DeployedAppHandler {
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for DeployedAppHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let app_id = req.param::<String>("app_id").unwrap_or_default();
        match crate::compute::manifest::ManifestReconciler::get_app(&self.garage, &app_id).await {
            Ok(Some(rec)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(rec));
            }
            Ok(None) => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(serde_json::json!({ "error": "Application deployment not found" })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct MeshStatusHandler {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for MeshStatusHandler {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::compute::NodeResources;
        use crate::storage::mesh::MeshReactor;
        use crate::storage::wireguard::{derive_mesh_ipv4, derive_mesh_ipv6, WireGuardInterface};

        let node_id = self.garage.node_id().to_string();
        let wg_ipv4 = derive_mesh_ipv4(&node_id);
        let wg_ipv6 = derive_mesh_ipv6(&node_id);
        let local_resources = NodeResources::scan();
        let (peers, peer_configs, _) = MeshReactor::load_mesh_snapshot(&self.db)
            .await
            .unwrap_or_default();
        let uapi_preview = WireGuardInterface::format_uapi_set_peers(&peer_configs);

        res.status_code(StatusCode::OK);
        res.render(Json(serde_json::json!({
            "node_id": node_id,
            "wg_ipv4": wg_ipv4,
            "wg_ipv6": wg_ipv6,
            "resources": local_resources,
            "peer_count": peers.len(),
            "peers": peers,
            "wireguard_uapi_bytes": uapi_preview.len()
        })));
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct MeshGossipHandler {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for MeshGossipHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::compute::NodeResources;
        use crate::iam::capabilities::{Capability, CapabilitySet};
        use crate::storage::mesh::{MeshGossipPayload, MeshReactor};
        use crate::storage::wireguard::{derive_mesh_ipv4, derive_mesh_ipv6};

        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller_caps = CapabilitySet::from_auth_context(auth.as_ref());
        if !caller_caps.has(Capability::CellSpawn) && !caller_caps.has(Capability::DbWrite) {
            crate::observability::global_metrics().inc_iam_auth_denial();
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({
                "error": "Missing required capability for /_nexus/mesh/gossip"
            })));
            return;
        }

        let payload: MeshGossipPayload = match req.parse_json().await {
            Ok(p) => p,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": format!("Invalid gossip JSON: {}", e) })));
                return;
            }
        };

        let target_pubkey = payload.pubkey.clone();
        match MeshReactor::ingest_gossip(&self.db, &self.garage, payload).await {
            Ok(merged) => {
                let node_id = self.garage.node_id().to_string();
                let (peers, _, _) = MeshReactor::load_mesh_snapshot(&self.db)
                    .await
                    .unwrap_or_default();
                let mesh_ipv4 = derive_mesh_ipv4(&target_pubkey);
                let mesh_ipv6 = derive_mesh_ipv6(&target_pubkey);
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({
                    "status": "ok",
                    "accepted": true,
                    "merged": merged,
                    "node_id": node_id,
                    "mesh_ipv4": mesh_ipv4,
                    "mesh_ipv6": mesh_ipv6,
                    "wg_ipv4": derive_mesh_ipv4(&node_id),
                    "wg_ipv6": derive_mesh_ipv6(&node_id),
                    "resources": NodeResources::scan(),
                    "peers": peers
                })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct MeshBlobTransferHandler {
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for MeshBlobTransferHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::iam::capabilities::{Capability, CapabilitySet};
        use crate::storage::cas_store::CasStore;

        let raw_cid = req.param::<String>("cid").unwrap_or_default();
        let hex_cid = raw_cid.strip_prefix("blake3:").unwrap_or(&raw_cid).to_ascii_lowercase();
        if hex_cid.len() != 64 || !hex_cid.chars().all(|c| c.is_ascii_hexdigit()) {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "Invalid BLAKE3 CID format" })));
            return;
        }

        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller_caps = CapabilitySet::from_auth_context(auth.as_ref());
        let cas = CasStore::new(self.garage.clone());
        let mesh_bucket = "nexus-mesh-cas";

        match *req.method() {
            salvo::http::Method::GET => {
                if !caller_caps.has(Capability::BlobRead) {
                    res.status_code(StatusCode::FORBIDDEN);
                    return;
                }
                match cas.get_verified_blob(mesh_bucket, "blobs/", &hex_cid).await {
                    Ok(bytes) => {
                        res.status_code(StatusCode::OK);
                        res.headers_mut().insert(
                            salvo::http::header::CONTENT_TYPE,
                            salvo::http::HeaderValue::from_static("application/octet-stream"),
                        );
                        let _ = res.write_body(bytes);
                    }
                    Err(e) => {
                        res.status_code(StatusCode::NOT_FOUND);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::PUT => {
                if !caller_caps.has(Capability::BlobWrite) {
                    res.status_code(StatusCode::FORBIDDEN);
                    return;
                }
                let Ok(payload) = req.payload_with_max_size(16 * 1024 * 1024).await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                let actual_hex = blake3::hash(payload).to_hex().to_string();
                if actual_hex != hex_cid {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(serde_json::json!({
                        "error": format!("BLAKE3 digest mismatch: expected {}, got {}", hex_cid, actual_hex)
                    })));
                    return;
                }
                let _ = self.garage.create_bucket(mesh_bucket).await;
                match cas.put_verified_blob(mesh_bucket, "blobs/", bytes::Bytes::copy_from_slice(payload)).await {
                    Ok(stored_cid) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(serde_json::json!({
                            "status": "verified",
                            "cid": format!("blake3:{}", stored_cid)
                        })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => {
                res.status_code(StatusCode::METHOD_NOT_ALLOWED);
            }
        }
    }
}

#[derive(Clone)]
struct HardwareListHandler;

#[async_trait]
impl Handler for HardwareListHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::hardware::{HardwareClass, HardwareRegistry};
        use crate::iam::capabilities::{Capability, CapabilitySet};

        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller_caps = CapabilitySet::from_auth_context(auth.as_ref());
        if !caller_caps.has(Capability::HwInfo) {
            crate::observability::global_metrics().inc_iam_auth_denial();
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({ "error": "Missing required capability hw.info" })));
            return;
        }
        let class_filter = req
            .query::<String>("class")
            .and_then(|c| HardwareClass::from_str_filter(&c));
        let devices = HardwareRegistry::global().list_devices(class_filter);
        res.status_code(StatusCode::OK);
        res.render(Json(serde_json::json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "devices": devices,
        })));
    }
}

#[derive(Clone)]
struct HardwareCallHandler;

#[async_trait]
impl Handler for HardwareCallHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::hardware::{required_capability_for_op, HardwareRegistry, HardwareStatus};
        use crate::iam::capabilities::CapabilitySet;

        #[derive(serde::Deserialize)]
        struct HwCallBody {
            op: String,
            #[serde(default)]
            payload: serde_json::Value,
        }

        let body: HwCallBody = match req.parse_json().await {
            Ok(b) => b,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": format!("Invalid hardware call JSON: {}", e) })));
                return;
            }
        };

        let req_cap = required_capability_for_op(&body.op);
        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller_caps = CapabilitySet::from_auth_context(auth.as_ref());
        if !caller_caps.has(req_cap) {
            crate::observability::global_metrics().inc_iam_auth_denial();
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({
                "error": format!("Missing required capability {:?} for '{}'", req_cap, body.op)
            })));
            return;
        }

        let resp = HardwareRegistry::global().dispatch(&body.op, &body.payload);
        let code = match resp.status {
            HardwareStatus::Ok => StatusCode::OK,
            HardwareStatus::PermissionDenied | HardwareStatus::ConsentRequired => StatusCode::FORBIDDEN,
            HardwareStatus::InvalidRequest => StatusCode::BAD_REQUEST,
            HardwareStatus::DeviceNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::NOT_IMPLEMENTED,
        };
        res.status_code(code);
        res.render(Json(resp));
    }
}

#[derive(Clone)]
struct OciV2PingHandler;

#[async_trait]
impl Handler for OciV2PingHandler {
    async fn handle(&self, _req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        res.status_code(StatusCode::OK);
        res.headers_mut().insert(
            "docker-distribution-api-version",
            salvo::http::HeaderValue::from_static("registry/2.0"),
        );
        res.render(Json(serde_json::json!({ "registry": "nexus-io", "version": "2.0" })));
    }
}

#[derive(Clone)]
struct RegistryBlobHandler {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
}

#[async_trait]
impl Handler for RegistryBlobHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        use crate::iam::capabilities::{Capability, CapabilitySet};
        use crate::registry::{ArtifactProvenance, NexusRegistry};

        let ns = req.param::<String>("ns").unwrap_or_default();
        let repo = req.param::<String>("repo").unwrap_or_default();
        let digest = req.param::<String>("digest").unwrap_or_default();
        let auth = crate::ux::iam::depot_auth_context(depot);
        let caps = CapabilitySet::from_auth_context(auth.as_ref());
        let reg = NexusRegistry::new(self.db.clone(), self.garage.clone());

        match *req.method() {
            salvo::http::Method::GET => {
                if !caps.has(Capability::BlobRead) {
                    res.status_code(StatusCode::FORBIDDEN);
                    return;
                }
                match reg.get_blob(&digest).await {
                    Ok(bytes) => {
                        res.status_code(StatusCode::OK);
                        res.headers_mut().insert(
                            salvo::http::header::CONTENT_TYPE,
                            salvo::http::HeaderValue::from_static("application/octet-stream"),
                        );
                        let _ = res.write_body(bytes);
                    }
                    Err(e) => {
                        res.status_code(StatusCode::NOT_FOUND);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::PUT => {
                if !caps.has(Capability::RuntimeInstall) {
                    crate::observability::global_metrics().inc_iam_auth_denial();
                    res.status_code(StatusCode::FORBIDDEN);
                    return;
                }
                let Ok(payload) = req.payload_with_max_size(64 * 1024 * 1024).await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                match reg
                    .publish_release(
                        &ns,
                        &repo,
                        &digest,
                        bytes::Bytes::copy_from_slice(payload),
                        Some(&digest),
                        "application/wasm",
                        None,
                        ArtifactProvenance::default(),
                    )
                    .await
                {
                    Ok(rel) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(rel));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => {
                res.status_code(StatusCode::METHOD_NOT_ALLOWED);
            }
        }
    }
}

#[derive(Clone)]
struct RegistryManifestHandler {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
}

#[async_trait]
impl Handler for RegistryManifestHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        use crate::iam::capabilities::{Capability, CapabilitySet};
        use crate::registry::{ArtifactProvenance, NexusRegistry};

        let ns = req.param::<String>("ns").unwrap_or_default();
        let repo = req.param::<String>("repo").unwrap_or_default();
        let reference = req.param::<String>("reference").unwrap_or_default();
        let auth = crate::ux::iam::depot_auth_context(depot);
        let caps = CapabilitySet::from_auth_context(auth.as_ref());
        let reg = NexusRegistry::new(self.db.clone(), self.garage.clone());

        match *req.method() {
            salvo::http::Method::GET => {
                match reg.get_release(&ns, &repo, &reference).await {
                    Ok(Some(rel)) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(rel));
                    }
                    Ok(None) => {
                        res.status_code(StatusCode::NOT_FOUND);
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::PUT => {
                if !caps.has(Capability::RuntimeInstall) {
                    crate::observability::global_metrics().inc_iam_auth_denial();
                    res.status_code(StatusCode::FORBIDDEN);
                    return;
                }
                let expected = req
                    .headers()
                    .get("x-nexus-blake3")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let Ok(payload) = req.payload_with_max_size(64 * 1024 * 1024).await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                match reg
                    .publish_release(
                        &ns,
                        &repo,
                        &reference,
                        bytes::Bytes::copy_from_slice(payload),
                        expected.as_deref(),
                        "application/wasm",
                        None,
                        ArtifactProvenance {
                            publisher: auth.and_then(|a| a.actor).unwrap_or_else(|| "authenticated".into()),
                            ..ArtifactProvenance::default()
                        },
                    )
                    .await
                {
                    Ok(rel) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(rel));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => {
                res.status_code(StatusCode::METHOD_NOT_ALLOWED);
            }
        }
    }
}

#[derive(Clone)]
struct RegistryPackagesHandler {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
}

#[async_trait]
impl Handler for RegistryPackagesHandler {
    async fn handle(&self, _req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let reg = crate::registry::NexusRegistry::new(self.db.clone(), self.garage.clone());
        match reg.list_releases().await {
            Ok(releases) => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({ "count": releases.len(), "releases": releases })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct RegistryInstallHandler {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
}

#[async_trait]
impl Handler for RegistryInstallHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        use crate::iam::capabilities::{Capability, CapabilitySet};

        let auth = crate::ux::iam::depot_auth_context(depot);
        let caps = CapabilitySet::from_auth_context(auth.as_ref());
        if !caps.has(Capability::RuntimeInstall) {
            crate::observability::global_metrics().inc_iam_auth_denial();
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({ "error": "Missing required capability runtime.install" })));
            return;
        }

        #[derive(serde::Deserialize)]
        struct InstallBody {
            reference: String,
            #[serde(default)]
            expected_blake3: Option<String>,
        }

        let body: InstallBody = match req.parse_json().await {
            Ok(b) => b,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": format!("Invalid install JSON: {}", e) })));
                return;
            }
        };

        let reg = crate::registry::NexusRegistry::new(self.db.clone(), self.garage.clone());
        match reg
            .install_package(&body.reference, body.expected_blake3.as_deref())
            .await
        {
            Ok(lock) => {
                res.status_code(StatusCode::OK);
                res.render(Json(lock));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

/// Explicitly resolve a configured asset directory — supports both single-dir and 9-domain layouts.
#[cfg(feature = "serve-web")]
fn resolve_explicit_asset_root(explicit: Option<&std::path::PathBuf>) -> Option<std::path::PathBuf> {
    let p = explicit?;
    if p.is_dir() {
        return Some(p.clone());
    }
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) {
        if name == "dist" {
            let ux_dist = parent.join("ux").join("dist");
            if ux_dist.is_dir() {
                return Some(ux_dist);
            }
        } else if name == "site" {
            let shell_dir = parent.join("shell");
            if shell_dir.is_dir() {
                return Some(shell_dir);
            }
        }
    }
    None
}

/// Resolve a relative web asset path across the configured `root` and (when `root` is `site` or `shell`
/// inside the 9-domain monorepo) across the sibling domain folders (`shell/`, `platform/`, `site/`,
/// `apps/`, `labs/`, `docs/`). Every path segment is strictly validated via `safe_join_within`.
#[cfg(feature = "serve-web")]
fn resolve_domain_web_file(
    root: &std::path::Path,
    rel: &str,
) -> Result<Option<std::path::PathBuf>, StatusCode> {
    let primary = safe_join_within(root, rel)?;
    if primary.is_file() {
        return Ok(Some(primary));
    }

    let Some(repo_root) = root.parent() else {
        return Ok(None);
    };
    let root_name = root.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !matches!(root_name, "site" | "shell" | "platform") {
        return Ok(None);
    }

    // 1. Check domain roots directly (shell, site, platform, labs)
    for domain in ["shell", "site", "platform", "labs"] {
        let d_root = repo_root.join(domain);
        if d_root.is_dir() {
            let cand = safe_join_within(&d_root, rel)?;
            if cand.is_file() {
                return Ok(Some(cand));
            }
        }
    }

    // 2. Check domain-mapped `_pages/*` prefixes
    let trimmed = rel.trim_start_matches('/');
    if let Some(sub) = trimmed.strip_prefix("_pages/apps/") {
        for domain in ["apps", "platform"] {
            let d_root = repo_root.join(domain);
            if d_root.is_dir() {
                let cand = safe_join_within(&d_root, sub)?;
                if cand.is_file() {
                    return Ok(Some(cand));
                }
            }
        }
    } else if let Some(sub) = trimmed.strip_prefix("_pages/labs/") {
        let d_root = repo_root.join("labs");
        if d_root.is_dir() {
            let cand = safe_join_within(&d_root, sub)?;
            if cand.is_file() {
                return Ok(Some(cand));
            }
        }
    } else if let Some(sub) = trimmed.strip_prefix("_pages/docs/") {
        let d_root = repo_root.join("docs");
        if d_root.is_dir() {
            let cand = safe_join_within(&d_root, sub)?;
            if cand.is_file() {
                return Ok(Some(cand));
            }
        }
    } else if let Some(sub) = trimmed.strip_prefix("_pages/") {
        for domain_pages in ["site/_pages", "shell/_pages"] {
            let d_root = repo_root.join(domain_pages);
            if d_root.is_dir() {
                let cand = safe_join_within(&d_root, sub)?;
                if cand.is_file() {
                    return Ok(Some(cand));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(feature = "serve-web")]
fn safe_join_within(
    root: &std::path::Path,
    rel_path: &str,
) -> Result<std::path::PathBuf, StatusCode> {
    let trimmed = rel_path.trim_start_matches('/');
    if trimmed.contains('\0') || trimmed.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut joined = root.to_path_buf();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains(':') {
            return Err(StatusCode::BAD_REQUEST);
        }
        joined.push(seg);
    }
    Ok(joined)
}

#[cfg(feature = "serve-web")]
fn mime_for_path(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") | Some("cjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") | Some("map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("md") | Some("markdown") => "text/markdown; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}

#[cfg(feature = "serve-web")]
fn is_reserved_non_spa_prefix(rel_path: &str) -> bool {
    let normalized = format!("/{}", rel_path.trim_start_matches('/'));
    const RESERVED: &[&str] = &[
        "/api/",
        "/dist/",
        "/rpc",
        "/sql",
        "/cells/",
        "/s3/",
        "/_nexus/",
        "/key/",
        "/graphql",
        "/v2/",
        "/proxy/",
        "/signin",
        "/signup",
        "/signout",
        "/export",
        "/import",
        "/query",
        "/health",
        "/ready",
        "/status",
        "/version",
    ];
    RESERVED.iter().any(|prefix| {
        normalized == *prefix || normalized.starts_with(prefix)
    })
}

#[cfg(feature = "serve-web")]
fn accepts_html(req: &Request) -> bool {
    match req
        .headers()
        .get(salvo::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    {
        Some(accept) => accept.contains("text/html") || accept.contains("*/*"),
        None => true,
    }
}

#[cfg(feature = "serve-web")]
fn apply_isolation_headers(
    res: &mut Response,
    coop: Option<&str>,
    coep: Option<&str>,
) {
    if let Some(val) = coop {
        if let Ok(hv) = salvo::http::header::HeaderValue::from_str(val) {
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("cross-origin-opener-policy"),
                hv,
            );
        }
    }
    if let Some(val) = coep {
        if let Ok(hv) = salvo::http::header::HeaderValue::from_str(val) {
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("cross-origin-embedder-policy"),
                hv,
            );
        }
    }
}

#[cfg(feature = "serve-web")]
#[derive(Clone)]
struct DistStaticHandler {
    dist_root: Option<std::path::PathBuf>,
    coep_header: Option<String>,
}

#[cfg(feature = "serve-web")]
impl DistStaticHandler {
    fn from_config(config: &GatewayConfig) -> Self {
        Self {
            dist_root: resolve_explicit_asset_root(config.dist_root.as_ref()),
            coep_header: config.coep_header.clone(),
        }
    }
}

#[cfg(feature = "serve-web")]
#[async_trait]
impl Handler for DistStaticHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let Some(root) = &self.dist_root else {
            res.status_code(StatusCode::NOT_FOUND);
            return;
        };
        let rel = req.param::<String>("path").unwrap_or_default();
        let target = match safe_join_within(root, &rel) {
            Ok(p) => p,
            Err(code) => {
                res.status_code(code);
                return;
            }
        };
        if !target.is_file() {
            res.status_code(StatusCode::NOT_FOUND);
            return;
        }
        match tokio::fs::read(&target).await {
            Ok(bytes) => {
                let ct = mime_for_path(&target);
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_TYPE,
                    salvo::http::HeaderValue::from_static(ct),
                );
                res.headers_mut().insert(
                    salvo::http::header::CACHE_CONTROL,
                    salvo::http::HeaderValue::from_static("public, max-age=300"),
                );
                res.headers_mut().insert(
                    salvo::http::header::HeaderName::from_static("cross-origin-resource-policy"),
                    salvo::http::HeaderValue::from_static("same-origin"),
                );
                // Chromium requires dedicated Web Worker scripts (e.g. logic.worker.js) to carry
                // matching COEP when the parent document is cross-origin isolated.
                if ct.starts_with("application/javascript") {
                    apply_isolation_headers(res, None, self.coep_header.as_deref());
                }
                res.body(bytes);
            }
            Err(_) => {
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
    }
}

#[cfg(feature = "serve-web")]
#[derive(Clone)]
struct WebStaticHandler {
    web_root: Option<std::path::PathBuf>,
    spa_fallback: bool,
    coop_header: Option<String>,
    coep_header: Option<String>,
}

#[cfg(feature = "serve-web")]
impl WebStaticHandler {
    fn from_config(config: &GatewayConfig) -> Self {
        Self {
            web_root: resolve_explicit_asset_root(config.web_root.as_ref()),
            spa_fallback: config.spa_fallback,
            coop_header: config.coop_header.clone(),
            coep_header: config.coep_header.clone(),
        }
    }
}

#[cfg(feature = "serve-web")]
#[async_trait]
impl Handler for WebStaticHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let rel = req
            .param::<String>("path")
            .unwrap_or_else(|| req.uri().path().trim_start_matches('/').to_string());

        let Some(root) = &self.web_root else {
            if rel.is_empty() && accepts_html(req) {
                render_bundle_unavailable(res);
            } else {
                res.status_code(StatusCode::NOT_FOUND);
            }
            return;
        };

        // Validate path safety first
        if let Err(code) = safe_join_within(root, &rel) {
            res.status_code(code);
            return;
        }

        // 1. Direct file match across configured root + 9-domain overlay
        let exact_target = if rel.is_empty() {
            match resolve_domain_web_file(root, "index.html") {
                Ok(found) => found,
                Err(code) => {
                    res.status_code(code);
                    return;
                }
            }
        } else {
            match resolve_domain_web_file(root, &rel) {
                Ok(found) => found,
                Err(code) => {
                    res.status_code(code);
                    return;
                }
            }
        };

        let (target, is_spa_fallback) = if let Some(file) = exact_target {
            (file, false)
        } else {
            // 2. Strict SPA fallback: ONLY for HTML navigation requests with no file extension
            //    and outside reserved API / RPC / dist / asset prefixes.
            let has_ext = std::path::Path::new(&rel).extension().is_some();
            if self.spa_fallback && !has_ext && !is_reserved_non_spa_prefix(&rel) && accepts_html(req) {
                if let Ok(Some(idx)) = resolve_domain_web_file(root, "index.html") {
                    (idx, true)
                } else {
                    if rel.is_empty() {
                        render_bundle_unavailable(res);
                    } else {
                        res.status_code(StatusCode::NOT_FOUND);
                    }
                    return;
                }
            } else {
                res.status_code(StatusCode::NOT_FOUND);
                return;
            }
        };

        match tokio::fs::read(&target).await {
            Ok(bytes) => {
                let ct = mime_for_path(&target);
                let is_html = ct.starts_with("text/html");
                let etag_val = format!("\"{}\"", blake3::hash(&bytes).to_hex());
                if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&etag_val) {
                    res.headers_mut().insert(salvo::http::header::ETAG, hv);
                }
                res.headers_mut().insert(
                    salvo::http::header::CACHE_CONTROL,
                    salvo::http::header::HeaderValue::from_static(if is_html || is_spa_fallback {
                        "no-cache"
                    } else {
                        "public, max-age=300"
                    }),
                );
                if req
                    .headers()
                    .get(salvo::http::header::IF_NONE_MATCH)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.trim() == etag_val)
                    .unwrap_or(false)
                {
                    res.status_code(StatusCode::NOT_MODIFIED);
                    return;
                }
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_TYPE,
                    salvo::http::HeaderValue::from_static(ct),
                );
                if is_html {
                    apply_isolation_headers(
                        res,
                        self.coop_header.as_deref(),
                        self.coep_header.as_deref(),
                    );
                }
                res.body(bytes);
            }
            Err(_) => {
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
    }
}

fn render_bundle_unavailable(res: &mut Response) {
    res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    res.render(Text::Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nexus-IO Gateway — Application Bundle Unavailable</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 720px; margin: 60px auto; padding: 0 20px; line-height: 1.6; color: #1f2937; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #fef3c7; color: #92400e; font-weight: 600; font-size: 0.85em; }
  </style>
</head>
<body>
  <h1>Nexus-IO Gateway</h1>
  <p><span class="badge">Application Bundle Unavailable</span></p>
  <p>The Nexus-IO kernel gateway is online, but no frontend application bundle (<code>index.html</code>) was found at the configured web root.</p>
  <p>Configure <code>NEXUS_WEB_ROOT</code> (and optionally <code>NEXUS_DIST_ROOT</code>) to serve a Nexus-UX application, or query <code>/health</code>, <code>/ready</code>, <code>/rpc</code>, <code>/cells/*</code>, and <code>/s3/*</code> directly.</p>
</body>
</html>"#,
    ));
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

#[cfg(not(feature = "serve-web"))]
#[handler]
async fn serve_static(res: &mut Response) {
    render_bundle_unavailable(res);
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
