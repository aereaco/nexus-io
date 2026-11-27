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
                )
                // --- Nexus-IDP: Universal Identity-First, Hierarchical Org, OIDC/OAuth 2.1, Outpost ---
                .push(Router::with_path("/.well-known/openid-configuration").get(OidcDiscoveryHandler))
                .push(Router::with_path("/.well-known/jwks.json").get(OidcJwksHandler { db: self.db.clone() }))
                .push(
                    Router::with_path("/oauth/v2/authorize")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(OAuthAuthorizeHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/oauth/v2/token")
                        .hoop(gate.clone())
                        .post(OAuthTokenHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/oauth/v2/revoke")
                        .hoop(gate.clone())
                        .post(OAuthRevokeHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/oauth/v2/introspect")
                        .hoop(gate.clone())
                        .post(OAuthIntrospectHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/oidc/v1/userinfo")
                        .hoop(gate.clone())
                        .get(OidcUserInfoHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/outpost/auth")
                        .hoop(gate.clone())
                        .get(ForwardAuthOutpostHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/identities")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamIdentitiesHandler { db: self.db.clone() })
                        .post(IamIdentitiesHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/identities/import")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamIdentityImportHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/orgs")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamOrgsHandler { db: self.db.clone() })
                        .post(IamOrgsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/orgs/{org_id}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamOrgDetailHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/orgs/{org_id}/members")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamOrgMembersHandler { db: self.db.clone() })
                        .post(IamOrgMembersHandler { db: self.db.clone() })
                        .delete(IamOrgMembersHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/orgs/{org_id}/policy")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamOrgPolicyHandler { db: self.db.clone() })
                        .put(IamOrgPolicyHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/evaluate")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamEvaluateHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/flows")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamFlowsHandler { db: self.db.clone() })
                        .post(IamFlowsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/flows/{flow_id}/start")
                        .hoop(gate.clone())
                        .post(IamFlowStartHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/flows/executions/{exec_id}/submit")
                        .hoop(gate.clone())
                        .post(IamFlowSubmitHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/identities/{identity_id}/password")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamIdentityPasswordHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/webauthn/register/begin")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamWebAuthnRegisterHandler { db: self.db.clone(), is_finish: false }),
                )
                .push(
                    Router::with_path("/_nexus/iam/webauthn/register/finish")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamWebAuthnRegisterHandler { db: self.db.clone(), is_finish: true }),
                )
                .push(
                    Router::with_path("/_nexus/iam/webauthn/auth/begin")
                        .hoop(gate.clone())
                        .post(IamWebAuthnAuthHandler { db: self.db.clone(), is_finish: false }),
                )
                .push(
                    Router::with_path("/_nexus/iam/webauthn/auth/finish")
                        .hoop(gate.clone())
                        .post(IamWebAuthnAuthHandler { db: self.db.clone(), is_finish: true }),
                )
                .push(
                    Router::with_path("/_nexus/iam/webauthn/credentials")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamWebAuthnCredsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/webauthn/credentials/{cred_id}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .delete(IamWebAuthnCredsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/federation/providers")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamFedProvidersHandler { db: self.db.clone() })
                        .post(IamFedProvidersHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/federation/links")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamFedLinksHandler { db: self.db.clone() })
                        .post(IamFedLinksHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/federation/discover")
                        .hoop(gate.clone())
                        .post(IamFedDiscoverHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/saml/metadata")
                        .get(IamSamlMetadataHandler),
                )
                .push(
                    Router::with_path("/_nexus/iam/sessions")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamSessionsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/sessions/{session_id}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .delete(IamSessionsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/devices")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .get(IamDevicesHandler { db: self.db.clone() })
                        .post(IamDevicesHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/devices/{device_id}")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .delete(IamDevicesHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/trust/clusters")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .get(IamClusterTrustHandler { db: self.db.clone() })
                        .post(IamClusterTrustHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/clients")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .get(IamClientsHandler { db: self.db.clone() })
                        .post(IamClientsHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/audit")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                        .get(IamAuditHandler { db: self.db.clone() }),
                )
                .push(
                    Router::with_path("/_nexus/iam/mfa/totp/enroll")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamTotpHandler { db: self.db.clone(), is_verify: false }),
                )
                .push(
                    Router::with_path("/_nexus/iam/mfa/totp/verify")
                        .hoop(gate.clone())
                        .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                        .post(IamTotpHandler { db: self.db.clone(), is_verify: true }),
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

// =============================================================================
// Nexus-IDP Gateway Handlers (OIDC, OAuth 2.1 PKCE, TOTP MFA, Orgs, Audit, Outpost)
// =============================================================================

#[derive(Clone)]
struct OidcDiscoveryHandler;

#[async_trait]
impl Handler for OidcDiscoveryHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("127.0.0.1:8443");
        let scheme = if req.headers().get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https") {
            "https"
        } else {
            "http"
        };
        let issuer = format!("{}://{}", scheme, host);
        res.status_code(StatusCode::OK);
        res.render(Json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/oauth/v2/authorize", issuer),
            "token_endpoint": format!("{}/oauth/v2/token", issuer),
            "userinfo_endpoint": format!("{}/oidc/v1/userinfo", issuer),
            "revocation_endpoint": format!("{}/oauth/v2/revoke", issuer),
            "introspection_endpoint": format!("{}/oauth/v2/introspect", issuer),
            "jwks_uri": format!("{}/.well-known/jwks.json", issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
        })));
    }
}

#[derive(Clone)]
struct OidcJwksHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for OidcJwksHandler {
    async fn handle(&self, _req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp.jwks().await {
            Ok(jwks) => {
                res.status_code(StatusCode::OK);
                res.render(Json(jwks));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct OAuthAuthorizeHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for OAuthAuthorizeHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        #[derive(serde::Deserialize)]
        struct AuthzReq {
            client_id: String,
            redirect_uri: String,
            #[serde(default = "default_oidc_scope")]
            scope: String,
            code_challenge: String,
            #[serde(default = "default_s256")]
            code_challenge_method: String,
            #[serde(default)]
            nonce: Option<String>,
            #[serde(default)]
            state: Option<String>,
        }
        fn default_oidc_scope() -> String { "openid profile".into() }
        fn default_s256() -> String { "S256".into() }

        let Ok(body) = req.parse_json::<AuthzReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "invalid_request" })));
            return;
        };
        let auth = crate::ux::iam::depot_auth_context(depot);
        let subject = auth
            .as_ref()
            .and_then(|a| a.actor.clone())
            .unwrap_or_else(|| "anonymous".into());
        let roles: Vec<String> = auth
            .as_ref()
            .map(|a| a.roles.iter().map(|r| format!("{:?}", r)).collect())
            .unwrap_or_default();

        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp
            .issue_authorization_code(
                &body.client_id,
                &body.redirect_uri,
                &body.scope,
                &body.code_challenge,
                &body.code_challenge_method,
                body.nonce,
                &subject,
                roles,
            )
            .await
        {
            Ok(code) => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({
                    "code": code,
                    "state": body.state,
                    "redirect_uri": body.redirect_uri,
                })));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": "invalid_request", "error_description": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct OAuthTokenHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for OAuthTokenHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        #[derive(serde::Deserialize)]
        struct TokenReq {
            grant_type: String,
            client_id: String,
            #[serde(default)]
            client_secret: Option<String>,
            #[serde(default)]
            code: Option<String>,
            #[serde(default)]
            redirect_uri: Option<String>,
            #[serde(default)]
            code_verifier: Option<String>,
            #[serde(default)]
            refresh_token: Option<String>,
            #[serde(default)]
            scope: Option<String>,
        }
        let Ok(body) = req.parse_json::<TokenReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "invalid_request" })));
            return;
        };
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp
            .exchange_token(
                &body.grant_type,
                &body.client_id,
                body.client_secret.as_deref(),
                body.code.as_deref(),
                body.redirect_uri.as_deref(),
                body.code_verifier.as_deref(),
                body.refresh_token.as_deref(),
                body.scope.as_deref(),
            )
            .await
        {
            Ok(tok) => {
                res.status_code(StatusCode::OK);
                res.render(Json(tok));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": "invalid_grant", "error_description": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct OAuthRevokeHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for OAuthRevokeHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        #[derive(serde::Deserialize)]
        struct RevokeReq { token: String }
        let Ok(body) = req.parse_json::<RevokeReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            return;
        };
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        let revoked = idp.revoke_token(&body.token).await.unwrap_or(false);
        res.status_code(StatusCode::OK);
        res.render(Json(serde_json::json!({ "revoked": revoked })));
    }
}

#[derive(Clone)]
struct OAuthIntrospectHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for OAuthIntrospectHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        #[derive(serde::Deserialize)]
        struct IntroReq { token: String }
        let Ok(body) = req.parse_json::<IntroReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            return;
        };
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp.introspect_token(&body.token).await {
            Ok(Some(rec)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({
                    "active": true,
                    "sub": rec.subject,
                    "org_id": rec.org_id,
                    "client_id": rec.client_id,
                    "scope": rec.scope,
                    "roles": rec.roles,
                    "exp": rec.expires_at_ms / 1000,
                })));
            }
            _ => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({ "active": false })));
            }
        }
    }
}

#[derive(Clone)]
struct OidcUserInfoHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for OidcUserInfoHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let Some(token) = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        else {
            res.status_code(StatusCode::UNAUTHORIZED);
            return;
        };
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp.introspect_token(token.trim()).await {
            Ok(Some(rec)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({
                    "sub": rec.subject,
                    "org_id": rec.org_id,
                    "roles": rec.roles,
                    "scope": rec.scope,
                })));
            }
            _ => {
                res.status_code(StatusCode::UNAUTHORIZED);
            }
        }
    }
}

/// Authentik-style Forward-Auth Proxy Outpost (`GET /_nexus/outpost/auth`).
/// Validates either an OAuth 2.1 Bearer access token or standard Nexus-DB IAM session,
/// returning `200 OK` with `X-Nexus-User`, `X-Nexus-Org`, and `X-Nexus-Roles` headers (or `401`).
#[derive(Clone)]
struct ForwardAuthOutpostHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for ForwardAuthOutpostHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        if let Some(bearer) = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        {
            let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
            if let Ok(Some(rec)) = idp.introspect_token(bearer.trim()).await {
                res.status_code(StatusCode::OK);
                if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&rec.subject) {
                    res.headers_mut().insert("x-nexus-user", hv);
                }
                if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&rec.org_id) {
                    res.headers_mut().insert("x-nexus-org", hv);
                }
                if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&rec.roles.join(",")) {
                    res.headers_mut().insert("x-nexus-roles", hv);
                }
                res.render(Json(serde_json::json!({
                    "authenticated": true,
                    "sub": rec.subject,
                    "org_id": rec.org_id,
                    "roles": rec.roles,
                })));
                return;
            }
        }

        let (ns, db_name) = crate::ux::surreal_http::extract_ns_db(req);
        if let Ok(Some(ctx)) = crate::ux::surreal_http::resolve_http_auth(req, &self.db, &ns, &db_name) {
            let user = ctx.actor.unwrap_or_else(|| "authenticated".into());
            let roles_str = ctx.roles.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>().join(",");
            res.status_code(StatusCode::OK);
            if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&user) {
                res.headers_mut().insert("x-nexus-user", hv);
            }
            res.headers_mut().insert("x-nexus-org", salvo::http::header::HeaderValue::from_static("default"));
            if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&roles_str) {
                res.headers_mut().insert("x-nexus-roles", hv);
            }
            res.render(Json(serde_json::json!({ "authenticated": true, "sub": user, "org_id": "default" })));
            return;
        }

        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(serde_json::json!({ "authenticated": false })));
    }
}

#[derive(Clone)]
struct IamIdentitiesHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamIdentitiesHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => match idp.list_identities().await {
                Ok(identities) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({ "identities": identities })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            },
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct CreateIdentReq {
                    display_name: String,
                    #[serde(default)]
                    primary_email: Option<String>,
                }
                let Ok(body) = req.parse_json::<CreateIdentReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                match idp.create_identity(&body.display_name, body.primary_email).await {
                    Ok((identity, root_secret)) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(serde_json::json!({
                            "identity": identity,
                            "root_secret": root_secret,
                        })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamIdentityImportHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamIdentityImportHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let Ok(pkg) = req.parse_json::<crate::iam::idp::PortableIdentityPackage>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            return;
        };
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp.import_portable_identity(&pkg).await {
            Ok(identity) => {
                res.status_code(StatusCode::CREATED);
                res.render(Json(identity));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamOrgsHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamOrgsHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth
            .as_ref()
            .and_then(|a| a.actor.clone())
            .unwrap_or_else(|| "anonymous".into());
        let is_platform_admin = auth
            .as_ref()
            .map(|a| a.roles.contains(&nexus_db::auth::Role::Owner))
            .unwrap_or(false);

        match *req.method() {
            salvo::http::Method::GET => {
                match idp.list_authorized_orgs(&actor, is_platform_admin).await {
                    Ok(orgs) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "orgs": orgs })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct CreateOrgReq {
                    slug: String,
                    name: String,
                    #[serde(default)]
                    parent_org_id: Option<String>,
                    #[serde(default)]
                    primary_domain: Option<String>,
                    #[serde(default)]
                    local_policy: crate::iam::idp::OrgPolicyPatch,
                }
                let Ok(body) = req.parse_json::<CreateOrgReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                if let Some(ref parent_id) = body.parent_org_id {
                    let dec = idp
                        .evaluate_permission(&actor, is_platform_admin, parent_id, "iam.org.create_child")
                        .await;
                    if !matches!(dec, Ok(d) if d.allowed) {
                        res.status_code(StatusCode::FORBIDDEN);
                        res.render(Json(serde_json::json!({ "error": "Insufficient permission to create child organization" })));
                        return;
                    }
                } else if !is_platform_admin {
                    res.status_code(StatusCode::FORBIDDEN);
                    res.render(Json(serde_json::json!({ "error": "Platform Administrator authority required to create root organization" })));
                    return;
                }
                match idp
                    .create_org(
                        &actor,
                        &body.slug,
                        &body.name,
                        body.parent_org_id,
                        body.primary_domain,
                        body.local_policy,
                    )
                    .await
                {
                    Ok(org) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(org));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamOrgDetailHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamOrgDetailHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let org_id = req.param::<String>("org_id").unwrap_or_default();
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let is_platform_admin = auth
            .as_ref()
            .map(|a| a.roles.contains(&nexus_db::auth::Role::Owner))
            .unwrap_or(false);
        let dec = idp.evaluate_permission(&actor, is_platform_admin, &org_id, "iam.org.read").await;
        if !matches!(dec, Ok(d) if d.allowed) {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({ "error": "Forbidden" })));
            return;
        }
        match idp.get_org(&org_id).await {
            Ok(Some(org)) => {
                let policy = idp.resolve_org_policy(&org_id).await.ok();
                let members = idp.list_memberships_for_org(&org_id).await.unwrap_or_default();
                let all_auth = idp.list_authorized_orgs(&actor, is_platform_admin).await.unwrap_or_default();
                let children: Vec<_> = all_auth
                    .into_iter()
                    .filter(|o| o.parent_org_id.as_deref() == Some(&org_id))
                    .collect();
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({
                    "organization": org,
                    "composed_policy": policy,
                    "children": children,
                    "members": members,
                })));
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
}

#[derive(Clone)]
struct IamOrgMembersHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamOrgMembersHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let org_id = req.param::<String>("org_id").unwrap_or_default();
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let is_platform_admin = auth
            .as_ref()
            .map(|a| a.roles.contains(&nexus_db::auth::Role::Owner))
            .unwrap_or(false);
        let needed = if *req.method() == salvo::http::Method::GET {
            "iam.users.read"
        } else {
            "iam.users.manage"
        };
        if !matches!(idp.evaluate_permission(&actor, is_platform_admin, &org_id, needed).await, Ok(d) if d.allowed) {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({ "error": "Forbidden" })));
            return;
        }
        match *req.method() {
            salvo::http::Method::GET => match idp.list_memberships_for_org(&org_id).await {
                Ok(members) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({ "members": members })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            },
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct GrantMemberReq {
                    subject_id: String,
                    #[serde(default)]
                    role_assignments: Vec<String>,
                    #[serde(default)]
                    direct_permissions: Vec<String>,
                    #[serde(default)]
                    scope: crate::iam::idp::DelegationScope,
                    #[serde(default)]
                    expires_at_ms: Option<u64>,
                }
                let Ok(body) = req.parse_json::<GrantMemberReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                match idp
                    .grant_membership(
                        &actor,
                        &org_id,
                        &body.subject_id,
                        body.role_assignments,
                        body.direct_permissions,
                        body.scope,
                        body.expires_at_ms,
                    )
                    .await
                {
                    Ok(mem) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(mem));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::DELETE => {
                let subject_id = req.query::<String>("subject_id").unwrap_or_default();
                if subject_id.is_empty() {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                }
                match idp.revoke_membership(&actor, &org_id, &subject_id).await {
                    Ok(revoked) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "revoked": revoked })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamOrgPolicyHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamOrgPolicyHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let org_id = req.param::<String>("org_id").unwrap_or_default();
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let is_platform_admin = auth
            .as_ref()
            .map(|a| a.roles.contains(&nexus_db::auth::Role::Owner))
            .unwrap_or(false);
        let needed = if *req.method() == salvo::http::Method::GET {
            "iam.policy.read"
        } else {
            "iam.policy.update"
        };
        if !matches!(idp.evaluate_permission(&actor, is_platform_admin, &org_id, needed).await, Ok(d) if d.allowed) {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({ "error": "Forbidden" })));
            return;
        }
        match *req.method() {
            salvo::http::Method::GET => match idp.resolve_org_policy(&org_id).await {
                Ok(pol) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(pol));
                }
                Err(e) => {
                    res.status_code(StatusCode::NOT_FOUND);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            },
            salvo::http::Method::PUT => {
                let Ok(patch) = req.parse_json::<crate::iam::idp::OrgPolicyPatch>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                match idp.update_org_policy(&actor, &org_id, patch).await {
                    Ok(_) => match idp.resolve_org_policy(&org_id).await {
                        Ok(pol) => {
                            res.status_code(StatusCode::OK);
                            res.render(Json(pol));
                        }
                        Err(e) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            res.render(Json(serde_json::json!({ "error": e.to_string() })));
                        }
                    },
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamEvaluateHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamEvaluateHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        #[derive(serde::Deserialize)]
        struct EvalReq {
            #[serde(default)]
            subject_id: Option<String>,
            org_id: String,
            action: String,
        }
        let Ok(body) = req.parse_json::<EvalReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            return;
        };
        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let is_platform_admin = auth
            .as_ref()
            .map(|a| a.roles.contains(&nexus_db::auth::Role::Owner))
            .unwrap_or(false);
        let subject = if is_platform_admin {
            body.subject_id.unwrap_or(caller)
        } else {
            caller
        };
        let eval_platform_admin = is_platform_admin && subject == auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match idp
            .evaluate_permission(&subject, eval_platform_admin, &body.org_id, &body.action)
            .await
        {
            Ok(dec) => {
                res.status_code(StatusCode::OK);
                res.render(Json(dec));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamFlowsHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamFlowsHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let engine = crate::iam::flows::AuthFlowEngine::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => match engine.list_flows().await {
                Ok(flows) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({ "flows": flows })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            },
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct CreateFlowReq {
                    flow_id: String,
                    name: String,
                    #[serde(default)]
                    org_id: Option<String>,
                    stages: Vec<crate::iam::flows::AuthStage>,
                    #[serde(default = "default_flow_timeout")]
                    timeout_secs: u64,
                    #[serde(default = "default_flow_retries")]
                    max_retries: u32,
                }
                fn default_flow_timeout() -> u64 { 300 }
                fn default_flow_retries() -> u32 { 5 }
                let Ok(body) = req.parse_json::<CreateFlowReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                let auth = crate::ux::iam::depot_auth_context(depot);
                let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_else(|| "owner".into());
                let is_admin = auth.as_ref().map(|a| a.roles.contains(&nexus_db::auth::Role::Owner)).unwrap_or(false);
                if !is_admin {
                    res.status_code(StatusCode::FORBIDDEN);
                    res.render(Json(serde_json::json!({ "error": "Administrator privileges required to define authentication flows" })));
                    return;
                }
                match engine
                    .create_flow(&actor, &body.flow_id, &body.name, body.org_id, body.stages, body.timeout_secs, body.max_retries)
                    .await
                {
                    Ok(flow) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(flow));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamFlowStartHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamFlowStartHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let flow_id = req.param::<String>("flow_id").unwrap_or_default();
        #[derive(serde::Deserialize, Default)]
        struct StartReq {
            #[serde(default)]
            org_id: Option<String>,
        }
        let body = req.parse_json::<StartReq>().await.unwrap_or_default();
        let engine = crate::iam::flows::AuthFlowEngine::new(self.db.clone());
        match engine.start_flow(&flow_id, body.org_id).await {
            Ok(exec) => {
                res.status_code(StatusCode::CREATED);
                res.render(Json(exec));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamFlowSubmitHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamFlowSubmitHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let exec_id = req.param::<String>("exec_id").unwrap_or_default();
        let sub = req
            .parse_json::<crate::iam::flows::StageSubmission>()
            .await
            .unwrap_or_default();
        let engine = crate::iam::flows::AuthFlowEngine::new(self.db.clone());
        match engine.submit_stage(&exec_id, sub).await {
            Ok(exec) => {
                res.status_code(StatusCode::OK);
                res.render(Json(exec));
            }
            Err(e) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamIdentityPasswordHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamIdentityPasswordHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let identity_id = req.param::<String>("identity_id").unwrap_or_default();
        #[derive(serde::Deserialize)]
        struct SetPassReq {
            password: String,
        }
        let Ok(body) = req.parse_json::<SetPassReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            return;
        };
        let engine = crate::iam::flows::AuthFlowEngine::new(self.db.clone());
        match engine.set_identity_password(&identity_id, &body.password).await {
            Ok(()) => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({ "updated": true })));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamWebAuthnRegisterHandler {
    db: Arc<Database>,
    is_finish: bool,
}

#[async_trait]
impl Handler for IamWebAuthnRegisterHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let svc = crate::iam::webauthn::WebAuthnService::new(self.db.clone());
        if !self.is_finish {
            let Ok(body) = req.parse_json::<crate::iam::webauthn::RegistrationRequest>().await else {
                res.status_code(StatusCode::BAD_REQUEST);
                return;
            };
            match svc.begin_registration(body).await {
                Ok(ch) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(ch));
                }
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            }
        } else {
            let Ok(body) = req.parse_json::<crate::iam::webauthn::RegistrationResponse>().await else {
                res.status_code(StatusCode::BAD_REQUEST);
                return;
            };
            match svc.finish_registration(body).await {
                Ok(cred) => {
                    res.status_code(StatusCode::CREATED);
                    res.render(Json(cred));
                }
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            }
        }
    }
}

#[derive(Clone)]
struct IamWebAuthnAuthHandler {
    db: Arc<Database>,
    is_finish: bool,
}

#[async_trait]
impl Handler for IamWebAuthnAuthHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let svc = crate::iam::webauthn::WebAuthnService::new(self.db.clone());
        if !self.is_finish {
            let Ok(body) = req.parse_json::<crate::iam::webauthn::AuthenticationRequest>().await else {
                res.status_code(StatusCode::BAD_REQUEST);
                return;
            };
            match svc.begin_authentication(body).await {
                Ok(ch) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(ch));
                }
                Err(e) => {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            }
        } else {
            let Ok(body) = req.parse_json::<crate::iam::webauthn::AuthenticationResponse>().await else {
                res.status_code(StatusCode::BAD_REQUEST);
                return;
            };
            match svc.finish_authentication(body).await {
                Ok(auth_res) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(auth_res));
                }
                Err(e) => {
                    res.status_code(StatusCode::UNAUTHORIZED);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            }
        }
    }
}

#[derive(Clone)]
struct IamWebAuthnCredsHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamWebAuthnCredsHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let identity_id = req.query::<String>("identity_id").unwrap_or_else(|| actor.clone());
        let svc = crate::iam::webauthn::WebAuthnService::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => match svc.list_credentials(&identity_id).await {
                Ok(creds) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({ "credentials": creds })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            },
            salvo::http::Method::DELETE => {
                let cred_id = req.param::<String>("cred_id").unwrap_or_default();
                match svc.revoke_credential(&actor, &identity_id, &cred_id).await {
                    Ok(revoked) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "revoked": revoked })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamFedProvidersHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamFedProvidersHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let fed = crate::iam::federation::FederationService::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => {
                let org_id = req.query::<String>("org_id");
                match fed.list_providers(org_id.as_deref()).await {
                    Ok(providers) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "providers": providers })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct RegProvReq {
                    org_id: String,
                    name: String,
                    protocol: crate::iam::federation::FederationProtocol,
                    issuer: String,
                    sso_url: String,
                    #[serde(default)]
                    token_endpoint: Option<String>,
                    #[serde(default)]
                    client_id: Option<String>,
                    #[serde(default)]
                    client_secret: Option<String>,
                    #[serde(default)]
                    jwks_json: Option<serde_json::Value>,
                    #[serde(default)]
                    x509_cert_pem: Option<String>,
                    #[serde(default)]
                    verified_domains: Vec<String>,
                }
                let Ok(body) = req.parse_json::<RegProvReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                let auth = crate::ux::iam::depot_auth_context(depot);
                let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
                let is_admin = auth.as_ref().map(|a| a.roles.contains(&nexus_db::auth::Role::Owner)).unwrap_or(false);
                let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
                if !matches!(idp.evaluate_permission(&actor, is_admin, &body.org_id, "iam.policy.update").await, Ok(d) if d.allowed) {
                    res.status_code(StatusCode::FORBIDDEN);
                    res.render(Json(serde_json::json!({ "error": "Forbidden" })));
                    return;
                }
                match fed
                    .register_provider(
                        &actor,
                        &body.org_id,
                        &body.name,
                        body.protocol,
                        &body.issuer,
                        &body.sso_url,
                        body.token_endpoint,
                        body.client_id,
                        body.client_secret.as_deref(),
                        body.jwks_json,
                        body.x509_cert_pem,
                        body.verified_domains,
                    )
                    .await
                {
                    Ok(prov) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(prov));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamFedLinksHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamFedLinksHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let fed = crate::iam::federation::FederationService::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => {
                let ident = req.query::<String>("identity_id").unwrap_or_else(|| actor.clone());
                match fed.list_links_for_identity(&ident).await {
                    Ok(links) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "links": links })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct LinkReq {
                    identity_id: String,
                    provider_id: String,
                    external_subject: String,
                    #[serde(default)]
                    linked_email: Option<String>,
                }
                let Ok(body) = req.parse_json::<LinkReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                match fed
                    .link_identity(&actor, &body.identity_id, &body.provider_id, &body.external_subject, body.linked_email)
                    .await
                {
                    Ok(link) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(link));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamFedDiscoverHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamFedDiscoverHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        #[derive(serde::Deserialize)]
        struct DiscReq {
            email: String,
        }
        let Ok(body) = req.parse_json::<DiscReq>().await else {
            res.status_code(StatusCode::BAD_REQUEST);
            return;
        };
        let fed = crate::iam::federation::FederationService::new(self.db.clone());
        match fed.discover_by_email(&body.email).await {
            Ok(d) => {
                res.status_code(StatusCode::OK);
                res.render(Json(d));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamSamlMetadataHandler;

#[async_trait]
impl Handler for IamSamlMetadataHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("127.0.0.1:8443");
        let scheme = if req.headers().get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https") {
            "https"
        } else {
            "http"
        };
        let entity_id = format!("{}://{}/_nexus/iam/saml/metadata", scheme, host);
        let acs_url = format!("{}://{}/_nexus/iam/saml/acs", scheme, host);
        let xml = crate::iam::federation::FederationService::saml_sp_metadata_xml(&entity_id, &acs_url);
        res.status_code(StatusCode::OK);
        res.headers_mut().insert(
            salvo::http::header::CONTENT_TYPE,
            salvo::http::HeaderValue::from_static("application/samlmetadata+xml; charset=utf-8"),
        );
        res.body(xml);
    }
}

#[derive(Clone)]
struct IamSessionsHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamSessionsHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let svc = crate::iam::sessions::SessionService::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => {
                let ident = req.query::<String>("identity_id").unwrap_or_else(|| actor.clone());
                match svc.list_sessions(&ident).await {
                    Ok(sessions) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "sessions": sessions })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::DELETE => {
                let session_id = req.param::<String>("session_id").unwrap_or_default();
                match svc.revoke_session(&actor, &session_id).await {
                    Ok(revoked) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "revoked": revoked })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamDevicesHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamDevicesHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let auth = crate::ux::iam::depot_auth_context(depot);
        let actor = auth.as_ref().and_then(|a| a.actor.clone()).unwrap_or_default();
        let svc = crate::iam::sessions::SessionService::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => {
                let ident = req.query::<String>("identity_id").unwrap_or_else(|| actor.clone());
                match svc.list_devices(&ident).await {
                    Ok(devices) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "devices": devices })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct RegDevReq {
                    #[serde(default)]
                    identity_id: Option<String>,
                    label: String,
                    fingerprint: String,
                    #[serde(default)]
                    trust_level: Option<crate::iam::sessions::DeviceTrustLevel>,
                }
                let Ok(body) = req.parse_json::<RegDevReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                let ident = body.identity_id.unwrap_or_else(|| actor.clone());
                match svc
                    .register_device(
                        &ident,
                        &body.label,
                        &body.fingerprint,
                        body.trust_level.unwrap_or(crate::iam::sessions::DeviceTrustLevel::Verified),
                    )
                    .await
                {
                    Ok(dev) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(dev));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::DELETE => {
                let device_id = req.param::<String>("device_id").unwrap_or_default();
                let ident = req.query::<String>("identity_id").unwrap_or_else(|| actor.clone());
                match svc.revoke_device(&actor, &ident, &device_id).await {
                    Ok(revoked) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "revoked": revoked })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamClusterTrustHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamClusterTrustHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let svc = crate::iam::sessions::SessionService::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => match svc.list_trusted_clusters().await {
                Ok(clusters) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({ "clusters": clusters })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            },
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct TrustReq {
                    cluster_id: String,
                    issuer: String,
                    root_pubkey: String,
                    #[serde(default = "default_true")]
                    allow_portable_import: bool,
                    #[serde(default = "default_true")]
                    require_local_mfa: bool,
                }
                fn default_true() -> bool { true }
                let Ok(body) = req.parse_json::<TrustReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                let actor = crate::ux::iam::depot_auth_context(depot)
                    .and_then(|a| a.actor)
                    .unwrap_or_else(|| "owner".into());
                match svc
                    .register_trusted_cluster(
                        &actor,
                        &body.cluster_id,
                        &body.issuer,
                        &body.root_pubkey,
                        body.allow_portable_import,
                        body.require_local_mfa,
                    )
                    .await
                {
                    Ok(pol) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(pol));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamClientsHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamClientsHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        match *req.method() {
            salvo::http::Method::GET => {
                let org_id = req.query::<String>("org_id");
                match idp.list_oidc_clients(org_id.as_deref()).await {
                    Ok(clients) => {
                        res.status_code(StatusCode::OK);
                        res.render(Json(serde_json::json!({ "clients": clients })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            salvo::http::Method::POST => {
                #[derive(serde::Deserialize)]
                struct CreateClientReq {
                    #[serde(default = "default_org")]
                    org_id: String,
                    name: String,
                    #[serde(default)]
                    client_type: Option<crate::iam::idp::OidcClientType>,
                    #[serde(default)]
                    redirect_uris: Vec<String>,
                    #[serde(default)]
                    grant_types: Vec<String>,
                    #[serde(default)]
                    scopes: Vec<String>,
                }
                fn default_org() -> String { "default".into() }
                let Ok(body) = req.parse_json::<CreateClientReq>().await else {
                    res.status_code(StatusCode::BAD_REQUEST);
                    return;
                };
                let actor = crate::ux::iam::depot_auth_context(depot)
                    .and_then(|a| a.actor)
                    .unwrap_or_else(|| "owner".into());
                match idp
                    .create_oidc_client(
                        &actor,
                        &body.org_id,
                        &body.name,
                        body.client_type.unwrap_or(crate::iam::idp::OidcClientType::Public),
                        body.redirect_uris,
                        body.grant_types,
                        body.scopes,
                    )
                    .await
                {
                    Ok((client, secret)) => {
                        res.status_code(StatusCode::CREATED);
                        res.render(Json(serde_json::json!({
                            "client": client,
                            "client_secret": secret,
                        })));
                    }
                    Err(e) => {
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(serde_json::json!({ "error": e.to_string() })));
                    }
                }
            }
            _ => { res.status_code(StatusCode::METHOD_NOT_ALLOWED); }
        }
    }
}

#[derive(Clone)]
struct IamAuditHandler {
    db: Arc<Database>,
}

#[async_trait]
impl Handler for IamAuditHandler {
    async fn handle(&self, req: &mut Request, _depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());
        let org_id = req.query::<String>("org_id");
        let limit = req.query::<usize>("limit").unwrap_or(100);
        match idp.list_audit_events(org_id.as_deref(), limit).await {
            Ok(events) => {
                res.status_code(StatusCode::OK);
                res.render(Json(serde_json::json!({ "events": events })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[derive(Clone)]
struct IamTotpHandler {
    db: Arc<Database>,
    is_verify: bool,
}

#[async_trait]
impl Handler for IamTotpHandler {
    async fn handle(&self, req: &mut Request, depot: &mut Depot, res: &mut Response, _ctrl: &mut FlowCtrl) {
        let auth = crate::ux::iam::depot_auth_context(depot);
        let subject = auth
            .as_ref()
            .and_then(|a| a.actor.clone())
            .unwrap_or_else(|| "owner".into());
        let idp = crate::iam::idp::NexusIdp::new(self.db.clone());

        if !self.is_verify {
            let org_id = req.query::<String>("org_id").unwrap_or_else(|| "default".into());
            match idp.enroll_totp(&org_id, &subject).await {
                Ok((secret, uri, recovery_codes)) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(serde_json::json!({
                        "secret": secret,
                        "otpauth_uri": uri,
                        "recovery_codes": recovery_codes,
                    })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
            }
        } else {
            #[derive(serde::Deserialize)]
            struct VerifyReq {
                #[serde(default = "default_org")]
                org_id: String,
                code: String,
            }
            fn default_org() -> String { "default".into() }
            let Ok(body) = req.parse_json::<VerifyReq>().await else {
                res.status_code(StatusCode::BAD_REQUEST);
                return;
            };
            match idp.verify_totp(&body.org_id, &subject, &body.code).await {
                Ok(valid) => {
                    res.status_code(if valid { StatusCode::OK } else { StatusCode::UNAUTHORIZED });
                    res.render(Json(serde_json::json!({ "valid": valid })));
                }
                Err(e) => {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Json(serde_json::json!({ "error": e.to_string() })));
                }
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
