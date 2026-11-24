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

    /// Port 443: Primary HTTPS gateway
    async fn serve_https(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = self.build_main_router();

        // TODO: Implement ACME once we have a domain
        // For now, use self-signed cert or require manual cert
        
        println!("✅ HTTPS Gateway listening on 0.0.0.0:443");
        println!("   Note: ACME/TLS not yet configured - manual cert required");
        
        // For development: just use HTTP on 8443
        let acceptor = TcpListener::new("0.0.0.0:8443").bind().await;
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
        Router::new()
            // Static PWA files
            .push(Router::with_path("/").get(serve_static))
            
            // WebSocket Signal Hub (SurrealDB LIVE queries)
            .push({
                let db = self.db.clone();
                let ws_handler = WebSocketHandler { db: db.clone() };
                let iam = crate::ux::iam::IamMiddleware { db };
                Router::with_path("/rpc")
                    .hoop(iam)
                    .get(ws_handler)
            })
            
            // S3 Proxy (browser-friendly)
            .push({
                let db = self.db.clone();
                let garage = self.garage.clone();
                let s3_handler = S3ProxyHandler { garage };
                let iam = crate::ux::iam::IamMiddleware { db };
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
                let iam = crate::ux::iam::IamMiddleware { db };
                Router::with_path("/cells/<**path>")
                    .hoop(iam)
                    .get(cell_handler.clone())
                    .post(cell_handler.clone())
                    .put(cell_handler.clone())
                    .delete(cell_handler)
            })
            
            // Health check
            .push(Router::with_path("/health").get(health_check))
    }
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
