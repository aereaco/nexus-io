// Quick test to verify the Salvo gateway works
// Run with: cargo run --bin test_gateway

use nexus_io::ux::gateway::{UxGateway, GatewayConfig};
use nexus_io::db::Database;
use nexus_io::storage::BlobBridge;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Nexus-IO UX Gateway\n");

    // Initialize dependencies (minimal for testing)
    let db = Arc::new(Database::init().await);
    let garage = Arc::new(BlobBridge::new(db.clone()).await?);

    // Configure gateway (dev mode - using ports 8443 and 8080)
    let config = GatewayConfig {
        enable_https: true,
        enable_http: true,
        enable_surreal_direct: false,
        enable_s3_direct: false,
        enable_metrics: false,
        acme_domain: None,
        acme_email: None,
    };

    // Start gateway
    let gateway = UxGateway::new(db, garage, config);
    
    println!("✅ Gateway initialized successfully");
    println!("\nTest the gateway with:");
    println!("  curl http://localhost:8080/");
    println!("  curl http://localhost:8080/health");
    println!("  curl http://localhost:8080/rpc");
    println!("\nPress Ctrl+C to stop\n");

    gateway.start().await?;

    Ok(())
}
