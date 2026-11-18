use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use crate::db::Database;
use super::BlobBridge;

/// Global singleton BlobBridge instance
/// This ensures state persists across multiple Nushell command invocations
static BRIDGE: Lazy<Arc<RwLock<Option<BlobBridge>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Get or initialize the global BlobBridge singleton
/// 
/// This function returns a clone of the bridge, allowing multiple commands
/// to share the same underlying storage store. The first call initializes
/// the bridge, subsequent calls return the existing instance.
pub async fn get_bridge(db: Arc<Database>) -> Result<BlobBridge> {
    // Fast path: check if already initialized (read lock)
    {
        let bridge_lock = BRIDGE.read().await;
        if let Some(bridge) = bridge_lock.as_ref() {
            return Ok(bridge.clone());
        }
    }
    
    // Slow path: initialize (write lock)
    let mut bridge_lock = BRIDGE.write().await;
    
    // Double-check in case another task initialized while we waited
    if bridge_lock.is_none() {
        println!("DEBUG: Initializing global BlobBridge singleton");
        *bridge_lock = Some(BlobBridge::new(db).await?);
    }
    
    Ok(bridge_lock.as_ref().unwrap().clone())
}

/// Reset the global bridge (useful for testing)
#[allow(dead_code)]
pub async fn reset_bridge() {
    let mut bridge_lock = BRIDGE.write().await;
    *bridge_lock = None;
    println!("DEBUG: Global BlobBridge reset");
}
