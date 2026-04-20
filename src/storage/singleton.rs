use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use crate::db::Database;
use super::GarageBridge;

/// Global singleton GarageBridge instance
/// This ensures state persists across multiple Nushell command invocations
static BRIDGE: Lazy<Arc<RwLock<Option<GarageBridge>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Get or initialize the global GarageBridge singleton
/// 
/// This function returns a clone of the bridge, allowing multiple commands
/// to share the same underlying storage HashMap. The first call initializes
/// the bridge, subsequent calls return the existing instance.
pub async fn get_bridge(db: Arc<Database>) -> Result<GarageBridge> {
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
        println!("DEBUG: Initializing global GarageBridge singleton");
        *bridge_lock = Some(GarageBridge::new(db).await?);
    }
    
    Ok(bridge_lock.as_ref().unwrap().clone())
}

/// Reset the global bridge (useful for testing)
#[allow(dead_code)]
pub async fn reset_bridge() {
    let mut bridge_lock = BRIDGE.write().await;
    *bridge_lock = None;
    println!("DEBUG: Global GarageBridge reset");
}
