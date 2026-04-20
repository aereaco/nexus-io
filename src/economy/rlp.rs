// Revenue-Link Protocol (RLP)
// Implements the specific revenue split logic for the Nexus Ecosystem

use serde::{Serialize, Deserialize};

/// Revenue split ratios (total must be 1.0)
pub const SPLIT_PLATFORM: f64 = 0.005;  // 0.5% (Nexus-IO)
pub const SPLIT_NODE: f64 = 0.645;      // 64.5% (Node Provider)
pub const SPLIT_DEV: f64 = 0.35;       // 35.0% (Developer/Creator)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueSplit {
    pub platform: f64,
    pub node: f64,
    pub dev: f64,
}

/// Calculate the split for a given total amount
pub fn calculate_split(total_za: f64) -> RevenueSplit {
    RevenueSplit {
        platform: total_za * SPLIT_PLATFORM,
        node: total_za * SPLIT_NODE,
        dev: total_za * SPLIT_DEV,
    }
}

/// Transaction record for audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub timestamp: u64,
    pub job_id: String,
    pub total_amount: f64,
    pub split: RevenueSplit,
    pub node_id: String,
    pub user_id: String,
}
