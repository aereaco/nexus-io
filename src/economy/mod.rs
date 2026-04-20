// Economic Kernel - Monetization logic for Nexus-IO
// Implements VPR (Variable Payout Rate) and RLP (Revenue-Link Protocol)

pub mod vpr;
pub mod rlp;

use std::sync::Arc;
use crate::db::Database;
use uuid::Uuid;
use serde::{Serialize, Deserialize};

/// Economic Kernel instance
pub struct EconomicKernel {
    db: Arc<Database>,
}

impl EconomicKernel {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
    
    /// Record a transaction in the audit log
    pub async fn record_transaction(&self, tx: rlp::Transaction) -> anyhow::Result<()> {
        let sql = "CREATE transaction CONTENT $tx";
        let tx_json = serde_json::to_value(&tx)?;
        self.db.client.query(sql)
            .bind(("tx", tx_json))
            .await?;
            
        println!("💰 Nexus-IO Monetization: Recorded transaction {} split: node={} dev={} platform={}", 
            tx.id, tx.split.node, tx.split.dev, tx.split.platform);
            
        Ok(())
    }

    /// Process a payout for a compute job
    pub async fn process_compute_payout(
        &self,
        job_id: &str,
        user_id: &str,
        node_id: &str,
        amount: f64,
    ) -> anyhow::Result<()> {
        let split = rlp::calculate_split(amount);
        let tx = rlp::Transaction {
            id: format!("tx_{}", Uuid::new_v4()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            job_id: job_id.to_string(),
            total_amount: amount,
            split: split.clone(),
            node_id: node_id.to_string(),
            user_id: user_id.to_string(),
        };

        // 1. Audit Log
        self.record_transaction(tx).await?;

        // 2. Settlement (Atomic Balance Updates)
        let billing = BillingService::new(self.db.clone());
        
        // Debit User
        billing.update_balance(user_id, -amount).await?;
        
        // Credit Node (Provider)
        billing.update_balance(node_id, split.node).await?;
        
        // Credit Platform (Vault)
        billing.update_balance("platform_nexus", split.platform).await?;
        
        // Credit Developer (Scope-based)
        // For PoC, credited to a global dev account
        billing.update_balance("dev_pioneer", split.dev).await?;

        Ok(())
    }
}

/// Billing Service - Manages ZA credit balances
pub struct BillingService {
    db: Arc<Database>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    pub user_id: String,
    pub balance_za: f64,
    pub last_updated: u64,
}

impl BillingService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Update ZA credit balance for a user (atomic increment/decrement)
    pub async fn update_balance(&self, user_id: &str, amount: f64) -> anyhow::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Use SurrealDB atomic increment (+=)
        // UPSERT logic: if wallet doesn't exist, create it.
        // SurrealDB 2.x+ supports 'UPSERT' or we can just use a query with a check.
        // Let's use a query to ensure atomicity and creation.
        let sql = "
            LET $exists = (SELECT * FROM wallet WHERE user_id = $user_id);
            IF $exists THEN
                UPDATE wallet SET balance_za += $amount, last_updated = $now WHERE user_id = $user_id
            ELSE
                CREATE wallet CONTENT {
                    user_id: $user_id,
                    balance_za: $amount,
                    last_updated: $now
                }
            END;
        ";

        self.db.client.query(sql)
            .bind(("user_id", user_id.to_string()))
            .bind(("amount", amount))
            .bind(("now", now))
            .await?;

        println!("💳 Billing: Updated balance for {} by {} ZA", user_id, amount);
        Ok(())
    }

    /// Get ZA credit balance for a user
    pub async fn get_balance(&self, user_id: &str) -> anyhow::Result<f64> {
        let mut response = self.db.client
            .query("SELECT balance_za FROM wallet WHERE user_id = $user_id")
            .bind(("user_id", user_id.to_string()))
            .await?;

        let balance: Option<f64> = response.take("balance_za")?;
        Ok(balance.unwrap_or(0.0))
    }
}
