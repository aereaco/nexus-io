use anyhow::Result;
use std::collections::HashMap;

use crate::storage::BlobBridge;

/// Summary row produced by scanning hibernated `elastic` cell snapshots in `BlobBridge`
/// without waking the cells (Layer 2 cross-cell analytics foundation).
#[derive(Debug, Clone)]
pub struct CellAnalyticsSummary {
    pub cells_scanned: usize,
    pub total_kv_keys: usize,
    pub kv_counts_by_app: HashMap<String, usize>,
}

/// Scan hibernated cell snapshots (`snapshots/<app>/<cell_id>.json`) directly from `BlobBridge`
/// without waking any `elastic` cells.
pub async fn scan_hibernated_cells(
    blobs: &BlobBridge,
    bucket: &str,
) -> Result<CellAnalyticsSummary> {
    let objects = blobs.list_objects(bucket, Some("snapshots/")).await?;
    let mut cells_scanned = 0usize;
    let mut total_kv_keys = 0usize;
    let mut kv_counts_by_app: HashMap<String, usize> = HashMap::new();

    for meta in objects {
        let Some(bytes) = blobs.get_object(bucket, &meta.key).await? else {
            continue;
        };
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };

        cells_scanned += 1;
        let app = json
            .get("ns")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let kv_len = json
            .get("kv")
            .and_then(|v| v.as_object())
            .map(|m| m.len())
            .unwrap_or(0);

        total_kv_keys += kv_len;
        *kv_counts_by_app.entry(app).or_insert(0) += kv_len;
    }

    Ok(CellAnalyticsSummary {
        cells_scanned,
        total_kv_keys,
        kv_counts_by_app,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::js::cell::{CellManager, CellPolicy};
    use std::sync::Arc;

    #[test]
    fn scans_hibernated_elastic_cells_without_waking() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let db = Arc::new(Database::open_mem());
                    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
                    let manager = CellManager::new(db.clone(), blobs.clone());

                    let policy = CellPolicy::Elastic {
                        idle_timeout: std::time::Duration::from_secs(60),
                        lease_bucket: "analytics-cells".to_string(),
                    };

                    for id in ["c1", "c2"] {
                        manager
                            .wake("analytics_app", id, policy.clone(), String::new())
                            .await
                            .unwrap();
                        manager
                            .eval_in_cell("analytics_app", id, r#"ctx.storage.put("k1", "v1")"#)
                            .await
                            .unwrap();
                        manager.hibernate("analytics_app", id).await.unwrap();
                    }

            let summary = scan_hibernated_cells(&blobs, "analytics-cells").await.unwrap();
            assert_eq!(summary.cells_scanned, 2);
            assert_eq!(summary.total_kv_keys, 2);
            assert_eq!(summary.kv_counts_by_app.get("analytics_app"), Some(&2));
        });
    }
}
