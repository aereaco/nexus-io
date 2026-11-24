use surrealdb::engine::local::SurrealKv;
use surrealdb::Surreal;
use chrono::{DateTime, Utc};

pub mod command;
pub mod sql_compiler;
pub mod state_engine;

pub use state_engine::StateEngine;

pub struct Database {
    pub client: Surreal<surrealdb::engine::local::Db>,
}

impl Database {
    pub async fn init() -> Self {
        Self::init_in(".").await
    }

    /// Initialize SurrealDB (`SurrealKv`) inside an explicit writable `data_dir` (required on Android/iOS sandboxes).
    pub async fn init_in(data_dir: impl AsRef<std::path::Path>) -> Self {
        let db_path = data_dir.as_ref().join("nexus.db");
        let db = Surreal::new::<SurrealKv>(db_path).await.unwrap();
        
        // Select Namespace
        db.use_ns("nexus").use_db("system").await.unwrap();

        // Load Schema (No seeds anymore)
        let schema_sql = include_str!("schema.surql");
        if let Err(e) = db.query(schema_sql).await {
            eprintln!("!! [Database] Schema Error: {:?}", e);
        }

        // 1. PROJECT SYSTEM IDENTITY (Zero-Seed IAM)
        // Extract users from host memory via sysinfo
        use sysinfo::Users;
        let users = Users::new_with_refreshed_list();
        println!("DEBUG: Found {} users from sysinfo", users.len());
        
        let mut sync_tasks = vec![];
        for user in &users {
            let username = user.name().to_string();
            let groups: Vec<String> = user.groups().iter()
                .map(|g| g.name().to_string())
                .collect();

            let is_admin = groups.iter().any(|g| ["sudo", "wheel", "admin", "root"].contains(&g.as_str()));
            let active_role = if is_admin { "role:admin" } else { "role:guest" };

            let u_json = serde_json::json!({
                "username": username,
                "password": "", 
                "groups": groups,
                "active_role": active_role
            });

            // Prepare UPSERT
            let query = db.query("UPSERT type::record('user', $id) SET username = $user.username, password = $user.password, groups = $user.groups, active_role = type::record($user.active_role)")
                .bind(("id", username.clone()))
                .bind(("user", u_json));
            
            sync_tasks.push(async move { query.await });
        }

        // Parallelize the projection
        let results = futures::future::join_all(sync_tasks).await;
        for (i, res) in results.into_iter().enumerate() {
            match res {
                Ok(response) => {
                    if let Err(e) = response.check() {
                        println!("ERROR: Projection {} failed: {:?}", i, e);
                    }
                }
                Err(e) => println!("ERROR: Projection {} DB error: {:?}", i, e),
            }
        }

        // 2. PROJECT HARDWARE (Storage)
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();
        for disk in &disks {
            let name = disk.name().to_string_lossy().to_string();
            let mount = disk.mount_point().to_string_lossy().to_string();
            let total = disk.total_space();
            let avail = disk.available_space();
            let removable = disk.is_removable();

            let d_json = serde_json::json!({
                "name": name,
                "mount_point": mount,
                "total_space": total,
                "available_space": avail,
                "removable": removable
            });

            let _ = db.query("UPSERT type::record('sys::storage', $id) SET name = $d.name, mount_point = $d.mount_point, total_space = $d.total_space, available_space = $d.available_space, removable = $d.removable")
                .bind(("id", mount.clone().replace("/", "_")))
                .bind(("d", d_json))
                .await;
        }

        // 3. PROJECT INITIAL VFS (Cross-platform temp dir)
        if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let path = entry.path().to_string_lossy().to_string();
                    let is_dir = meta.is_dir();
                    let size = meta.len();
                    
                    let f_json = serde_json::json!({
                        "path": path,
                        "is_dir": is_dir,
                        "size": size,
                        "modified": DateTime::<Utc>::from(meta.modified().unwrap_or(std::time::SystemTime::now())).to_rfc3339()
                    });

                    let _ = db.query("UPSERT type::record('sys::file', $id) SET path = $f.path, is_dir = $f.is_dir, size = $f.size, modified = type::datetime($f.modified)")
                        .bind(("id", path.clone().replace("/", "_")))
                        .bind(("f", f_json))
                        .await;
                }
            }
        }

        println!("DEBUG: Hardware & VFS Projection complete");

        Self {
            client: db,
        }
    }
}
