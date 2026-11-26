#![cfg(feature = "serve-web")]

use nexus_io::db::Database;
use nexus_io::storage::BlobBridge;
use nexus_io::ux::{GatewayConfig, UxGateway};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use salvo::Service;
use std::path::PathBuf;
use std::sync::Arc;

fn repo_site_and_dist() -> (PathBuf, PathBuf) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().expect("io/ parent is aerea-nexus root");
    let web_dir = if root.join("shell").join("index.html").is_file() {
        root.join("shell")
    } else {
        root.join("site")
    };
    let dist_dir = if root.join("ux").join("dist").join("nexus-ux.js").is_file() {
        root.join("ux").join("dist")
    } else {
        root.join("dist")
    };
    (web_dir, dist_dir)
}

#[tokio::test]
async fn serve_web_serves_real_site_dist_spa_fallback_404_and_isolation_headers() {
    let (site_dir, dist_dir) = repo_site_and_dist();
    assert!(site_dir.join("index.html").is_file(), "site/index.html must exist");
    assert!(dist_dir.join("nexus-ux.js").is_file(), "dist/nexus-ux.js must exist");

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let config = GatewayConfig {
        enable_web: true,
        web_root: Some(site_dir.clone()),
        dist_root: Some(dist_dir.clone()),
        coop_header: Some("same-origin".to_string()),
        coep_header: Some("credentialless".to_string()),
        ..GatewayConfig::all_core()
    };
    let gw = UxGateway::new(db.clone(), blobs.clone(), config);
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // 1. Root HTML + COOP/COEP headers
    let mut root_res = TestClient::get("http://127.0.0.1/")
        .add_header("accept", "text/html", true)
        .send(&service)
        .await;
    assert_eq!(root_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        root_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        root_res
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|v| v.to_str().ok()),
        Some("same-origin")
    );
    assert_eq!(
        root_res
            .headers()
            .get("cross-origin-embedder-policy")
            .and_then(|v| v.to_str().ok()),
        Some("credentialless")
    );
    let root_body = root_res.take_string().await.unwrap();
    assert!(root_body.contains("app-layout"), "expected real site/index.html");

    // 2. Real dist bundle (/dist/nexus-ux.js) + matching COEP for dedicated Web Workers
    let dist_res = TestClient::get("http://127.0.0.1/dist/nexus-ux.js")
        .send(&service)
        .await;
    assert_eq!(dist_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        dist_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/javascript; charset=utf-8")
    );
    assert_eq!(
        dist_res
            .headers()
            .get("cross-origin-embedder-policy")
            .and_then(|v| v.to_str().ok()),
        Some("credentialless")
    );

    // 3. Real site JSON & SVG assets with proper MIME types
    let manifest_res = TestClient::get("http://127.0.0.1/_pages/manifest.json")
        .send(&service)
        .await;
    assert_eq!(manifest_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        manifest_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json; charset=utf-8")
    );

    let svg_res = TestClient::get("http://127.0.0.1/_assets/images/emblem.svg")
        .send(&service)
        .await;
    assert_eq!(svg_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        svg_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("image/svg+xml")
    );

    // 4. SPA HTML navigation fallback for nested route
    let mut spa_res = TestClient::get("http://127.0.0.1/labs/attributes/signal")
        .add_header("accept", "text/html", true)
        .send(&service)
        .await;
    assert_eq!(spa_res.status_code, Some(StatusCode::OK));
    let spa_body = spa_res.take_string().await.unwrap();
    assert!(spa_body.contains("app-layout"));

    // 5. Genuine 404 for missing static assets and unknown non-HTML API routes
    let missing_js = TestClient::get("http://127.0.0.1/missing.js")
        .send(&service)
        .await;
    assert_eq!(missing_js.status_code, Some(StatusCode::NOT_FOUND));

    let missing_dist = TestClient::get("http://127.0.0.1/dist/does-not-exist.js")
        .send(&service)
        .await;
    assert_eq!(missing_dist.status_code, Some(StatusCode::NOT_FOUND));

    let missing_api = TestClient::get("http://127.0.0.1/api/unknown-endpoint")
        .add_header("accept", "application/json", true)
        .send(&service)
        .await;
    assert_eq!(missing_api.status_code, Some(StatusCode::NOT_FOUND));

    // 6. Path traversal rejection (400 Bad Request)
    let traversal = TestClient::get("http://127.0.0.1/web/..%2FCargo.toml")
        .send(&service)
        .await;
    assert!(
        traversal.status_code == Some(StatusCode::BAD_REQUEST)
            || traversal.status_code == Some(StatusCode::NOT_FOUND),
        "traversal must be rejected, got {:?}",
        traversal.status_code
    );

    // 7. Liveness (/health) and readiness (/ready) remain unaffected
    let health = TestClient::get("http://127.0.0.1/health").send(&service).await;
    assert_eq!(health.status_code, Some(StatusCode::OK));
    let ready = TestClient::get("http://127.0.0.1/ready").send(&service).await;
    assert_eq!(ready.status_code, Some(StatusCode::OK));
}

#[tokio::test]
async fn serve_web_respects_disabled_coop_coep_and_reports_unavailable_bundle() {
    let (site_dir, dist_dir) = repo_site_and_dist();
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());

    // 1. Disabled COOP/COEP headers
    let no_iso_cfg = GatewayConfig {
        enable_web: true,
        web_root: Some(site_dir),
        dist_root: Some(dist_dir),
        coop_header: None,
        coep_header: None,
        ..GatewayConfig::default()
    };
    let gw = UxGateway::new(db.clone(), blobs.clone(), no_iso_cfg);
    let service = Service::new(gw.router());
    let res = TestClient::get("http://127.0.0.1/")
        .add_header("accept", "text/html", true)
        .send(&service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    assert!(res.headers().get("cross-origin-opener-policy").is_none());
    assert!(res.headers().get("cross-origin-embedder-policy").is_none());

    // 2. Explicit missing web_root returns 503 bundle unavailable page (never silently falls back)
    let missing_cfg = GatewayConfig {
        enable_web: true,
        web_root: Some(PathBuf::from("nonexistent_nexus_bundle_dir_12345")),
        dist_root: None,
        ..GatewayConfig::default()
    };
    let gw2 = UxGateway::new(db, blobs, missing_cfg);
    let service2 = Service::new(gw2.router());
    let mut unavail = TestClient::get("http://127.0.0.1/")
        .add_header("accept", "text/html", true)
        .send(&service2)
        .await;
    assert_eq!(unavail.status_code, Some(StatusCode::SERVICE_UNAVAILABLE));
    let body = unavail.take_string().await.unwrap();
    assert!(body.contains("Application Bundle Unavailable"));
}

#[tokio::test]
async fn rpc_session_matches_sql_sprite_positional_json_rpc_and_live_lifecycle() {
    let db = Arc::new(Database::open_mem());
    let mut session = db.inner.rpc_session("erp", "main");

    // 1. Positional `use` -> ["erp", "main"]
    let use_reply: serde_json::Value =
        serde_json::from_str(&session.handle_json(r#"{"id":"1","method":"use","params":["erp","main"]}"#))
            .unwrap();
    assert!(use_reply.get("error").is_none(), "use failed: {:?}", use_reply);

    // 2. Subscribe via positional `live` -> ["task"]
    let live_reply: serde_json::Value =
        serde_json::from_str(&session.handle_json(r#"{"id":"2","method":"live","params":["task"]}"#))
            .unwrap();
    assert!(live_reply.get("error").is_none(), "live failed: {:?}", live_reply);
    let live_id = live_reply["result"].as_str().expect("live returns uuid string").to_string();

    // 3. Mutate via positional `query` -> [sql, vars]
    let create_reply: serde_json::Value = serde_json::from_str(&session.handle_json(
        r#"{"id":"3","method":"query","params":["CREATE task:1 SET title = $title, done = false;",{"title":"Verify RPC"}]}"#,
    ))
    .unwrap();
    assert!(create_reply.get("error").is_none(), "create failed: {:?}", create_reply);

    // 4. Drain LIVE notifications -> SurrealDB v2 push frame { result: { id, action, result } }
    let frames = session.drain_live_notifications();
    assert!(!frames.is_empty(), "expected CREATE live notification");
    let pushed: serde_json::Value = serde_json::from_str(&frames[0]).unwrap();
    assert_eq!(pushed["result"]["id"].as_str(), Some(live_id.as_str()));
    assert_eq!(pushed["result"]["action"].as_str(), Some("CREATE"));
    assert_eq!(pushed["result"]["result"]["title"].as_str(), Some("Verify RPC"));

    // 5. Kill subscription via positional `kill` -> [live_id]
    let kill_req = serde_json::json!({ "id": "4", "method": "kill", "params": [live_id] });
    let kill_reply: serde_json::Value =
        serde_json::from_str(&session.handle_json(&kill_req.to_string())).unwrap();
    assert!(kill_reply.get("error").is_none(), "kill failed: {:?}", kill_reply);

    // 6. Further mutations after `kill` produce zero notifications
    let _ = session.handle_json(
        r#"{"id":"5","method":"query","params":["CREATE task:2 SET title = 'After kill';",{}]}"#,
    );
    assert!(session.drain_live_notifications().is_empty());
}

#[tokio::test]
async fn iam_session_cookie_auth_me_and_server_rbac_enforcement() {
    // Ensure local unauth bypass is OFF so real IAM enforcement is exercised
    std::env::remove_var("NEXUS_ALLOW_UNAUTH_LOCAL");

    let db = Arc::new(Database::open_mem());
    // Seed two real Nexus-DB users with distinct RBAC roles
    db.inner
        .query_scoped_multi(
            "nexus",
            "system",
            "DEFINE USER director ON DATABASE PASSWORD 'director-pass' ROLES OWNER;
             DEFINE USER auditor ON DATABASE PASSWORD 'auditor-pass' ROLES VIEWER;
             CREATE erp_po:po_088 SET title = 'PO #2026-Q3-088', status = 'Pending Review', amount = '$14,250.00';",
            vec![],
        )
        .expect("seed users and PO");

    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db.clone(), blobs, GatewayConfig::all_core());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // 1. Anonymous GET /_nexus/auth/me reports unauthenticated
    let mut anon_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .send(&service)
        .await;
    assert_eq!(anon_me.status_code, Some(StatusCode::OK));
    let anon_json: serde_json::Value = serde_json::from_str(&anon_me.take_string().await.unwrap()).unwrap();
    assert_eq!(anon_json["authenticated"], false);
    assert!(anon_json["roles"].as_array().unwrap().is_empty());

    // 2. Anonymous POST /sql is rejected with 401 Unauthorized
    let anon_sql = TestClient::post("http://127.0.0.1/sql")
        .body("SELECT * FROM erp_po;")
        .send(&service)
        .await;
    assert_eq!(anon_sql.status_code, Some(StatusCode::UNAUTHORIZED));

    // 3. Sign in as VIEWER (`auditor`) -> sets HttpOnly nexus_session cookie
    let viewer_signin = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "auditor", "pass": "auditor-pass", "ns": "nexus", "db": "system" }))
        .send(&service)
        .await;
    assert_eq!(viewer_signin.status_code, Some(StatusCode::OK));
    let set_cookie = viewer_signin
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header must be present")
        .to_string();
    assert!(set_cookie.contains("nexus_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let viewer_cookie = set_cookie.split(';').next().unwrap().to_string();

    // 4. GET /_nexus/auth/me with VIEWER cookie returns verified identity + read-only capabilities
    let mut viewer_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .add_header("cookie", &viewer_cookie, true)
        .send(&service)
        .await;
    assert_eq!(viewer_me.status_code, Some(StatusCode::OK));
    let viewer_json: serde_json::Value = serde_json::from_str(&viewer_me.take_string().await.unwrap()).unwrap();
    assert_eq!(viewer_json["authenticated"], true);
    assert_eq!(viewer_json["actor"], "auditor");
    assert_eq!(viewer_json["roles"], serde_json::json!(["VIEWER"]));
    let viewer_caps = viewer_json["capabilities"].as_array().unwrap();
    assert!(viewer_caps.contains(&serde_json::json!("db.read")));
    assert!(!viewer_caps.contains(&serde_json::json!("db.write")));

    // 5. VIEWER can SELECT via cookie, but server REJECTS mutating UPDATE
    let mut viewer_read = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &viewer_cookie, true)
        .body("SELECT * FROM erp_po;")
        .send(&service)
        .await;
    assert_eq!(viewer_read.status_code, Some(StatusCode::OK));
    let read_body = viewer_read.take_string().await.unwrap();
    assert!(read_body.contains("PO #2026-Q3-088"));

    let mut viewer_write = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &viewer_cookie, true)
        .body("UPDATE erp_po:po_088 SET status = 'Approved';")
        .send(&service)
        .await;
    let write_status = viewer_write.status_code;
    let write_body = viewer_write.take_string().await.unwrap();
    assert!(
        write_status == Some(StatusCode::BAD_REQUEST)
            || write_status == Some(StatusCode::FORBIDDEN)
            || write_body.contains("\"status\":\"ERR\""),
        "VIEWER write must be rejected by server RBAC, got {:?}: {}",
        write_status,
        write_body
    );

    // 6. Sign in as OWNER (`director`) -> can mutate erp_po:po_088
    let owner_signin = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "director", "pass": "director-pass", "ns": "nexus", "db": "system" }))
        .send(&service)
        .await;
    assert_eq!(owner_signin.status_code, Some(StatusCode::OK));
    let owner_cookie = owner_signin
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let mut owner_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    let owner_json: serde_json::Value = serde_json::from_str(&owner_me.take_string().await.unwrap()).unwrap();
    assert_eq!(owner_json["authenticated"], true);
    assert_eq!(owner_json["actor"], "director");
    assert_eq!(owner_json["roles"], serde_json::json!(["OWNER"]));
    assert!(owner_json["capabilities"].as_array().unwrap().contains(&serde_json::json!("db.write")));

    let mut owner_write = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &owner_cookie, true)
        .body("UPDATE erp_po:po_088 SET status = 'Approved', approved_by = 'director';")
        .send(&service)
        .await;
    assert_eq!(owner_write.status_code, Some(StatusCode::OK));
    let owner_write_body = owner_write.take_string().await.unwrap();
    assert!(owner_write_body.contains("Approved"), "expected Approved in {}", owner_write_body);

    // 7. POST /signout clears the cookie
    let signout = TestClient::post("http://127.0.0.1/signout")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(signout.status_code, Some(StatusCode::OK));
    let clear_hdr = signout.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(clear_hdr.contains("nexus_session=;"));
    assert!(clear_hdr.contains("Max-Age=0"));
}

#[tokio::test]
async fn s3_proxy_enforces_blob_capabilities_traversal_and_etag() {
    std::env::remove_var("NEXUS_ALLOW_UNAUTH_LOCAL");

    let db = Arc::new(Database::open_mem());
    db.inner
        .query_scoped_multi(
            "nexus",
            "system",
            "DEFINE USER director ON DATABASE PASSWORD 'director-pass' ROLES OWNER;
             DEFINE USER auditor ON DATABASE PASSWORD 'auditor-pass' ROLES VIEWER;",
            vec![],
        )
        .unwrap();

    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db, blobs, GatewayConfig::all_core());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    let owner_cookie = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "director", "pass": "director-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let viewer_cookie = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "auditor", "pass": "auditor-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // 1. VIEWER PUT is rejected with 403 Forbidden (missing BlobWrite)
    let viewer_put = TestClient::put("http://127.0.0.1/s3/erp-attachments/po_088/spec.txt")
        .add_header("cookie", &viewer_cookie, true)
        .body("unauthorized upload")
        .send(&service)
        .await;
    assert_eq!(viewer_put.status_code, Some(StatusCode::FORBIDDEN));

    // 2. OWNER PUT succeeds and returns ETag
    let owner_put = TestClient::put("http://127.0.0.1/s3/erp-attachments/po_088/spec.txt")
        .add_header("cookie", &owner_cookie, true)
        .body("PO #2026-Q3-088 hydraulic spec sheet")
        .send(&service)
        .await;
    assert_eq!(owner_put.status_code, Some(StatusCode::OK));
    assert!(owner_put.headers().get("etag").is_some(), "PUT must return ETag");

    // 3. VIEWER can GET and HEAD the uploaded object (BlobRead), with ETag
    let mut viewer_get = TestClient::get("http://127.0.0.1/s3/erp-attachments/po_088/spec.txt")
        .add_header("cookie", &viewer_cookie, true)
        .send(&service)
        .await;
    assert_eq!(viewer_get.status_code, Some(StatusCode::OK));
    assert!(viewer_get.headers().get("etag").is_some(), "GET must return ETag");
    assert_eq!(
        viewer_get.take_string().await.unwrap(),
        "PO #2026-Q3-088 hydraulic spec sheet"
    );

    // 4. VIEWER DELETE is rejected with 403 Forbidden
    let viewer_del = TestClient::delete("http://127.0.0.1/s3/erp-attachments/po_088/spec.txt")
        .add_header("cookie", &viewer_cookie, true)
        .send(&service)
        .await;
    assert_eq!(viewer_del.status_code, Some(StatusCode::FORBIDDEN));

    // 5. Path traversal is rejected with 400 Bad Request
    let traversal = TestClient::get("http://127.0.0.1/s3/erp-attachments/..%2fsecret.txt")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert!(
        traversal.status_code == Some(StatusCode::BAD_REQUEST)
            || traversal.status_code == Some(StatusCode::NOT_FOUND)
    );

    // 6. OWNER DELETE succeeds (204)
    let owner_del = TestClient::delete("http://127.0.0.1/s3/erp-attachments/po_088/spec.txt")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(owner_del.status_code, Some(StatusCode::NO_CONTENT));
}

#[cfg(feature = "runtime-wasm")]
#[tokio::test]
async fn wasm_cell_executes_po_approval_enforces_caller_iam_and_survives_hibernation() {
    std::env::remove_var("NEXUS_ALLOW_UNAUTH_LOCAL");

    let db = Arc::new(Database::open_mem());
    db.inner
        .query_scoped_multi(
            "nexus",
            "system",
            "DEFINE USER director ON DATABASE PASSWORD 'director-pass' ROLES OWNER;
             DEFINE USER auditor ON DATABASE PASSWORD 'auditor-pass' ROLES VIEWER;
             CREATE erp_po:po_088 SET title = 'PO #2026-Q3-088', status = 'Pending Review', amount = '$14,250.00';",
            vec![],
        )
        .unwrap();

    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db.clone(), blobs, GatewayConfig::all_core());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    let owner_cookie = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "director", "pass": "director-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let viewer_cookie = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "auditor", "pass": "auditor-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Real WASI Preview 1 module calling nexus_host::nexus_db_query + nexus_host::nexus_blob_put
    let query = "UPDATE erp_po:po_088 SET status = 'Approved', approved_by = 'director', receipt_path = '/s3/erp-receipts/po_088-receipt.json';";
    let receipt = r#"{"po_id":"erp_po:po_088","status":"Approved","approved_by":"director","engine":"wasmtime-51","cell":"erp/po-workflow"}"#;
    let ok_json = r#"{"ok":true,"po_id":"erp_po:po_088","status":"Approved","receipt_path":"/s3/erp-receipts/po_088-receipt.json","engine":"wasmtime-51"}"#;
    let err_json = r#"{"ok":false,"error":"IAM capability denied inside Wasmtime sandbox"}"#;

    let wat = format!(
        r#"(module
          (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "nexus_host" "nexus_db_query" (func $db_query (param i32 i32 i32 i32 i32 i32) (result i32)))
          (import "nexus_host" "nexus_blob_put" (func $blob_put (param i32 i32 i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "surql")
          (data (i32.const 16) "{query}")
          (data (i32.const 256) "erp-receipts")
          (data (i32.const 288) "po_088-receipt.json")
          (data (i32.const 320) "{receipt_esc}")
          (data (i32.const 512) "{ok_esc}")
          (data (i32.const 700) "{err_esc}")
          (func $write_stdout (param $ptr i32) (param $len i32)
            (i32.store (i32.const 900) (local.get $ptr))
            (i32.store (i32.const 904) (local.get $len))
            (drop (call $fd_write (i32.const 1) (i32.const 900) (i32.const 1) (i32.const 912)))
          )
          (func (export "_start")
            (local $rc i32)
            (local.set $rc (call $db_query (i32.const 0) (i32.const 5) (i32.const 16) (i32.const {qlen}) (i32.const 1024) (i32.const 1024)))
            (if (i32.lt_s (local.get $rc) (i32.const 0))
              (then
                (call $write_stdout (i32.const 700) (i32.const {elen}))
                (return)
              )
            )
            (local.set $rc (call $blob_put (i32.const 256) (i32.const 12) (i32.const 288) (i32.const 19) (i32.const 320) (i32.const {rlen})))
            (if (i32.lt_s (local.get $rc) (i32.const 0))
              (then
                (call $write_stdout (i32.const 700) (i32.const {elen}))
                (return)
              )
            )
            (call $write_stdout (i32.const 512) (i32.const {olen}))
          )
        )"#,
        query = query,
        qlen = query.len(),
        receipt_esc = receipt.replace('"', "\\\""),
        rlen = receipt.len(),
        ok_esc = ok_json.replace('"', "\\\""),
        olen = ok_json.len(),
        err_esc = err_json.replace('"', "\\\""),
        elen = err_json.len(),
    );

    // 1. Grant erp/po-workflow a Reference DB binding to nexus/system (requires OWNER CellManage)
    let cfg_res = TestClient::put("http://127.0.0.1/cells/erp/po-workflow/db-config")
        .add_header("cookie", &owner_cookie, true)
        .json(&serde_json::json!({
            "mode": { "reference": { "target_app": "nexus", "target_cell_id": "system", "read_only": false } },
            "flavors": ["surql"],
            "transports": ["internal"]
        }))
        .send(&service)
        .await;
    assert_eq!(cfg_res.status_code, Some(StatusCode::OK));

    // 2. Deploy the WASI cell (requires CellSpawn)
    let deploy_res = TestClient::put("http://127.0.0.1/cells/erp/po-workflow")
        .add_header("cookie", &owner_cookie, true)
        .add_header("x-nexus-runtime", "wasm", true)
        .body(wat)
        .send(&service)
        .await;
    assert_eq!(deploy_res.status_code, Some(StatusCode::OK));

    // 3. VIEWER invokes cell -> Wasmtime nexus_host denies DbWrite/BlobWrite inside sandbox!
    let mut viewer_invoke = TestClient::post("http://127.0.0.1/cells/erp/po-workflow")
        .add_header("cookie", &viewer_cookie, true)
        .body("{}")
        .send(&service)
        .await;
    let viewer_out = viewer_invoke.take_string().await.unwrap();
    assert!(
        viewer_out.contains("IAM capability denied"),
        "expected sandbox denial for VIEWER, got: {}",
        viewer_out
    );

    // 4. OWNER invokes cell -> Wasmtime executes UPDATE erp_po:po_088 + writes S3 receipt
    let mut owner_invoke = TestClient::post("http://127.0.0.1/cells/erp/po-workflow")
        .add_header("cookie", &owner_cookie, true)
        .body("{}")
        .send(&service)
        .await;
    assert_eq!(owner_invoke.status_code, Some(StatusCode::OK));
    let owner_out = owner_invoke.take_string().await.unwrap();
    assert!(owner_out.contains("\"ok\":true"), "unexpected cell output: {}", owner_out);

    // 5. Hibernate cell (DELETE /cells/erp/po-workflow) -> 204 No Content
    let hib = TestClient::delete("http://127.0.0.1/cells/erp/po-workflow")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(hib.status_code, Some(StatusCode::NO_CONTENT));

    // 6. Durable state survived cell hibernation in both Nexus-DB and S3 BlobStore!
    let mut receipt_get = TestClient::get("http://127.0.0.1/s3/erp-receipts/po_088-receipt.json")
        .add_header("cookie", &viewer_cookie, true)
        .send(&service)
        .await;
    assert_eq!(receipt_get.status_code, Some(StatusCode::OK));
    let receipt_body = receipt_get.take_string().await.unwrap();
    assert!(receipt_body.contains("wasmtime-51"));

    let mut po_check = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &viewer_cookie, true)
        .body("SELECT * FROM erp_po:po_088;")
        .send(&service)
        .await;
    let po_body = po_check.take_string().await.unwrap();
    assert!(po_body.contains("Approved") && po_body.contains("po_088-receipt.json"));
}

#[tokio::test]
async fn opt_in_default_mounts_zero_services_and_manifest_compiles_cleanly() {
    use nexus_io::compute::manifest::AppManifest;

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());

    // 1. Default GatewayConfig mounts ONLY probes — zero RPC, S3, Cells, or Web endpoints
    let gw = UxGateway::new(db, blobs, GatewayConfig::default());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    assert_eq!(TestClient::get("http://127.0.0.1/health").send(&service).await.status_code, Some(StatusCode::OK));
    assert_eq!(TestClient::get("http://127.0.0.1/ready").send(&service).await.status_code, Some(StatusCode::OK));
    assert_eq!(TestClient::get("http://127.0.0.1/").send(&service).await.status_code, Some(StatusCode::NOT_FOUND));
    assert_eq!(TestClient::post("http://127.0.0.1/sql").body("RETURN 1;").send(&service).await.status_code, Some(StatusCode::NOT_FOUND));
    assert_eq!(TestClient::get("http://127.0.0.1/s3/b/k").send(&service).await.status_code, Some(StatusCode::NOT_FOUND));
    assert_eq!(TestClient::get("http://127.0.0.1/cells/a/b").send(&service).await.status_code, Some(StatusCode::NOT_FOUND));

    // 2. Authoritative repo `aerea-nexus/nexus.toml` parses, validates, and compiles cleanly
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let manifest_path = repo_root.join("nexus.toml");
    let manifest = AppManifest::from_file(&manifest_path).expect("parse nexus.toml");
    manifest.validate().expect("validate nexus.toml");
    let compiled = manifest.compile_gateway_config(&repo_root).expect("compile nexus.toml");
    assert!(compiled.enable_rpc);
    assert!(compiled.enable_cells);
    assert!(compiled.enable_s3);
    assert!(compiled.enable_web);
    assert!(!compiled.enable_proxy);
    assert_eq!(compiled.web_root.as_deref(), Some(repo_root.join("./shell").as_path()));
    assert_eq!(compiled.dist_root.as_deref(), Some(repo_root.join("./ux/dist").as_path()));

    // 3. Declared missing web root fails fast at compile time (zero silent fallback)
    let bad = AppManifest::from_toml(
        r#"
        api_version = "nexus.io/v1"
        kind = "Application"
        [metadata]
        name = "bad-web"
        version = "0.1.0"
        [gateway.web]
        enabled = true
        root = "./definitely-does-not-exist-99999"
        "#,
    )
    .unwrap();
    assert!(bad.compile_gateway_config(&repo_root).is_err());
}

#[tokio::test]
async fn first_run_bootstrap_iam_admin_and_persisted_wasm_cell_auto_restore() {
    std::env::remove_var("NEXUS_ALLOW_UNAUTH_LOCAL");

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db.clone(), blobs.clone(), GatewayConfig::all_core());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // 1. Fresh empty DB reports initialized = false
    let mut status1 = TestClient::get("http://127.0.0.1/_nexus/setup/status")
        .send(&service)
        .await;
    assert_eq!(status1.status_code, Some(StatusCode::OK));
    let s1: serde_json::Value = serde_json::from_str(&status1.take_string().await.unwrap()).unwrap();
    assert_eq!(s1["initialized"], false);

    // 2. First-run bootstrap creates OWNER admin and sets HttpOnly cookie
    let boot = TestClient::post("http://127.0.0.1/_nexus/setup/bootstrap")
        .json(&serde_json::json!({ "user": "founder", "pass": "founder-pass" }))
        .send(&service)
        .await;
    assert_eq!(boot.status_code, Some(StatusCode::CREATED));
    let owner_cookie = boot
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // 3. Second bootstrap attempt is STRICTLY REJECTED with 403 Forbidden
    let boot2 = TestClient::post("http://127.0.0.1/_nexus/setup/bootstrap")
        .json(&serde_json::json!({ "user": "attacker", "pass": "attacker-pass" }))
        .send(&service)
        .await;
    assert_eq!(boot2.status_code, Some(StatusCode::FORBIDDEN));

    // 4. setup/status now reports initialized = true
    let mut status2 = TestClient::get("http://127.0.0.1/_nexus/setup/status")
        .send(&service)
        .await;
    let s2: serde_json::Value = serde_json::from_str(&status2.take_string().await.unwrap()).unwrap();
    assert_eq!(s2["initialized"], true);

    // 5. OWNER creates a VIEWER via POST /_nexus/iam/users and lists users
    let add_viewer = TestClient::post("http://127.0.0.1/_nexus/iam/users")
        .add_header("cookie", &owner_cookie, true)
        .json(&serde_json::json!({ "user": "viewer1", "pass": "viewer-pass", "role": "VIEWER" }))
        .send(&service)
        .await;
    assert_eq!(add_viewer.status_code, Some(StatusCode::CREATED));

    let mut list_res = TestClient::get("http://127.0.0.1/_nexus/iam/users")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(list_res.status_code, Some(StatusCode::OK));
    let list_json: serde_json::Value = serde_json::from_str(&list_res.take_string().await.unwrap()).unwrap();
    let users = list_json["users"].as_array().unwrap();
    assert_eq!(users.len(), 2);

    // 6. VIEWER is rejected with 403 on GET /_nexus/iam/users
    let viewer_cookie = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "viewer1", "pass": "viewer-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let viewer_admin = TestClient::get("http://127.0.0.1/_nexus/iam/users")
        .add_header("cookie", &viewer_cookie, true)
        .send(&service)
        .await;
    assert_eq!(viewer_admin.status_code, Some(StatusCode::FORBIDDEN));

    // 7. Deploy a WASI cell, then simulate a full process restart (brand-new UxGateway + CellManager)
    //    and confirm the Wasm cell auto-restores on boot and executes cleanly!
    #[cfg(feature = "runtime-wasm")]
    {
        let wat = r#"(module
          (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{\"restored\":true}")
          (func (export "_start")
            (i32.store (i32.const 64) (i32.const 0))
            (i32.store (i32.const 68) (i32.const 17))
            (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 72)))
          )
        )"#;
        let dep = TestClient::put("http://127.0.0.1/cells/erp/echo")
            .add_header("cookie", &owner_cookie, true)
            .add_header("x-nexus-runtime", "wasm", true)
            .body(wat)
            .send(&service)
            .await;
        assert_eq!(dep.status_code, Some(StatusCode::OK));

        // Fresh UxGateway sharing the same durable DB + BlobBridge (simulating nexus.exe restart)
        let gw_restarted = UxGateway::new(db, blobs, GatewayConfig::all_core());
        gw_restarted.reconcile_storage_on_boot().await.unwrap();
        let service2 = Service::new(gw_restarted.router());

        let mut invoke = TestClient::post("http://127.0.0.1/cells/erp/echo")
            .add_header("cookie", &owner_cookie, true)
            .body("{}")
            .send(&service2)
            .await;
        assert_eq!(invoke.status_code, Some(StatusCode::OK));
        let out = invoke.take_string().await.unwrap();
        assert_eq!(out, r#"{"restored":true}"#);

        let mut cells_res = TestClient::get("http://127.0.0.1/_nexus/cells")
            .add_header("cookie", &owner_cookie, true)
            .send(&service2)
            .await;
        assert_eq!(cells_res.status_code, Some(StatusCode::OK));
        let cells_body = cells_res.take_string().await.unwrap();
        assert!(cells_body.contains("echo"));
    }
}

#[tokio::test]
async fn iam_full_user_crud_last_owner_guard_and_record_level_permissions() {
    std::env::remove_var("NEXUS_ALLOW_UNAUTH_LOCAL");

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db, blobs, GatewayConfig::all_core());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // 1. Bootstrap sole OWNER
    let owner_cookie = TestClient::post("http://127.0.0.1/_nexus/setup/bootstrap")
        .json(&serde_json::json!({ "user": "rootadmin", "pass": "root-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // 2. Last-OWNER protection: cannot delete or demote sole OWNER
    let del_sole = TestClient::delete("http://127.0.0.1/_nexus/iam/users/rootadmin")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(del_sole.status_code, Some(StatusCode::BAD_REQUEST));

    let demote_sole = TestClient::put("http://127.0.0.1/_nexus/iam/users/rootadmin")
        .add_header("cookie", &owner_cookie, true)
        .json(&serde_json::json!({ "roles": ["VIEWER"] }))
        .send(&service)
        .await;
    assert_eq!(demote_sole.status_code, Some(StatusCode::BAD_REQUEST));

    // 3. Create user `alice` (VIEWER) -> Edit to EDITOR (preserving password) -> Verify signin -> Delete
    let create_alice = TestClient::post("http://127.0.0.1/_nexus/iam/users")
        .add_header("cookie", &owner_cookie, true)
        .json(&serde_json::json!({ "user": "alice", "pass": "alice-pass", "roles": ["VIEWER"] }))
        .send(&service)
        .await;
    assert_eq!(create_alice.status_code, Some(StatusCode::CREATED));

    let mut edit_alice = TestClient::put("http://127.0.0.1/_nexus/iam/users/alice")
        .add_header("cookie", &owner_cookie, true)
        .json(&serde_json::json!({ "roles": ["EDITOR"] }))
        .send(&service)
        .await;
    assert_eq!(edit_alice.status_code, Some(StatusCode::OK));
    assert!(edit_alice.take_string().await.unwrap().contains("EDITOR"));

    // Sign in as alice with original password -> verify EDITOR role in /_nexus/auth/me
    let alice_cookie = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "alice", "pass": "alice-pass" }))
        .send(&service)
        .await
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut alice_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .add_header("cookie", &alice_cookie, true)
        .send(&service)
        .await;
    assert!(alice_me.take_string().await.unwrap().contains("EDITOR"));

    let del_alice = TestClient::delete("http://127.0.0.1/_nexus/iam/users/alice")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(del_alice.status_code, Some(StatusCode::OK));

    // 4. Apply live record-level PERMISSIONS policy via POST /_nexus/iam/policies/apply
    let mut apply_policy = TestClient::post("http://127.0.0.1/_nexus/iam/policies/apply")
        .add_header("cookie", &owner_cookie, true)
        .json(&serde_json::json!({
            "table": "secret_doc",
            "scope": "table",
            "mode": "where",
            "ops": "select",
            "where_expr": "owner == $auth"
        }))
        .send(&service)
        .await;
    assert_eq!(apply_policy.status_code, Some(StatusCode::OK));
    let policy_body = apply_policy.take_string().await.unwrap();
    assert!(policy_body.contains("DEFINE TABLE secret_doc SCHEMALESS PERMISSIONS FOR select WHERE owner == $auth;"));
}

#[tokio::test]
async fn digit_leading_hex_record_ids_and_html_etag_revalidation() {
    let (site_dir, dist_dir) = repo_site_and_dist();
    let db = Arc::new(Database::open_mem());

    // 1. Digit-leading hex UUIDs (including leading zeros) work seamlessly in CREATE/SELECT/UPDATE/DELETE
    db.inner
        .query_scoped_multi(
            "nexus",
            "system",
            "CREATE erp_po:91faeb111dab45a68ade7037706c1a73 SET status = 'Pending';
             CREATE erp_po:00a1b2c3d4e5f607 SET status = 'Draft';
             UPDATE erp_po:91faeb111dab45a68ade7037706c1a73 SET status = 'Approved';
             UPDATE erp_po:00a1b2c3d4e5f607 SET status = 'Reviewed';",
            vec![],
        )
        .expect("digit-leading hex record IDs must parse and update cleanly");

    let rows = db
        .inner
        .query_scoped_multi(
            "nexus",
            "system",
            "SELECT * FROM erp_po:91faeb111dab45a68ade7037706c1a73; SELECT * FROM erp_po:00a1b2c3d4e5f607;",
            vec![],
        )
        .expect("select digit-leading hex record IDs");
    assert_eq!(rows[0].result.len(), 1);
    assert!(rows[0].result[0].to_json().to_string().contains("Approved"));
    assert_eq!(rows[1].result.len(), 1);
    assert!(rows[1].result[0].to_json().to_string().contains("Reviewed"));

    // 2. HTML partials return ETag + Cache-Control: no-cache + 304 Not Modified on If-None-Match
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(
        db,
        blobs,
        GatewayConfig {
            enable_web: true,
            web_root: Some(site_dir),
            dist_root: Some(dist_dir),
            ..GatewayConfig::default()
        },
    );
    let service = Service::new(gw.router());

    let first = TestClient::get("http://127.0.0.1/_components/layout-profile.html")
        .send(&service)
        .await;
    assert_eq!(first.status_code, Some(StatusCode::OK));
    assert_eq!(
        first.headers().get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-cache")
    );
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("HTML partial must emit ETag")
        .to_string();

    let second = TestClient::get("http://127.0.0.1/_components/layout-profile.html")
        .add_header("if-none-match", &etag, true)
        .send(&service)
        .await;
    assert_eq!(second.status_code, Some(StatusCode::NOT_MODIFIED));
}
