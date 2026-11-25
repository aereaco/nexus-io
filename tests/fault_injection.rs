use nexus_db::auth::{AuthContext, AuthLevel, Role};
use nexus_io::compute::crystal::{CrystalEngine, NexusHostContext, WasiRunConfig};
use nexus_io::compute::wasm_registry::{
    current_aot_compat_key, validate_runtime_name, RuntimeTrustPolicy, TrustMode,
    WasmRuntimeRegistry,
};
use nexus_io::db::sql_compiler::execute_unified_query;
use nexus_io::db::Database;
use nexus_io::iam::capabilities::CapabilitySet;
use nexus_io::js::cell::{
    CellDbConfig, CellDbTransport, CellLifecycleState, CellManager, CellPolicy, CellWorkload,
};
use nexus_io::observability::global_metrics;
use nexus_io::storage::BlobBridge;
use std::sync::Arc;

/// P0.1 Acceptance Test: A user with `VIEWER` permissions cannot write through ANY protocol
/// (direct SQL/unified query, cell query, or WebSocket RPC session), while reads succeed.
#[tokio::test(flavor = "multi_thread")]
async fn viewer_role_cannot_write_across_sql_cell_and_websocket_rpc() {
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let manager = CellManager::new(db.clone(), blobs);

    // Seed data as owner/system
    execute_unified_query(
        &db.inner,
        "acme",
        "prod",
        "surql",
        "CREATE secret:1 SET val = 'protected'",
        vec![],
        None,
    )
    .unwrap();

    let viewer = AuthContext {
        level: AuthLevel::Database("acme".into(), "prod".into()),
        roles: vec![Role::Viewer],
        actor: Some("bob_viewer".into()),
        access_name: None,
        token_claims: None,
    };

    // 1. Unified HTTP/SQL query path: read allowed, write denied
    let read_ok = execute_unified_query(
        &db.inner,
        "acme",
        "prod",
        "surql",
        "SELECT val FROM secret",
        vec![],
        Some(viewer.clone()),
    );
    assert!(read_ok.is_ok());

    let write_denied = execute_unified_query(
        &db.inner,
        "acme",
        "prod",
        "surql",
        "CREATE secret:2 SET val = 'pwned'",
        vec![],
        Some(viewer.clone()),
    );
    assert!(write_denied.is_err(), "VIEWER must not write via unified SQL");

    // 2. CellManager::query_cell path: write denied for VIEWER
    let cell_write_denied = manager
        .query_cell(
            "acme",
            "prod",
            CellDbTransport::HttpRest,
            "surql",
            "DELETE secret:1",
            vec![],
            Some(viewer.clone()),
        )
        .await;
    assert!(cell_write_denied.is_err(), "VIEWER must not delete via cell query");

    // 3. WebSocket RPC session path with propagated `AuthContext`: write denied
    let mut rpc = db.inner.rpc_session("acme", "prod");
    rpc.auth = Some(viewer);
    let rpc_reply = rpc.handle_json(
        r#"{"id":1,"method":"query","params":["CREATE secret:3 SET val = 'ws_pwned'"]}"#,
    );
    assert!(
        rpc_reply.contains("\"error\""),
        "VIEWER must not write over WebSocket RPC, got: {}",
        rpc_reply
    );
}

/// P0.3 Adversarial Guest Test: A malicious WASI guest with a read-only `CapabilitySet`
/// attempting mutating SQL (`CREATE`) or `nexus_blob_put` is denied (`-2`) at the host ABI.
#[tokio::test(flavor = "multi_thread")]
async fn malicious_wasi_guest_cannot_bypass_effective_capabilities() {
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());

    // Guest tries to execute a mutating `CREATE` query via `nexus_db_query` and writes return code to stdout
    let hostile_wat = br#"
        (module
            (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (import "nexus_host" "nexus_db_query"
                (func $db_query (param i32 i32 i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 32) "surql")
            (data (i32.const 64) "CREATE evil:1 SET x = 1")
            (data (i32.const 128) "DENIED")
            (data (i32.const 140) "ALLOWED")
            (func (export "_start")
                (local $rc i32)
                (local.set $rc
                    (call $db_query
                        (i32.const 32) (i32.const 5)
                        (i32.const 64) (i32.const 23)
                        (i32.const 256) (i32.const 256)))
                (if (i32.eq (local.get $rc) (i32.const -2))
                    (then
                        (i32.store (i32.const 0) (i32.const 128))
                        (i32.store (i32.const 4) (i32.const 6))
                        (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                    )
                    (else
                        (i32.store (i32.const 0) (i32.const 140))
                        (i32.store (i32.const 4) (i32.const 7))
                        (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                    )
                )
            )
        )
    "#;

    let ro_host = NexusHostContext::new(
        "acme",
        "ro_cell",
        CellDbConfig::dedicated_full(),
        db,
        blobs,
    )
    .with_capabilities(CapabilitySet::read_only_cell());

    let out = tokio::task::spawn_blocking(move || {
        let crystal = CrystalEngine::new().unwrap();
        crystal
            .run_wasi_with_host(hostile_wat, WasiRunConfig::default(), ro_host)
            .unwrap()
    })
    .await
    .unwrap();

    assert_eq!(String::from_utf8_lossy(&out.stdout), "DENIED");
    assert!(global_metrics().snapshot().iam_auth_denials >= 1);
}

/// P1.1 & P1.2 Fault-Injection Test: Cell lifecycle state transitions, stolen lease failure,
/// runtime name validation, immutable version enforcement, uninstall/reinstall, and AOT compat key.
#[tokio::test(flavor = "multi_thread")]
async fn cell_lifecycle_lease_conflict_and_runtime_trust_policy() {
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let manager = CellManager::new(db, blobs.clone());

    // 1. Cell lifecycle state transitions: Declared -> Running -> Hibernated -> Running
    assert_eq!(
        manager.cell_state("app1", "c1").await,
        CellLifecycleState::Declared
    );
    manager
        .wake_workload(
            "app1",
            "c1",
            CellPolicy::elastic_default(),
            CellWorkload::WasiModule {
                module_bytes: vec![],
                args: vec![],
                env: vec![],
                preopen_dirs: vec![],
                fuel_limit: 100_000,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        manager.cell_state("app1", "c1").await,
        CellLifecycleState::Running
    );
    manager.hibernate("app1", "c1").await.unwrap();
    assert_eq!(
        manager.cell_state("app1", "c1").await,
        CellLifecycleState::Hibernated
    );

    // Simulate stolen/pre-held lease on another node -> wake must transition to Failed
    blobs
        .put_object(
            "nexus-cells",
            "leases/app1/c1.lease",
            bytes::Bytes::from_static(b"owner:remote_node"),
        )
        .await
        .unwrap();
    assert!(manager.ensure_awake("app1", "c1").await.is_err());
    assert!(matches!(
        manager.cell_state("app1", "c1").await,
        CellLifecycleState::Failed(_)
    ));

    // 2. Runtime registry name validation, immutable versions, AOT compat key, and uninstall
    assert!(validate_runtime_name("../escape").is_err());
    assert!(validate_runtime_name("bad/name").is_err());
    assert!(validate_runtime_name("quickjs-1.0_beta").is_ok());

    let reg = WasmRuntimeRegistry::new(blobs.clone());
    reg.set_trust_policy(RuntimeTrustPolicy {
        mode: TrustMode::AllowlistOnly,
        allowed_registries: vec!["ghcr.io".to_string()],
        immutable_versions: true,
    })
    .await;

    let v1 = br#"(module (func (export "_start")))"#;
    let v2 = br#"(module (func (export "_start") nop))"#;
    let r1 = reg.register_runtime("quickjs-v1", v1).await.unwrap();
    assert_eq!(r1.aot_compat.as_deref(), Some(current_aot_compat_key().as_str()));

    // Overwriting an immutable runtime with different bytes must be rejected
    assert!(reg.register_runtime("quickjs-v1", v2).await.is_err());

    // Explicit uninstall allows clean reinstallation
    assert!(reg.uninstall_runtime("quickjs-v1").await.unwrap());
    let r2 = reg.register_runtime("quickjs-v1", v2).await.unwrap();
    assert_ne!(r1.cid, r2.cid);

    // 3. Persistent CellDbConfig survives full CellManager restart
    manager
        .set_db_config("billing", "ledger", CellDbConfig::stateless())
        .await
        .unwrap();
    let fresh_db = Arc::new(Database::open_mem());
    let fresh_mgr = CellManager::new(fresh_db, blobs);
    let restored_cfg = fresh_mgr.get_db_config("billing", "ledger").await;
    assert_eq!(
        restored_cfg.mode,
        nexus_io::js::cell::CellDbMode::None,
        "CellDbConfig must persist across CellManager restarts"
    );
}

/// Startup Invariant Test: Proves `UxGateway` blocks cell traffic with `503 Service Unavailable`
/// until `reconcile_storage_on_boot()` replays pending write-ahead `OwnershipTx` journals durably.
#[tokio::test(flavor = "multi_thread")]
async fn boot_recovery_gates_cell_work_and_replays_wal_on_startup() {
    use nexus_io::storage::cas_store::{CasStore, OwnershipTx};
    use nexus_io::ux::{GatewayConfig, UxGateway};
    use salvo::test::TestClient;
    use salvo::Service;

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let cas = CasStore::new(blobs.clone());

    // Seed an uncommitted write-ahead OwnershipTx in `nexus-wasm-db` (simulating prior crash)
    let live_cid = cas
        .put_verified_blob("nexus-wasm-db", "blobs/", bytes::Bytes::from_static(b"v1-live"))
        .await
        .unwrap();
    let aborted_cid = cas
        .put_verified_blob("nexus-wasm-db", "blobs/", bytes::Bytes::from_static(b"v2-aborted"))
        .await
        .unwrap();
    cas.acquire_owners_batch("nexus-wasm-db", "wasmdb:demo/c1", &[live_cid.clone()])
        .await
        .unwrap();
    cas.commit_manifest_cas(
        "nexus-wasm-db",
        "cells/demo/c1/manifest.json",
        &serde_json::json!({"manifest": {"version": 1}}),
        None,
    )
    .await
    .unwrap();
    cas.begin_ownership_tx(
        "nexus-wasm-db",
        &OwnershipTx {
            tx_id: "boot-wal-1".into(),
            owner_id: "wasmdb:demo/c1".into(),
            target_manifest_key: "cells/demo/c1/manifest.json".into(),
            target_version: 2,
            acquired_cids: vec![aborted_cid.clone()],
            prev_cids: vec![live_cid.clone()],
            created_at_ms: 1,
        },
    )
    .await
    .unwrap();
    cas.acquire_owners_batch("nexus-wasm-db", "wasmdb:demo/c1", &[aborted_cid.clone()])
        .await
        .unwrap();

    let gw = UxGateway::new(db.clone(), blobs.clone(), GatewayConfig::default());
    assert!(!gw.is_storage_ready());
    let service = Service::new(gw.router());

    // 1. BEFORE boot recovery completes:
    //    - `/health` (liveness) MUST return 200 OK
    //    - `/ready` (readiness) MUST return 503 Service Unavailable
    //    - EVERY storage-dependent route (`/cells/*`, `/cells/*/query`, `/s3/*`, `/query`,
    //      `/sql`, `/rpc`, `/key/*`, `/api/*`) MUST fail closed with 503 Service Unavailable!
    let health_pre = TestClient::get("http://127.0.0.1/health").send(&service).await;
    assert_eq!(health_pre.status_code, Some(salvo::http::StatusCode::OK));
    let ready_pre = TestClient::get("http://127.0.0.1/ready").send(&service).await;
    assert_eq!(ready_pre.status_code, Some(salvo::http::StatusCode::SERVICE_UNAVAILABLE));

    for (method, path) in [
        ("GET", "http://127.0.0.1/cells/demo/c1"),
        ("POST", "http://127.0.0.1/cells/demo/c1/query"),
        ("GET", "http://127.0.0.1/s3/bucket/key"),
        ("POST", "http://127.0.0.1/query"),
        ("POST", "http://127.0.0.1/sql"),
        ("POST", "http://127.0.0.1/rpc"),
        ("GET", "http://127.0.0.1/key/users"),
        ("GET", "http://127.0.0.1/api/ns1/db1/items"),
    ] {
        let resp = if method == "POST" {
            TestClient::post(path).send(&service).await
        } else {
            TestClient::get(path).send(&service).await
        };
        assert_eq!(
            resp.status_code,
            Some(salvo::http::StatusCode::SERVICE_UNAVAILABLE),
            "Route {} {} must fail closed with 503 before boot recovery completes",
            method,
            path
        );
    }

    // 2. Run startup boot reconciliation (same path invoked at top of `UxGateway::start()`)
    let (db_rep, _rt_rep) = gw.reconcile_storage_on_boot().await.unwrap();
    assert_eq!(db_rep.tx_replayed, 1);
    assert!(gw.is_storage_ready());
    assert!(cas.get_verified_blob("nexus-wasm-db", "blobs/", &live_cid).await.is_ok());
    assert!(cas.get_verified_blob("nexus-wasm-db", "blobs/", &aborted_cid).await.is_err());
    assert!(blobs.list_objects("nexus-wasm-db", Some("tx/")).await.unwrap().is_empty());

    // 3. AFTER boot recovery completes:
    //    - `/ready` returns 200 OK
    //    - All storage-dependent routes pass the boot gate (reaching IAM -> 401 Unauthorized)
    let ready_post = TestClient::get("http://127.0.0.1/ready").send(&service).await;
    assert_eq!(ready_post.status_code, Some(salvo::http::StatusCode::OK));
    for (method, path) in [
        ("GET", "http://127.0.0.1/cells/demo/c1"),
        ("POST", "http://127.0.0.1/cells/demo/c1/query"),
        ("GET", "http://127.0.0.1/s3/bucket/key"),
        ("POST", "http://127.0.0.1/query"),
        ("POST", "http://127.0.0.1/sql"),
        ("POST", "http://127.0.0.1/rpc"),
        ("GET", "http://127.0.0.1/key/users"),
        ("GET", "http://127.0.0.1/api/ns1/db1/items"),
    ] {
        let resp = if method == "POST" {
            TestClient::post(path).send(&service).await
        } else {
            TestClient::get(path).send(&service).await
        };
        assert_eq!(
            resp.status_code,
            Some(salvo::http::StatusCode::UNAUTHORIZED),
            "Route {} {} must pass boot gate and reach IAM after recovery",
            method,
            path
        );
    }
}

/// Multi-Node Adversarial Test A & B:
/// A. Two independent `CasStore` nodes race `reconcile_on_boot()` simultaneously on the same pending
///    `OwnershipTx` — proving zero double-decrement, live CID preservation, and idempotent convergence.
/// B. A live writer persists `OwnershipTx` and writes a new immutable blob BEFORE acquiring ownership,
///    while a second node runs full `gc_unreferenced_blobs()` concurrently — proving the active
///    write-ahead journal protects in-flight blobs while genuinely abandoned garbage IS reclaimed.
#[tokio::test(flavor = "multi_thread")]
async fn multi_node_concurrent_recovery_and_gc_vs_live_writer() {
    use nexus_io::storage::cas_store::{CasStore, OwnershipTx};
    use std::collections::HashSet;

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db).await.unwrap());

    // --- Part A: Simultaneous Recovery Race ---
    let node_a = CasStore::new(blobs.clone());
    let node_b = CasStore::new(blobs.clone());

    let live_cid = node_a
        .put_verified_blob("mn-race", "blobs/", bytes::Bytes::from_static(b"mn-live-v1"))
        .await
        .unwrap();
    let aborted_cid = node_a
        .put_verified_blob("mn-race", "blobs/", bytes::Bytes::from_static(b"mn-abort-v2"))
        .await
        .unwrap();
    node_a
        .acquire_owners_batch("mn-race", "wasmdb:app/c1", &[live_cid.clone()])
        .await
        .unwrap();
    node_a
        .commit_manifest_cas(
            "mn-race",
            "cells/app/c1/manifest.json",
            &serde_json::json!({"manifest": {"version": 1}}),
            None,
        )
        .await
        .unwrap();
    node_a
        .begin_ownership_tx(
            "mn-race",
            &OwnershipTx {
                tx_id: "race-tx-1".into(),
                owner_id: "wasmdb:app/c1".into(),
                target_manifest_key: "cells/app/c1/manifest.json".into(),
                target_version: 2,
                acquired_cids: vec![aborted_cid.clone()],
                prev_cids: vec![live_cid.clone()],
                created_at_ms: 1,
            },
        )
        .await
        .unwrap();
    node_a
        .acquire_owners_batch("mn-race", "wasmdb:app/c1", &[aborted_cid.clone()])
        .await
        .unwrap();

    // Both nodes boot and reconcile the exact same bucket simultaneously
    let empty = HashSet::new();
    let (res_a, res_b) = tokio::join!(
        node_a.reconcile_on_boot("mn-race", "blobs/", &empty, 0, false),
        node_b.reconcile_on_boot("mn-race", "blobs/", &empty, 0, false),
    );
    assert!(res_a.is_ok(), "node_a recovery failed: {:?}", res_a);
    assert!(res_b.is_ok(), "node_b recovery failed: {:?}", res_b);
    assert!(node_a.get_verified_blob("mn-race", "blobs/", &live_cid).await.is_ok());
    assert!(node_a.get_verified_blob("mn-race", "blobs/", &aborted_cid).await.is_err());
    assert!(blobs.list_objects("mn-race", Some("tx/")).await.unwrap().is_empty());
    // Repeating recovery converges idempotently
    let repeat = node_b
        .reconcile_on_boot("mn-race", "blobs/", &empty, 0, false)
        .await
        .unwrap();
    assert!(repeat.skipped);

    // --- Part B: Concurrent Full Orphan GC vs. Live Writer ---
    let writer = CasStore::new(blobs.clone());
    let gc_node = CasStore::new(blobs.clone());

    // Genuine unowned garbage blob (no ledger entry, no OwnershipTx)
    let garbage_cid = writer
        .put_verified_blob("mn-gc", "blobs/", bytes::Bytes::from_static(b"true-orphan-garbage"))
        .await
        .unwrap();

    // Live writer follows WAL-before-blob order: persists OwnershipTx BEFORE uploading in-flight blob
    let inflight_bytes = bytes::Bytes::from_static(b"live-writer-inflight-blob");
    let inflight_cid = blake3::hash(&inflight_bytes).to_hex().to_string();
    writer
        .begin_ownership_tx(
            "mn-gc",
            &OwnershipTx {
                tx_id: "live-inflight-1".into(),
                owner_id: "wasmdb:app/c2".into(),
                target_manifest_key: "cells/app/c2/manifest.json".into(),
                target_version: 1,
                acquired_cids: vec![inflight_cid.clone()],
                prev_cids: vec![],
                created_at_ms: 1,
            },
        )
        .await
        .unwrap();
    writer
        .put_verified_blob("mn-gc", "blobs/", inflight_bytes)
        .await
        .unwrap();

    // BEFORE writer acquires ownership or commits manifest, gc_node runs a full orphan GC scan!
    let reclaimed = gc_node
        .gc_unreferenced_blobs("mn-gc", "blobs/", &empty)
        .await
        .unwrap();
    assert_eq!(reclaimed, 1, "GC must reclaim only genuine unowned garbage");
    assert!(writer.get_verified_blob("mn-gc", "blobs/", &garbage_cid).await.is_err());
    assert!(
        writer.get_verified_blob("mn-gc", "blobs/", &inflight_cid).await.is_ok(),
        "Concurrent orphan GC MUST NOT delete a live writer's WAL-protected in-flight blob!"
    );
}

/// Isolated Guest AOT `.cwasm` Instantiation & Execution Micro-Benchmark (200 samples: p50/p95/min/max).
#[test]
fn aot_guest_instantiation_latency_benchmark() {
    let crystal = CrystalEngine::new().unwrap();
    let wat = br#"(module (func (export "add") (param i64 i64) (result i64) local.get 0 local.get 1 i64.add))"#;
    let cwasm = crystal.compile_aot(wat).unwrap();

    let mut samples_us = Vec::with_capacity(200);
    for i in 0..200i64 {
        let t0 = std::time::Instant::now();
        let res = crystal.run_aot_i64(&cwasm, "add", i, 42, 100_000).unwrap();
        let elapsed_us = t0.elapsed().as_micros();
        assert_eq!(res, i + 42);
        samples_us.push(elapsed_us);
    }
    samples_us.sort_unstable();
    let p50 = samples_us[samples_us.len() / 2];
    let p95 = samples_us[(samples_us.len() * 95) / 100];
    let min = samples_us[0];
    let max = *samples_us.last().unwrap();
    println!(
        "AOT_MICROBENCH_US n={} p50={} p95={} min={} max={}",
        samples_us.len(),
        p50,
        p95,
        min,
        max
    );
}

/// End-to-End Guest Invocation Benchmark (cold AOT rebuild vs. warm NXAOT01 cache hit + WASI + DB)
/// AND 20-Cell Concurrent Isolated Workload Benchmark (mixed reads/writes + correctness verification).
#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_guest_and_concurrent_20_cell_workload_benchmark() {
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let reg = WasmRuntimeRegistry::new(blobs.clone());

    // Minimal WASI guest calling `nexus_host::nexus_db_query` (full host-ABI roundtrip)
    let guest_wat = br#"
        (module
            (import "nexus_host" "nexus_db_query" (func $db_q (param i32 i32 i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 2)
            (data (i32.const 0) "surql")
            (data (i32.const 16) "SELECT * FROM bench;")
            (func (export "_start")
                (local $n i32)
                (local.set $n (call $db_q (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 20) (i32.const 256) (i32.const 4096)))
                (i32.store (i32.const 128) (i32.const 256))
                (i32.store (i32.const 132) (local.get $n))
                (drop (call $fd_write (i32.const 1) (i32.const 128) (i32.const 1) (i32.const 140)))
            )
        )
    "#;
    let rec = reg.register_runtime("bench-guest", guest_wat).await.unwrap();
    let compat = current_aot_compat_key();
    let aot_key = format!("aot-cid/{}/{}.cwasm", compat, rec.cid);

    // 1. Cold-cache end-to-end (delete AOT cache -> BLAKE3 source verify -> compile -> WASI + DB)
    blobs.delete_object("nexus-runtimes", &aot_key).await.unwrap();
    let t_cold = std::time::Instant::now();
    let cold_art = reg.resolve_runtime("bench-guest").await.unwrap();
    let cold_bytes = match cold_art {
        nexus_io::compute::wasm_registry::ResolvedRuntime::Aot(b) => b,
        _ => panic!("expected AOT"),
    };
    let db_c = db.clone();
    let blobs_c = blobs.clone();
    let out_cold = tokio::task::spawn_blocking(move || {
        let crystal = CrystalEngine::new().unwrap();
        let host = NexusHostContext::new(
            "bench_app",
            "cold_cell",
            CellDbConfig::dedicated_full(),
            db_c,
            blobs_c,
        );
        crystal
            .run_wasi_aot_with_host(&cold_bytes, WasiRunConfig::default(), host)
            .unwrap()
    })
    .await
    .unwrap();
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(out_cold.exit_code, 0);

    // 2. Warm-cache end-to-end (25 runs: NXAOT01 BLAKE3 verify -> WASI + nexus_host DB query)
    let mut warm_us = Vec::with_capacity(25);
    for _ in 0..25 {
        let t0 = std::time::Instant::now();
        let art = reg.resolve_runtime("bench-guest").await.unwrap();
        let bytes = match art {
            nexus_io::compute::wasm_registry::ResolvedRuntime::Aot(b) => b,
            _ => panic!("expected AOT"),
        };
        let db_w = db.clone();
        let blobs_w = blobs.clone();
        let out = tokio::task::spawn_blocking(move || {
            let crystal = CrystalEngine::new().unwrap();
            let host = NexusHostContext::new(
                "bench_app",
                "warm_cell",
                CellDbConfig::dedicated_full(),
                db_w,
                blobs_w,
            );
            crystal
                .run_wasi_aot_with_host(&bytes, WasiRunConfig::default(), host)
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(out.exit_code, 0);
        warm_us.push(t0.elapsed().as_micros());
    }
    warm_us.sort_unstable();
    println!(
        "E2E_GUEST_BENCH cold_ms={:.2} warm_p50_us={} warm_p95_us={} warm_min_us={} warm_max_us={}",
        cold_ms,
        warm_us[warm_us.len() / 2],
        warm_us[(warm_us.len() * 95) / 100],
        warm_us[0],
        warm_us[warm_us.len() - 1]
    );

    // 3. 20 Concurrent Cells with Isolated State (mixed writes + reads + strict isolation check)
    let t_conc = std::time::Instant::now();
    let mut handles = Vec::with_capacity(20);
    for cell_idx in 0..20usize {
        let db_i = db.clone();
        handles.push(tokio::spawn(async move {
            let cell_name = format!("cell_{}", cell_idx);
            let mut lat_us = Vec::with_capacity(10);
            for op in 0..10usize {
                let t0 = std::time::Instant::now();
                let q = format!(
                    "CREATE items SET cell = {}, seq = {}; SELECT * FROM items WHERE cell = {};",
                    cell_idx, op, cell_idx
                );
                let rows = db_i
                    .inner
                    .query_scoped("conc_bench", &cell_name, &q, vec![])
                    .unwrap();
                assert!(!rows.is_empty());
                lat_us.push(t0.elapsed().as_micros());
            }
            // Verify strict isolation: cell_i sees exactly 10 rows, none from other cells
            let check = db_i
                .inner
                .query_scoped("conc_bench", &cell_name, "SELECT * FROM items;", vec![])
                .unwrap();
            let count = if check.len() == 1 {
                match &check[0] {
                    nexus_db::Value::Array(arr) => arr.len(),
                    _ => 1,
                }
            } else {
                check.len()
            };
            assert_eq!(count, 10, "Cell {} isolation violation: expected 10 rows, got {}", cell_name, count);
            lat_us
        }));
    }
    let mut all_lat = Vec::with_capacity(200);
    for h in handles {
        all_lat.extend(h.await.unwrap());
    }
    let total_secs = t_conc.elapsed().as_secs_f64();
    all_lat.sort_unstable();
    let ops_per_sec = (all_lat.len() as f64) / total_secs.max(0.0001);
    println!(
        "CONCURRENT_20_CELLS ops={} failures=0 ops_per_sec={:.1} p50_us={} p95_us={}",
        all_lat.len(),
        ops_per_sec,
        all_lat[all_lat.len() / 2],
        all_lat[(all_lat.len() * 95) / 100]
    );
}

/// Declarative Control-Plane API & Fenced Stateful Migration Integration Test:
/// 1. `POST /_nexus/deploy` fails closed (`503`) before boot recovery.
/// 2. `VIEWER` cannot deploy (`403 Forbidden`), while `OWNER` deploys TOML `AppManifest` (`202 Accepted`),
///    and `GET /_nexus/deploy/{op_id}` + `GET /_nexus/apps/{app_id}` return durable CAS records.
/// 3. Stateful cell `fenced_checkpoint` migration from Node A -> Node B advances monotonic
///    `fencing_token` and rejects stale Node A commits.
#[tokio::test(flavor = "multi_thread")]
async fn declarative_manifest_control_plane_and_fenced_stateful_migration() {
    use nexus_io::storage::cas_store::CasStore;
    use nexus_io::ux::{GatewayConfig, UxGateway};
    use salvo::test::{ResponseExt, TestClient};
    use salvo::Service;

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db.clone(), blobs.clone(), GatewayConfig::default());
    let service = Service::new(gw.router());

    let cid = format!("blake3:{}", "b".repeat(64));
    let manifest_toml = format!(
        r#"
api_version = "nexus.io/v1"
kind = "Application"

[metadata]
name = "billing"
version = "1.0.0"

[topology]
mode = "modular"

[cells.ledger]
artifact = "{cid}"
replicas = 1
migration = "fenced_checkpoint"

[cells.ledger.database]
mode = "dedicated"
flavors = ["surql"]
transports = ["internal"]

[cells.ledger.capabilities]
allow = ["db.read", "db.write"]
"#
    );

    // 1. Pre-recovery: /_nexus/deploy MUST return 503 Service Unavailable
    let pre = TestClient::post("http://127.0.0.1/_nexus/deploy")
        .text(manifest_toml.clone())
        .send(&service)
        .await;
    assert_eq!(pre.status_code, Some(salvo::http::StatusCode::SERVICE_UNAVAILABLE));

    gw.reconcile_storage_on_boot().await.unwrap();

    // Provision VIEWER and OWNER tokens via real Nexus-DB IAM + HTTP `/signin`
    db.inner
        .query_scoped(
            "nexus",
            "system",
            "DEFINE USER viewer_u ON ROOT PASSWORD 'secret' ROLES VIEWER; DEFINE USER owner_u ON ROOT PASSWORD 'secret' ROLES OWNER;",
            vec![],
        )
        .unwrap();
    let mut sv = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "viewer_u", "pass": "secret" }))
        .send(&service)
        .await;
    let viewer_tok = sv.take_json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut so = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "owner_u", "pass": "secret" }))
        .send(&service)
        .await;
    let owner_tok = so.take_json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. VIEWER is denied (403 Forbidden - lacks `cell.spawn`)
    let r_viewer = TestClient::post("http://127.0.0.1/_nexus/deploy")
        .add_header("Authorization", format!("Bearer {}", viewer_tok), true)
        .text(manifest_toml.clone())
        .send(&service)
        .await;
    assert_eq!(r_viewer.status_code, Some(salvo::http::StatusCode::FORBIDDEN));

    // 3. OWNER deploys cleanly -> 202 Accepted + durable operation & app records
    let mut r_owner = TestClient::post("http://127.0.0.1/_nexus/deploy")
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .text(manifest_toml)
        .send(&service)
        .await;
    assert_eq!(r_owner.status_code, Some(salvo::http::StatusCode::ACCEPTED));
    let op_json: serde_json::Value = r_owner.take_json().await.unwrap();
    let op_id = op_json["operation_id"].as_str().unwrap();
    assert_eq!(op_json["status"], "succeeded");

    let mut r_op = TestClient::get(format!("http://127.0.0.1/_nexus/deploy/{}", op_id))
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .send(&service)
        .await;
    assert_eq!(r_op.status_code, Some(salvo::http::StatusCode::OK));
    let op_fetched: serde_json::Value = r_op.take_json().await.unwrap();
    assert_eq!(op_fetched["app_name"], "billing");

    let mut r_app = TestClient::get("http://127.0.0.1/_nexus/apps/billing")
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .send(&service)
        .await;
    assert_eq!(r_app.status_code, Some(salvo::http::StatusCode::OK));
    let app_rec: serde_json::Value = r_app.take_json().await.unwrap();
    assert_eq!(app_rec["cells"]["ledger"]["migration_policy"], "fenced_checkpoint");

    // 4. Stateful `fenced_checkpoint` migration handoff (Node A -> Node B):
    //    Node A acquires token 1, checkpoints state & releases lease;
    //    Node B acquires monotonic token 2; Node A's stale token 1 renewal MUST be fenced out!
    let cas_a = CasStore::new(blobs.clone());
    let cas_b = CasStore::new(blobs.clone());
    let lease_a = cas_a
        .acquire_execution_lease("nexus-deployments", "leases/billing/ledger.json", "node-a", 30_000)
        .await
        .unwrap();
    assert_eq!(lease_a.fencing_token, 1);
    // Node A checkpoints and cleanly releases lease for migration
    assert!(cas_a
        .release_execution_lease(
            "nexus-deployments",
            "leases/billing/ledger.json",
            "node-a",
            lease_a.fencing_token
        )
        .await
        .unwrap());
    // Node B takes ownership with monotonic fencing_token = 2
    let lease_b = cas_b
        .acquire_execution_lease("nexus-deployments", "leases/billing/ledger.json", "node-b", 30_000)
        .await
        .unwrap();
    assert_eq!(lease_b.fencing_token, 2);
    // Stale Node A renewal MUST be rejected by fencing!
    assert!(cas_a
        .renew_execution_lease(
            "nexus-deployments",
            "leases/billing/ledger.json",
            "node-a",
            lease_a.fencing_token,
            30_000
        )
        .await
        .is_err());
}
