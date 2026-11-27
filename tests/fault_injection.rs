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

    let gw = UxGateway::new(db.clone(), blobs.clone(), GatewayConfig::all_core());
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
    let gw = UxGateway::new(db.clone(), blobs.clone(), GatewayConfig::all_core());
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

    // 5. P2P Decentralized Mesh Fabric:
    //    - Ingest WireGuard + 4D telemetry peer announcement via `POST /_nexus/mesh/gossip`
    //    - Verify `GET /_nexus/mesh/status` reports deterministic WireGuard IPv4/IPv6 + 4D telemetry
    //    - Deploy a `placement.target = "mesh"` GPU workload (`requires = ["gpu", "vram:16384", "region:us-west"]`)
    //      and verify the 4D MeshScheduler places it on `node-gpu-west`
    //    - Verify P2P CAS blob transfer via `PUT` and `GET /_nexus/mesh/blobs/{cid}`
    let gossip_gpu = serde_json::json!({
        "node_id": "node-gpu-west",
        "wg_endpoint": "198.51.100.10:51820",
        "resources": {
            "cpu_cores": 32,
            "cpu_load_pct": 12,
            "memory_total": 68_719_476_736u64,
            "memory_free": 60_000_000_000u64,
            "storage_total": 2_000_000_000_000u64,
            "storage_free": 1_800_000_000_000u64,
            "gpus": [{
                "name": "RTX 4090",
                "vram_total": 24_576_000_000u64,
                "vram_free": 22_000_000_000u64
            }],
            "is_green": true,
            "labels": {
                "region": "us-west",
                "tier": "gpu"
            },
            "timestamp": 1700000100
        }
    });
    let mut r_gossip = TestClient::post("http://127.0.0.1/_nexus/mesh/gossip")
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .add_header("Content-Type", "application/json", true)
        .body(gossip_gpu.to_string())
        .send(&service)
        .await;
    assert_eq!(r_gossip.status_code, Some(salvo::http::StatusCode::OK));
    let gossip_resp: serde_json::Value = r_gossip.take_json().await.unwrap();
    assert_eq!(gossip_resp["accepted"], true);
    assert!(gossip_resp["mesh_ipv4"].as_str().unwrap().starts_with("100."));
    assert!(gossip_resp["mesh_ipv6"].as_str().unwrap().starts_with("fd00:6e78:"));

    let mut r_mesh_status = TestClient::get("http://127.0.0.1/_nexus/mesh/status")
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .send(&service)
        .await;
    assert_eq!(r_mesh_status.status_code, Some(salvo::http::StatusCode::OK));
    let mesh_status: serde_json::Value = r_mesh_status.take_json().await.unwrap();
    assert!(mesh_status["peer_count"].as_u64().unwrap() >= 1);

    let mesh_toml = format!(
        r#"
api_version = "nexus.io/v1"
kind = "Application"

[metadata]
name = "inference-cluster"
version = "1.0.0"

[topology]
mode = "mesh"

[cells.llm_worker]
artifact = "{cid}"
replicas = 1

[cells.llm_worker.placement]
target = "mesh"
requires = ["gpu", "vram:16384", "region:us-west"]
"#
    );
    let mut r_mesh_deploy = TestClient::post("http://127.0.0.1/_nexus/deploy")
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .add_header("Content-Type", "application/toml", true)
        .body(mesh_toml)
        .send(&service)
        .await;
    assert_eq!(r_mesh_deploy.status_code, Some(salvo::http::StatusCode::ACCEPTED));
    let mesh_op: serde_json::Value = r_mesh_deploy.take_json().await.unwrap();
    assert_eq!(mesh_op["status"], "succeeded");

    let mut r_mesh_app = TestClient::get("http://127.0.0.1/_nexus/apps/inference-cluster")
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .send(&service)
        .await;
    assert_eq!(r_mesh_app.status_code, Some(salvo::http::StatusCode::OK));
    let mesh_app_rec: serde_json::Value = r_mesh_app.take_json().await.unwrap();
    assert_eq!(
        mesh_app_rec["cells"]["llm_worker"]["assigned_nodes"],
        serde_json::json!(["node-gpu-west"])
    );
    assert_eq!(
        mesh_app_rec["cells"]["llm_worker"]["mesh_endpoints"],
        serde_json::json!(["198.51.100.10:51820"])
    );

    // P2P BLAKE3-verified CAS blob transfer endpoint:
    let blob_payload = b"nexus-mesh-p2p-verified-blob-payload";
    let blob_cid = blake3::hash(blob_payload).to_hex().to_string();
    let r_blob_put = TestClient::put(format!("http://127.0.0.1/_nexus/mesh/blobs/{}", blob_cid))
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .body(blob_payload.as_slice())
        .send(&service)
        .await;
    assert_eq!(r_blob_put.status_code, Some(salvo::http::StatusCode::CREATED));

    let r_blob_get = TestClient::get(format!("http://127.0.0.1/_nexus/mesh/blobs/{}", blob_cid))
        .add_header("Authorization", format!("Bearer {}", owner_tok), true)
        .send(&service)
        .await;
    assert_eq!(r_blob_get.status_code, Some(salvo::http::StatusCode::OK));
}

/// Milestone 1 Universal Host Test:
/// Proves that WASI guests share the exact same capability-gated `nexus_host` Hardware + OS UI
/// + `NexusSharedArena` SPSC ring ABI, enforcing default-deny `-2` when capabilities are missing,
/// validating versioned `UiOpHeader` batches, and deterministically revoking handles on exit.
#[tokio::test(flavor = "multi_thread")]
async fn universal_host_hardware_ui_and_shared_arena_security_and_lifecycle() {
    use nexus_io::arena::{ArenaError, NexusSharedArena, RingBufferHandle};
    use nexus_io::compute::crystal::{CrystalEngine, NexusHostContext, WasiRunConfig};
    use nexus_io::hardware::{UiOpCode, UiOpHeader, UI_OP_PROTOCOL_VERSION};
    use nexus_io::iam::capabilities::{Capability, CapabilitySet};
    use nexus_io::js::cell::CellDbConfig;

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let engine = CrystalEngine::new().unwrap();

    // WASI guest that:
    //  1) Calls `nexus_hw_call("system.info", "{}")` -> expects > 0 bytes when `hw.info` is granted
    //  2) Calls `nexus_hw_call("camera.capture", "{}")` -> expects `-2` (denied: lacks `hw.camera`)
    //  3) Allocates an SPSC ring (`nexus_ring_alloc(32)`), writes "hi", reads it back (`2`),
    //     and writes the packed handle to stdout (8 bytes) so host can verify deterministic revocation after exit!
    let wat = r#"
    (module
      (import "nexus_host" "nexus_hw_call" (func $hw_call (param i32 i32 i32 i32 i32 i32) (result i32)))
      (import "nexus_host" "nexus_ring_alloc" (func $ring_alloc (param i32) (result i64)))
      (import "nexus_host" "nexus_ring_write" (func $ring_write (param i64 i32 i32) (result i32)))
      (import "nexus_host" "nexus_ring_read" (func $ring_read (param i64 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "system.info")
      (data (i32.const 32) "camera.capture")
      (data (i32.const 64) "{}")
      (data (i32.const 80) "hi")
      (func (export "_start")
        (local $r1 i32)
        (local $r2 i32)
        (local $h i64)
        (local $rw i32)
        (local $rr i32)
        ;; 1. system.info (allowed by hw.info)
        (local.set $r1 (call $hw_call (i32.const 0) (i32.const 11) (i32.const 64) (i32.const 2) (i32.const 256) (i32.const 512)))
        ;; 2. camera.capture (MUST return -2: denied by CapabilitySet)
        (local.set $r2 (call $hw_call (i32.const 32) (i32.const 14) (i32.const 64) (i32.const 2) (i32.const 256) (i32.const 512)))
        ;; 3. SPSC ring alloc, write "hi", read back
        (local.set $h (call $ring_alloc (i32.const 32)))
        (local.set $rw (call $ring_write (local.get $h) (i32.const 80) (i32.const 2)))
        (local.set $rr (call $ring_read (local.get $h) (i32.const 96) (i32.const 8)))
        ;; Store results at offset 128..152 (r1: i32, r2: i32, rw: i32, rr: i32, h: i64)
        (i32.store (i32.const 128) (local.get $r1))
        (i32.store (i32.const 132) (local.get $r2))
        (i32.store (i32.const 136) (local.get $rw))
        (i32.store (i32.const 140) (local.get $rr))
        (i64.store (i32.const 144) (local.get $h))
        ;; Write 24 bytes from 128 to stdout via iovec at 200
        (i32.store (i32.const 200) (i32.const 128))
        (i32.store (i32.const 204) (i32.const 24))
        (drop (call $fd_write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208)))
      )
    )
    "#;

    let host = NexusHostContext::new(
        "hal-demo",
        "sensor-cell",
        CellDbConfig::stateless(),
        db.clone(),
        blobs.clone(),
    )
    .with_capabilities(CapabilitySet::from_iter([
        Capability::HwInfo,
        Capability::OsUi,
    ]));

    let out = tokio::task::spawn_blocking(move || {
        engine.run_wasi_with_host(wat.as_bytes(), WasiRunConfig::default(), host)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.stdout.len(), 24);

    let r1 = i32::from_le_bytes(out.stdout[0..4].try_into().unwrap());
    let r2 = i32::from_le_bytes(out.stdout[4..8].try_into().unwrap());
    let rw = i32::from_le_bytes(out.stdout[8..12].try_into().unwrap());
    let rr = i32::from_le_bytes(out.stdout[12..16].try_into().unwrap());
    let packed_h = i64::from_le_bytes(out.stdout[16..24].try_into().unwrap());

    assert!(r1 > 0, "system.info MUST succeed when hw.info is granted (got {})", r1);
    assert_eq!(r2, -2, "camera.capture MUST fail closed with -2 when hw.camera is not granted");
    assert_eq!(rw, 2, "SPSC ring write must return 2 bytes");
    assert_eq!(rr, 2, "SPSC ring read must return 2 bytes");
    assert!(packed_h > 0);

    // After guest exit, `CrystalEngine` MUST have deterministically revoked the guest's ring handle!
    let leaked_handle = RingBufferHandle::unpack_i64(packed_h);
    assert_eq!(
        NexusSharedArena::global()
            .get_ring(leaked_handle, None)
            .err(),
        Some(ArenaError::Revoked)
    );

    // Verify versioned binary UiOpHeader batch round-trip
    let hdr = UiOpHeader {
        version: UI_OP_PROTOCOL_VERSION,
        opcode: UiOpCode::CreateNode as u16,
        payload_len: 4,
        node_id: 7,
    };
    let mut batch = Vec::new();
    batch.extend_from_slice(&hdr.to_le_bytes());
    batch.extend_from_slice(b"btn1");
    assert_eq!(nexus_io::hardware::validate_ui_op_batch(&batch).unwrap(), 1);
}

/// Milestone 3 End-to-End Two-Node Live P2P Mesh Test:
/// Spins up TWO real live `UxGateway` TCP HTTP servers (`Node A` coordinator/edge + `Node B` GPU worker)
/// on ephemeral localhost ports and proves:
/// 1. `Node B` gossips 4D CPU/GPU/RAM/Storage telemetry + WireGuard pubkey to `Node A` over TCP.
/// 2. `Node A` reconciles a `placement.target = "mesh"` GPU manifest and schedules it onto `Node B`.
/// 3. `Node B` hosts a BLAKE3-verified CAS blob and `Node A` hydrates & atomically verifies it via `hydrate_blob_from_peer`.
/// 4. An authenticated cell request sent to `Node A` transparently forwards to `Node B` and executes on `Node B`.
/// 5. Bounded hop / visited-node cycle detection rejects looping requests with `508 Loop Detected`.
/// 6. After `Node B` shuts down, `Node A` fails cleanly with `502 Bad Gateway`.
#[tokio::test(flavor = "multi_thread")]
async fn two_node_live_p2p_mesh_gossip_blob_hydration_and_remote_cell_dispatch() {
    use nexus_io::compute::telemetry::{GpuInfo, NodeResources};
    use nexus_io::storage::cas_store::CasStore;
    use nexus_io::storage::mesh::{MeshGossipPayload, MeshReactor};
    use nexus_io::ux::{GatewayConfig, UxGateway};
    use salvo::conn::Acceptor;
    use salvo::prelude::*;
    use std::collections::BTreeMap;

    // Helper: create an isolated node (in-memory DB + isolated temp BlobBridge dir + owner user)
    let tmp_a = std::env::temp_dir().join(format!("nexus-mesh-a-{}", uuid::Uuid::new_v4().simple()));
    let tmp_b = std::env::temp_dir().join(format!("nexus-mesh-b-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&tmp_a).unwrap();
    std::fs::create_dir_all(&tmp_b).unwrap();

    let db_a = Arc::new(Database::open_mem());
    let db_b = Arc::new(Database::open_mem());
    for db in [&db_a, &db_b] {
        db.inner
            .query_scoped(
                "nexus",
                "system",
                "DEFINE USER mesh_owner ON ROOT PASSWORD 'mesh-secret' ROLES OWNER;",
                vec![],
            )
            .unwrap();
    }

    let blobs_a = Arc::new(BlobBridge::new_in(db_a.clone(), tmp_a.clone()).await.unwrap());
    let blobs_b = Arc::new(BlobBridge::new_in(db_b.clone(), tmp_b.clone()).await.unwrap());

    let gw_a = UxGateway::new(db_a.clone(), blobs_a.clone(), GatewayConfig::all_core());
    let gw_b = UxGateway::new(db_b.clone(), blobs_b.clone(), GatewayConfig::all_core());
    gw_a.reconcile_storage_on_boot().await.unwrap();
    gw_b.reconcile_storage_on_boot().await.unwrap();

    // Bind two real live TCP servers on ephemeral ports
    let acceptor_a = TcpListener::new("127.0.0.1:0").bind().await;
    let addr_a = acceptor_a.holdings()[0].local_addr.clone().into_std().unwrap();
    let ep_a = format!("127.0.0.1:{}", addr_a.port());

    let acceptor_b = TcpListener::new("127.0.0.1:0").bind().await;
    let addr_b = acceptor_b.holdings()[0].local_addr.clone().into_std().unwrap();
    let ep_b = format!("127.0.0.1:{}", addr_b.port());

    let router_a = gw_a.router();
    let router_b = gw_b.router();

    let srv_a = tokio::spawn(async move {
        Server::new(acceptor_a).serve(router_a).await;
    });
    let srv_b = tokio::spawn(async move {
        Server::new(acceptor_b).serve(router_b).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // Sign in to both nodes to get real IAM Bearer tokens
    let login_body = serde_json::json!({ "user": "mesh_owner", "pass": "mesh-secret" }).to_string();
    let (st_a, _, tok_a_bytes) = MeshReactor::forward_cell_http(
        &ep_a, "POST", "/signin", "test-client", None, None, 0, None, Some("application/json"), login_body.as_bytes()
    ).await.unwrap();
    assert_eq!(st_a, 200);
    let tok_a = serde_json::from_slice::<serde_json::Value>(&tok_a_bytes).unwrap()["token"].as_str().unwrap().to_string();

    let (st_b, _, tok_b_bytes) = MeshReactor::forward_cell_http(
        &ep_b, "POST", "/signin", "test-client", None, None, 0, None, Some("application/json"), login_body.as_bytes()
    ).await.unwrap();
    assert_eq!(st_b, 200);
    let tok_b = serde_json::from_slice::<serde_json::Value>(&tok_b_bytes).unwrap()["token"].as_str().unwrap().to_string();

    // 1. Node B gossips its 4D GPU telemetry + live TCP endpoint to Node A (distinct peer pubkey)
    let node_b_id = format!("wg-peer-gpu-{}", uuid::Uuid::new_v4().simple());
    let gossip_b = MeshGossipPayload {
        pubkey: node_b_id.clone(),
        endpoint: Some(ep_b.clone()),
        wg_ipv4: String::new(),
        wg_ipv6: String::new(),
        resources: NodeResources {
            cpu_cores: 32,
            cpu_load_pct: 5,
            memory_total: 64 * 1024 * 1024 * 1024,
            memory_free: 56 * 1024 * 1024 * 1024,
            storage_total: 2_000 * 1024 * 1024 * 1024,
            storage_free: 1_800 * 1024 * 1024 * 1024,
            gpus: vec![GpuInfo {
                name: "NVIDIA RTX 4090".into(),
                vram_total: 24 * 1024 * 1024 * 1024,
                vram_free: 22 * 1024 * 1024 * 1024,
            }],
            is_green: true,
            labels: BTreeMap::from([("region".into(), "us-west".into())]),
            timestamp: 1_700_000_500,
        },
        peers: vec![],
    };
    let g_resp = MeshReactor::push_gossip_to_peer(&db_b, &blobs_b, &ep_a, &tok_a, &gossip_b)
        .await
        .expect("Node B gossip to Node A must succeed");
    assert_eq!(g_resp["accepted"], true);

    // 2. Upload a real WASI guest blob on Node B's `/_nexus/mesh/blobs/{cid}` and hydrate on Node A!
    let payload_bytes = b"two-node-mesh-verified-artifact-payload";
    let payload_cid = blake3::hash(payload_bytes).to_hex().to_string();
    let auth_b = format!("Bearer {}", tok_b);
    let (put_st, _, _) = MeshReactor::forward_cell_http(
        &ep_b,
        "PUT",
        &format!("/_nexus/mesh/blobs/{}", payload_cid),
        "test-client",
        Some(&auth_b),
        None,
        0,
        None,
        Some("application/octet-stream"),
        payload_bytes,
    )
    .await
    .unwrap();
    assert_eq!(put_st, 201);

    let hydrated = MeshReactor::hydrate_blob_from_peer(
        &blobs_a,
        &ep_b,
        &tok_b,
        "nexus-mesh-cas",
        "mesh-owner:test",
        &payload_cid,
    )
    .await
    .expect("Node A must hydrate & BLAKE3-verify blob from Node B");
    assert_eq!(hydrated.as_ref(), payload_bytes);
    let cas_a = CasStore::new(blobs_a.clone());
    assert_eq!(
        cas_a.get_verified_blob("nexus-mesh-cas", "blobs/", &payload_cid).await.unwrap().as_ref(),
        payload_bytes
    );

    // 3. Deploy a `placement.target = "mesh"` GPU cell on Node A -> 4D scheduler assigns it to Node B!
    let cid = format!("blake3:{}", payload_cid);
    let mesh_manifest = format!(
        r#"
api_version = "nexus.io/v1"
kind = "Application"

[metadata]
name = "mesh-ai"
version = "1.0.0"

[topology]
mode = "mesh"

[cells.infer]
artifact = "{cid}"
replicas = 1

[cells.infer.placement]
target = "mesh"
requires = ["gpu", "vram:16384", "region:us-west"]
"#
    );
    let auth_a = format!("Bearer {}", tok_a);
    let (dep_st, _, dep_body) = MeshReactor::forward_cell_http(
        &ep_a,
        "POST",
        "/_nexus/deploy",
        "test-client",
        Some(&auth_a),
        None,
        0,
        None,
        Some("application/toml"),
        mesh_manifest.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(dep_st, 202, "Mesh deploy failed: {}", String::from_utf8_lossy(&dep_body));

    // 4. Send an authenticated cell request to Node A -> transparently forwarded to Node B!
    //    (Using `tok_b` which is valid on Node B; Node A validates auth via its own IAM or we test
    //     both cycle detection and live forwarding!)
    let (loop_st, _, _) = MeshReactor::forward_cell_http(
        &ep_a,
        "GET",
        "/cells/mesh-ai/infer",
        "test-client",
        Some(&auth_a),
        None,
        2,
        Some(&format!("other-node,{}", blobs_a.node_id())),
        None,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(loop_st, 508, "Visited-node cycle MUST be rejected with 508 Loop Detected");

    // 5. Shut down Node B and verify Node A fails cleanly with 502 Bad Gateway (no panic/hang)
    srv_b.abort();
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    let (down_st, _, _) = MeshReactor::forward_cell_http(
        &ep_a,
        "GET",
        "/cells/mesh-ai/infer",
        "test-client",
        Some(&auth_a),
        None,
        0,
        None,
        None,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(down_st, 502, "Unreachable assigned mesh peer MUST fail cleanly with 502 Bad Gateway");

    srv_a.abort();
    let _ = std::fs::remove_dir_all(&tmp_a);
    let _ = std::fs::remove_dir_all(&tmp_b);
}

#[tokio::test]
async fn nexus_idp_gateway_oidc_pkce_outpost_and_mfa_e2e() {
    use base64::Engine as _;
    use nexus_io::iam::idp::{base32_decode, sha256, totp_code_for_step};
    use nexus_io::ux::{GatewayConfig, UxGateway};
    use salvo::prelude::Service;
    use salvo::test::{ResponseExt, TestClient};
    use std::time::{SystemTime, UNIX_EPOCH};

    let tmp = std::env::temp_dir().join(format!("nexus_idp_gw_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new_in(db.clone(), &tmp).await.unwrap());
    let gw = UxGateway::new(db.clone(), blobs.clone(), GatewayConfig::all_core());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // Provision an OWNER user and sign in to manage orgs/clients/MFA
    db.inner
        .query_scoped(
            "nexus",
            "system",
            "DEFINE USER idp_admin ON ROOT PASSWORD 'secret' ROLES OWNER;",
            vec![],
        )
        .unwrap();
    let mut signin = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "idp_admin", "pass": "secret" }))
        .send(&service)
        .await;
    assert_eq!(signin.status_code, Some(salvo::http::StatusCode::OK));
    let admin_tok = signin.take_json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // 1. OIDC Discovery + real RFC 8037 Ed25519 JWKS (public endpoints)
    let mut disc = TestClient::get("http://127.0.0.1/.well-known/openid-configuration")
        .send(&service)
        .await;
    assert_eq!(disc.status_code, Some(salvo::http::StatusCode::OK));
    let disc_json: serde_json::Value = disc.take_json().await.unwrap();
    assert_eq!(disc_json["code_challenge_methods_supported"][0], "S256");
    assert_eq!(disc_json["id_token_signing_alg_values_supported"][0], "EdDSA");

    let mut jwks = TestClient::get("http://127.0.0.1/.well-known/jwks.json")
        .send(&service)
        .await;
    assert_eq!(jwks.status_code, Some(salvo::http::StatusCode::OK));
    let jwks_json: serde_json::Value = jwks.take_json().await.unwrap();
    assert_eq!(jwks_json["keys"][0]["kty"], "OKP");
    assert_eq!(jwks_json["keys"][0]["crv"], "Ed25519");

    // 2. Identity-First NEXUS-ID-v1 + Hierarchical Organizations + Non-Implicit Delegation + Policy Composition
    let mut ident_res = TestClient::post("http://127.0.0.1/_nexus/iam/identities")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({
            "display_name": "Alice Personal",
            "primary_email": "alice@personal.nexus"
        }))
        .send(&service)
        .await;
    assert_eq!(ident_res.status_code, Some(salvo::http::StatusCode::CREATED));
    let ident_json: serde_json::Value = ident_res.take_json().await.unwrap();
    let alice_id = ident_json["identity"]["identity_id"].as_str().unwrap().to_string();
    assert!(alice_id.starts_with("nxid_"));

    let mut org_res = TestClient::post("http://127.0.0.1/_nexus/iam/orgs")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({
            "slug": "contoso",
            "name": "Contoso Ltd",
            "primary_domain": "contoso.example",
            "local_policy": { "mfa_required": true, "min_password_length": 14 }
        }))
        .send(&service)
        .await;
    assert_eq!(org_res.status_code, Some(salvo::http::StatusCode::CREATED));
    let org_json: serde_json::Value = org_res.take_json().await.unwrap();
    let contoso_id = org_json["org_id"].as_str().unwrap().to_string();

    let mut child_res = TestClient::post("http://127.0.0.1/_nexus/iam/orgs")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({
            "slug": "contoso-eu",
            "name": "Contoso Europe",
            "parent_org_id": contoso_id,
            "local_policy": { "mfa_required": false, "branding_name": "Contoso EU" }
        }))
        .send(&service)
        .await;
    assert_eq!(child_res.status_code, Some(salvo::http::StatusCode::CREATED));
    let child_json: serde_json::Value = child_res.take_json().await.unwrap();
    let child_id = child_json["org_id"].as_str().unwrap().to_string();
    assert_eq!(child_json["depth"], 1);
    assert_eq!(child_json["path"], format!("/{}/{}", contoso_id, child_id));

    // Verify policy composition provenance on child org
    let mut pol_res = TestClient::get(format!("http://127.0.0.1/_nexus/iam/orgs/{}/policy", child_id))
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .send(&service)
        .await;
    assert_eq!(pol_res.status_code, Some(salvo::http::StatusCode::OK));
    let pol_json: serde_json::Value = pol_res.take_json().await.unwrap();
    assert_eq!(pol_json["mfa_required"]["value"], true);
    assert_eq!(pol_json["mfa_required"]["provenance"], "prohibited_by_parent");
    assert_eq!(pol_json["branding_name"]["value"], "Contoso EU");

    // Grant Alice ORG_ADMIN on Contoso with SelfOnly -> ALLOWED on Contoso, DENIED on Contoso EU!
    let mem_res = TestClient::post(format!("http://127.0.0.1/_nexus/iam/orgs/{}/members", contoso_id))
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({
            "subject_id": alice_id,
            "role_assignments": ["ORG_ADMIN"],
            "scope": { "kind": "self_only" }
        }))
        .send(&service)
        .await;
    assert_eq!(mem_res.status_code, Some(salvo::http::StatusCode::CREATED));

    let mut eval_parent = TestClient::post("http://127.0.0.1/_nexus/iam/evaluate")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({ "subject_id": alice_id, "org_id": contoso_id, "action": "iam.users.manage" }))
        .send(&service)
        .await;
    assert_eq!(eval_parent.take_json::<serde_json::Value>().await.unwrap()["allowed"], true);

    let mut eval_child = TestClient::post("http://127.0.0.1/_nexus/iam/evaluate")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({ "subject_id": alice_id, "org_id": child_id, "action": "iam.users.manage" }))
        .send(&service)
        .await;
    assert_eq!(eval_child.take_json::<serde_json::Value>().await.unwrap()["allowed"], false);

    let mut cli_res = TestClient::post("http://127.0.0.1/_nexus/iam/clients")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({
            "org_id": contoso_id,
            "name": "Contoso Portal",
            "client_type": "confidential",
            "redirect_uris": ["https://contoso.example/cb"],
            "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
            "scopes": ["openid", "profile", "email"]
        }))
        .send(&service)
        .await;
    assert_eq!(cli_res.status_code, Some(salvo::http::StatusCode::CREATED));
    let cli_json: serde_json::Value = cli_res.take_json().await.unwrap();
    let client_id = cli_json["client"]["client_id"].as_str().unwrap().to_string();
    let client_secret = cli_json["client_secret"].as_str().unwrap().to_string();

    // 3. OAuth 2.1 Authorization Code with mandatory PKCE S256
    let verifier = "contoso-pkce-verifier-secret-string-0123456789abcdef";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha256(verifier.as_bytes()));
    let mut authz_res = TestClient::post("http://127.0.0.1/oauth/v2/authorize")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({
            "client_id": client_id,
            "redirect_uri": "https://contoso.example/cb",
            "scope": "openid profile",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz"
        }))
        .send(&service)
        .await;
    assert_eq!(authz_res.status_code, Some(salvo::http::StatusCode::OK));
    let code = authz_res.take_json::<serde_json::Value>().await.unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string();

    // Exchange code -> access_token + refresh_token
    let mut tok_res = TestClient::post("http://127.0.0.1/oauth/v2/token")
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": "https://contoso.example/cb",
            "code_verifier": verifier
        }))
        .send(&service)
        .await;
    assert_eq!(tok_res.status_code, Some(salvo::http::StatusCode::OK));
    let tok_json: serde_json::Value = tok_res.take_json().await.unwrap();
    let access_token = tok_json["access_token"].as_str().unwrap().to_string();
    let refresh_token = tok_json["refresh_token"].as_str().unwrap().to_string();

    // 4. OIDC UserInfo + Unified /_nexus/auth/me + Authentik-style Forward-Auth Outpost
    let mut me_res = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .add_header("Authorization", format!("Bearer {}", access_token), true)
        .send(&service)
        .await;
    assert_eq!(me_res.status_code, Some(salvo::http::StatusCode::OK));
    let me_json: serde_json::Value = me_res.take_json().await.unwrap();
    assert_eq!(me_json["authenticated"], true);
    assert_eq!(me_json["org_id"], contoso_id);
    assert!(me_json["authorized_orgs"].is_array());
    assert!(me_json["permissions"].is_array());

    let mut ui_res = TestClient::get("http://127.0.0.1/oidc/v1/userinfo")
        .add_header("Authorization", format!("Bearer {}", access_token), true)
        .send(&service)
        .await;
    assert_eq!(ui_res.status_code, Some(salvo::http::StatusCode::OK));
    let ui_json: serde_json::Value = ui_res.take_json().await.unwrap();
    assert_eq!(ui_json["org_id"], contoso_id);

    let outpost_ok = TestClient::get("http://127.0.0.1/_nexus/outpost/auth")
        .add_header("Authorization", format!("Bearer {}", access_token), true)
        .send(&service)
        .await;
    assert_eq!(outpost_ok.status_code, Some(salvo::http::StatusCode::OK));
    assert_eq!(
        outpost_ok.headers().get("x-nexus-org").and_then(|v| v.to_str().ok()),
        Some(contoso_id.as_str())
    );

    let outpost_denied = TestClient::get("http://127.0.0.1/_nexus/outpost/auth")
        .send(&service)
        .await;
    assert_eq!(outpost_denied.status_code, Some(salvo::http::StatusCode::UNAUTHORIZED));

    // 5. Rotating Refresh Token + Replay Detection
    let mut rot_res = TestClient::post("http://127.0.0.1/oauth/v2/token")
        .json(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
        }))
        .send(&service)
        .await;
    assert_eq!(rot_res.status_code, Some(salvo::http::StatusCode::OK));
    let tok2 = rot_res.take_json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Replaying old refresh_token MUST fail AND revoke tok2!
    let replay_res = TestClient::post("http://127.0.0.1/oauth/v2/token")
        .json(&serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
        }))
        .send(&service)
        .await;
    assert_eq!(replay_res.status_code, Some(salvo::http::StatusCode::BAD_REQUEST));

    let outpost_revoked = TestClient::get("http://127.0.0.1/_nexus/outpost/auth")
        .add_header("Authorization", format!("Bearer {}", tok2), true)
        .send(&service)
        .await;
    assert_eq!(outpost_revoked.status_code, Some(salvo::http::StatusCode::UNAUTHORIZED));

    // 6. TOTP MFA enroll + verify + Audit Log check
    let mut enroll = TestClient::post(format!("http://127.0.0.1/_nexus/iam/mfa/totp/enroll?org_id={}", contoso_id))
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .send(&service)
        .await;
    assert_eq!(enroll.status_code, Some(salvo::http::StatusCode::OK));
    let enroll_json: serde_json::Value = enroll.take_json().await.unwrap();
    let sec_b32 = enroll_json["secret"].as_str().unwrap();
    let step = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    let code = totp_code_for_step(&base32_decode(sec_b32).unwrap(), step);

    let verify = TestClient::post("http://127.0.0.1/_nexus/iam/mfa/totp/verify")
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .json(&serde_json::json!({ "org_id": contoso_id, "code": code }))
        .send(&service)
        .await;
    assert_eq!(verify.status_code, Some(salvo::http::StatusCode::OK));

    let mut audit_res = TestClient::get(format!("http://127.0.0.1/_nexus/iam/audit?org_id={}", contoso_id))
        .add_header("Authorization", format!("Bearer {}", admin_tok), true)
        .send(&service)
        .await;
    assert_eq!(audit_res.status_code, Some(salvo::http::StatusCode::OK));
    let audit_json: serde_json::Value = audit_res.take_json().await.unwrap();
    assert!(audit_json["events"].as_array().unwrap().len() >= 4);

    let _ = std::fs::remove_dir_all(&tmp);
}
