use nexus_db::auth::{AuthContext, AuthLevel, Role};
use nexus_io::compute::crystal::{CrystalEngine, NexusHostContext, WasiRunConfig};
use nexus_io::compute::wasm_registry::{
    current_aot_compat_key, validate_runtime_name, RuntimeTrustPolicy, WasmRuntimeRegistry,
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

    let reg = WasmRuntimeRegistry::new(blobs);
    reg.set_trust_policy(RuntimeTrustPolicy {
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
}
