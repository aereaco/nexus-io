//! Nexus-IO Empirical Deployment Density Benchmark Suite (3 Workload Profiles + Profile A/B)
//!
//! Run in release mode with `--nocapture` for reproducible production numbers:
//!   cargo test --release --test density_benchmark --no-default-features --features core -- --nocapture --test-threads=1

use nexus_io::arena::{NexusSharedArena, TransportMode};
use nexus_io::compute::crystal::{CrystalEngine, DensityProfile, NexusHostContext, WasiRunConfig};
use nexus_io::db::Database;
use nexus_io::iam::capabilities::{Capability, CapabilitySet};
use nexus_io::js::cell::{CellDbConfig, CellManager, CellPolicy, CellWorkload};
use nexus_io::storage::BlobBridge;
use std::sync::Arc;
use std::time::Instant;
use sysinfo::{Pid, ProcessesToUpdate, System};

fn current_rss_kib() -> u64 {
    let mut sys = System::new();
    let pid = Pid::from_u32(std::process::id());
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]));
    sys.process(pid).map(|p| p.memory() / 1024).unwrap_or(0)
}

fn percentile_us(sorted: &[u128], pct: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (((sorted.len() as f64) * pct).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

const TINY_ECHO_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "ok")
  (func (export "_start")
    (i32.store (i32.const 16) (i32.const 0))
    (i32.store (i32.const 20) (i32.const 2))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
  )
)
"#;

const MEMORY_BOMB_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start")
    ;; Attempt to grow memory by 64 pages (4 MiB) when StoreLimits caps at 1 MiB
    (if (i32.eq (memory.grow (i32.const 64)) (i32.const -1))
      (then (unreachable))
    )
  )
)
"#;

const DB_APP_WAT: &str = r#"
(module
  (import "nexus_host" "nexus_db_query" (func $db_q (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "nexus_host" "nexus_blob_put" (func $b_put (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "surql")
  (data (i32.const 16) "CREATE kv SET v = 42; SELECT v FROM kv;")
  (data (i32.const 80) "density-blobs")
  (data (i32.const 112) "state.bin")
  (data (i32.const 128) "persisted-cell-state")
  (func (export "_start")
    (local $n i32)
    (local.set $n (call $db_q (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 39) (i32.const 512) (i32.const 1024)))
    (drop (call $b_put (i32.const 80) (i32.const 13) (i32.const 112) (i32.const 9) (i32.const 128) (i32.const 20)))
    (i32.store (i32.const 256) (i32.const 512))
    (i32.store (i32.const 260) (local.get $n))
    (drop (call $fd_write (i32.const 1) (i32.const 256) (i32.const 1) (i32.const 264)))
  )
)
"#;

const COMPUTE_RING_WAT: &str = r#"
(module
  (import "nexus_host" "nexus_ring_alloc" (func $ring_alloc (param i32) (result i64)))
  (import "nexus_host" "nexus_ring_write" (func $ring_write (param i64 i32 i32) (result i32)))
  (import "nexus_host" "nexus_ring_read" (func $ring_read (param i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "0123456789abcdef0123456789abcdef")
  (func (export "_start")
    (local $h i64)
    (local $i i32)
    (local.set $h (call $ring_alloc (i32.const 256)))
    (loop $l
      (drop (call $ring_write (local.get $h) (i32.const 0) (i32.const 32)))
      (drop (call $ring_read (local.get $h) (i32.const 64) (i32.const 32)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 16)))
    )
  )
)
"#;

#[test]
fn enforced_store_limits_block_runaway_guest_memory_growth() {
    let engine = CrystalEngine::with_profile(DensityProfile::HighDensity).unwrap();
    let cfg = WasiRunConfig {
        max_memory_bytes: 1024 * 1024, // 1 MiB hard cap
        max_memories: 1,
        ..WasiRunConfig::default()
    };
    let res = engine.run_wasi_p1(MEMORY_BOMB_WAT.as_bytes(), cfg);
    assert!(
        res.is_err(),
        "Runaway guest attempting 4 MiB growth under 1 MiB StoreLimits MUST trap/fail"
    );
}

#[test]
fn profile_ab_standard_vs_high_density_vs_pooling() {
    let profiles = [
        ("Standard (Wasmtime default)", DensityProfile::Standard),
        ("HighDensity (4MiB res / 64KiB guard)", DensityProfile::HighDensity),
        ("UltraCompact (1MiB res / 64KiB guard)", DensityProfile::UltraCompact),
    ];

    println!("\n=== A/B Wasmtime Density Profile Comparison (200 warm AOT executions each) ===");
    for (name, prof) in profiles {
        let rss_before = current_rss_kib();
        let t_eng = Instant::now();
        let engine = CrystalEngine::with_profile(prof).unwrap();
        let eng_us = t_eng.elapsed().as_micros();

        let t_compile = Instant::now();
        let aot = engine.compile_aot(TINY_ECHO_WAT.as_bytes()).unwrap();
        let compile_us = t_compile.elapsed().as_micros();

        // Cold first AOT execution
        let t_cold = Instant::now();
        let out = engine.run_wasi_p1_aot(&aot, WasiRunConfig::default()).unwrap();
        let cold_us = t_cold.elapsed().as_micros();
        assert_eq!(out.stdout, b"ok");

        // Warm 200 executions
        let mut lats = Vec::with_capacity(200);
        for _ in 0..200 {
            let t = Instant::now();
            let o = engine.run_wasi_p1_aot(&aot, WasiRunConfig::default()).unwrap();
            lats.push(t.elapsed().as_micros());
            assert_eq!(o.exit_code, 0);
        }
        lats.sort_unstable();
        let rss_after = current_rss_kib();
        println!(
            "  [{name}] engine={}us | aot_compile={}us | cold={}us | warm p50={}us p95={}us p99={}us | rss_delta={} KiB",
            eng_us,
            compile_us,
            cold_us,
            percentile_us(&lats, 0.50),
            percentile_us(&lats, 0.95),
            percentile_us(&lats, 0.99),
            rss_after.saturating_sub(rss_before)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_1_500_tiny_idle_burst_cells_and_hibernation() {
    let tmp = std::env::temp_dir().join(format!("nexus-bench-p1-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&tmp).unwrap();

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new_in(db.clone(), tmp.clone()).await.unwrap());
    let cells = Arc::new(CellManager::new(db.clone(), blobs.clone()));

    let rss_start = current_rss_kib();
    let t_wake_all = Instant::now();
    let mut wake_lats = Vec::with_capacity(500);

    for i in 0..500usize {
        let cell_id = format!("svc_{:03}", i);
        let t = Instant::now();
        cells
            .wake_workload(
                "density-p1",
                &cell_id,
                CellPolicy::elastic_default(),
                CellWorkload::WasiModule {
                    module_bytes: TINY_ECHO_WAT.as_bytes().to_vec(),
                    args: vec!["svc.wasm".into()],
                    env: vec![],
                    preopen_dirs: vec![],
                    fuel_limit: 5_000_000,
                },
            )
            .await
            .unwrap();
        if i % 5 == 0 {
            wake_lats.push(t.elapsed().as_micros());
        }
    }
    let wake_total_ms = t_wake_all.elapsed().as_millis();
    let rss_active = current_rss_kib();

    // Burst execute 50 sampled cells across the 500 active cells
    let mut exec_lats = Vec::with_capacity(50);
    for i in (0..500).step_by(10) {
        let cell_id = format!("svc_{:03}", i);
        let t = Instant::now();
        let resp = cells
            .invoke_http("density-p1", &cell_id, "GET", "/", "", &[])
            .await
            .unwrap();
        exec_lats.push(t.elapsed().as_micros());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
    }

    // Hibernate all 500 cells to CasStore & measure snapshot + restore
    let t_hib = Instant::now();
    for i in 0..500usize {
        let cell_id = format!("svc_{:03}", i);
        cells.hibernate("density-p1", &cell_id).await.unwrap();
    }
    let hib_ms = t_hib.elapsed().as_millis();
    let rss_hibernated = current_rss_kib();

    // Restore 25 sampled cells from hibernation
    let mut restore_lats = Vec::with_capacity(25);
    for i in (0..500).step_by(20) {
        let cell_id = format!("svc_{:03}", i);
        let t = Instant::now();
        cells
            .wake_workload(
                "density-p1",
                &cell_id,
                CellPolicy::elastic_default(),
                CellWorkload::WasiModule {
                    module_bytes: TINY_ECHO_WAT.as_bytes().to_vec(),
                    args: vec!["svc.wasm".into()],
                    env: vec![],
                    preopen_dirs: vec![],
                    fuel_limit: 5_000_000,
                },
            )
            .await
            .unwrap();
        restore_lats.push(t.elapsed().as_micros());
    }

    wake_lats.sort_unstable();
    exec_lats.sort_unstable();
    restore_lats.sort_unstable();

    let delta_active_kib = rss_active.saturating_sub(rss_start);
    let kib_per_cell = delta_active_kib as f64 / 500.0;

    println!("\n=== Profile 1: 500 Tiny Idle/Burst Services + Hibernation ===");
    println!(
        "  500 cells woken in {} ms | wake p50={}us p95={}us | burst exec p50={}us p95={}us",
        wake_total_ms,
        percentile_us(&wake_lats, 0.50),
        percentile_us(&wake_lats, 0.95),
        percentile_us(&exec_lats, 0.50),
        percentile_us(&exec_lats, 0.95),
    );
    println!(
        "  500 cells hibernated in {} ms | restore p50={}us p95={}us",
        hib_ms,
        percentile_us(&restore_lats, 0.50),
        percentile_us(&restore_lats, 0.95),
    );
    println!(
        "  RSS start={} KiB | active(500)={} KiB (delta={} KiB, {:.1} KiB/cell) | hibernated={} KiB",
        rss_start, rss_active, delta_active_kib, kib_per_cell, rss_hibernated
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_2_100_persistent_db_backed_isolated_apps() {
    let tmp = std::env::temp_dir().join(format!("nexus-bench-p2-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&tmp).unwrap();

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new_in(db.clone(), tmp.clone()).await.unwrap());
    let engine = Arc::new(CrystalEngine::with_profile(DensityProfile::HighDensity).unwrap());
    let aot = Arc::new(engine.compile_aot(DB_APP_WAT.as_bytes()).unwrap());

    let rss_before = current_rss_kib();
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(100);

    for i in 0..100usize {
        let eng = engine.clone();
        let aot_b = aot.clone();
        let db_c = db.clone();
        let blobs_c = blobs.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let cell_id = format!("app_{:03}", i);
            let host = NexusHostContext::new(
                "density-p2",
                &cell_id,
                CellDbConfig::dedicated_full(),
                db_c,
                blobs_c,
            )
            .with_capabilities(CapabilitySet::from_iter([
                Capability::DbRead,
                Capability::DbWrite,
                Capability::BlobRead,
                Capability::BlobWrite,
            ]));
            let t = Instant::now();
            let out = eng
                .run_wasi_aot_with_host(&aot_b, WasiRunConfig::default(), host)
                .unwrap();
            let us = t.elapsed().as_micros();
            assert_eq!(out.exit_code, 0);
            let s = String::from_utf8_lossy(&out.stdout);
            assert!(s.contains("42"), "Cell {} DB output missing expected row: {}", cell_id, s);
            us
        }));
    }

    let mut lats = Vec::with_capacity(100);
    for h in handles {
        lats.push(h.await.unwrap());
    }
    let total_ms = t0.elapsed().as_millis();
    lats.sort_unstable();
    let rss_after = current_rss_kib();

    println!("\n=== Profile 2: 100 Persistent Isolated DB + Blob Apps ===");
    println!(
        "  100 isolated DB+Blob apps completed in {} ms | p50={}us p95={}us p99={}us | rss_delta={} KiB",
        total_ms,
        percentile_us(&lats, 0.50),
        percentile_us(&lats, 0.95),
        percentile_us(&lats, 0.99),
        rss_after.saturating_sub(rss_before),
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_3_64_workers_compute_and_spsc_arena_streaming() {
    let tmp = std::env::temp_dir().join(format!("nexus-bench-p3-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&tmp).unwrap();

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new_in(db.clone(), tmp.clone()).await.unwrap());
    let engine = Arc::new(CrystalEngine::with_profile(DensityProfile::HighDensity).unwrap());
    let aot = Arc::new(engine.compile_aot(COMPUTE_RING_WAT.as_bytes()).unwrap());

    let rss_before = current_rss_kib();
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(64);
    let iters_per_worker = 25usize;

    for w in 0..64usize {
        let eng = engine.clone();
        let aot_b = aot.clone();
        let db_c = db.clone();
        let blobs_c = blobs.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let mut local_lats = Vec::with_capacity(iters_per_worker);
            for k in 0..iters_per_worker {
                let host = NexusHostContext::new(
                    "density-p3",
                    format!("worker_{}_{}", w, k),
                    CellDbConfig::stateless(),
                    db_c.clone(),
                    blobs_c.clone(),
                );
                let t = Instant::now();
                let out = eng
                    .run_wasi_aot_with_host(&aot_b, WasiRunConfig::default(), host)
                    .unwrap();
                local_lats.push(t.elapsed().as_micros());
                assert_eq!(out.exit_code, 0);
            }
            local_lats
        }));
    }

    let mut all_lats = Vec::with_capacity(64 * iters_per_worker);
    for h in handles {
        all_lats.extend(h.await.unwrap());
    }
    let elapsed_s = t0.elapsed().as_secs_f64().max(0.0001);
    let total_invocations = all_lats.len();
    let ops_per_sec = total_invocations as f64 / elapsed_s;
    all_lats.sort_unstable();
    let rss_after = current_rss_kib();

    // Pure native Rust SPSC baseline on same machine
    let arena = NexusSharedArena::new();
    let owner = arena.mint_owner_id("baseline", "native").as_canonical();
    let s = arena.alloc_ring(&owner, "native.spsc", 4096, TransportMode::PortableCopy).unwrap();
    let (mut prod, mut cons) = arena.split_ring(s.handle, Some(&owner)).unwrap();
    let t_nat = Instant::now();
    let chunk = [0xABu8; 64];
    let mut out = [0u8; 64];
    for _ in 0..100_000 {
        let _ = prod.write(&chunk).unwrap();
        let _ = cons.read(&mut out).unwrap();
    }
    let nat_ms = t_nat.elapsed().as_secs_f64() * 1000.0;
    let nat_mb_s = ((100_000.0 * 64.0) / (1024.0 * 1024.0)) / (nat_ms / 1000.0);

    println!("\n=== Profile 3: 64 Concurrent Wasm Compute + Arena SPSC Streaming ===");
    println!(
        "  {} Wasm+SPSC invocations in {:.3}s ({:.0} cells/sec) | p50={}us p95={}us p99={}us | rss_delta={} KiB",
        total_invocations,
        elapsed_s,
        ops_per_sec,
        percentile_us(&all_lats, 0.50),
        percentile_us(&all_lats, 0.95),
        percentile_us(&all_lats, 0.99),
        rss_after.saturating_sub(rss_before),
    );
    println!(
        "  Native Rust SPSC baseline (100k x 64B): {:.2} ms ({:.1} MiB/s)",
        nat_ms, nat_mb_s
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
