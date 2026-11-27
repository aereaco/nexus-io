# Nexus-IO Empirical Deployment Density & Runtime Benchmarks

All results below were measured directly in `--release` mode on the real **Nexus-IO `core` microkernel** (`422` unique crates, Wasmtime 51 + WASI Preview 1, embedded `nexus-db`, `BlobBridge` + `CasStore`, and `NexusSharedArena` SPSC rings).

## Test Environment & Reproducibility

- **OS / Arch:** Windows (`x86_64`)
- **Profile:** `--release --no-default-features --features core` (`422` unique crates, `0` extra benchmark crates)
- **Exact Command:**
  ```powershell
  cd io
  cargo test --release --test density_benchmark --no-default-features --features core -- --nocapture --test-threads=1
  ```
- **Source:** [`io/tests/density_benchmark.rs`](../tests/density_benchmark.rs)
- **Memory Safety Verification:** `enforced_store_limits_block_runaway_guest_memory_growth` — **PASSED** (guest attempting 4 MiB `memory.grow` under 1 MiB `StoreLimits` hard-traps cleanly without OOMing host).

---

## 1. Wasmtime Memory Reservation A/B Comparison (200 Warm AOT Executions Each)

Shared `CrystalEngine` + cached `Linker<CrystalWasiState>` + AOT `.cwasm` module:

| Density Profile | Engine Init | AOT Compile | Cold First Run | Warm p50 | Warm p95 | Warm p99 | Measured RSS Delta |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`Standard`** *(Wasmtime default)* | `285 µs` | `2,405 µs` | `533 µs` | `65 µs` | `86 µs` | `115 µs` | `916 KiB` |
| **`HighDensity`** *(4 MiB res / 2 MiB growth / 64 KiB guard)* | `299 µs` | `2,962 µs` | `299 µs` | `42 µs` | `55 µs` | `88 µs` | `100 KiB` |
| **`UltraCompact`** *(1 MiB res / 512 KiB growth / 64 KiB guard)* | `305 µs` | `2,458 µs` | `211 µs` | `41 µs` | `57 µs` | `103 µs` | `0 KiB` |

**Key Finding:** `HighDensity` cuts cold AOT instantiation by **44%** (`533 µs → 299 µs`), warm p50 by **35%** (`65 µs → 42 µs`), and process RSS delta by **89%** (`916 KiB → 100 KiB`) compared to Wasmtime defaults, while keeping `StoreLimits` hard-enforced per cell (`max_memory_bytes`, `max_memories`, `max_tables`).

---

## 2. Three-Profile Workload Density Results

### Profile 1 — 500 Tiny Idle/Burst Services + Hibernation
- **Workload:** 500 independently registered elastic WASI cells sharing 1 `CrystalEngine` + cached module, burst HTTP execution across 50 sampled cells, full hibernation of all 500 cells to `CasStore`, and restoration of 25 sampled cells.
- **Results:**
  - **500 cells woken:** `1,267 ms` (`wake p50 = 2,014 µs`, `p95 = 5,340 µs`)
  - **Burst execution:** `p50 = 126 µs`, `p95 = 253 µs`
  - **500 cells hibernated:** `1,118 ms`
  - **Restore from hibernation:** `p50 = 1,196 µs`, `p95 = 1,643 µs`
  - **Memory footprint:** `RSS start = 16,288 KiB` → `RSS active (500 cells) = 25,292 KiB` (**`9,004 KiB` delta = `18.0 KiB / active cell`**)
  - *Note on OS RSS after hibernation:* Windows process working-set (`26,036 KiB` immediately after hibernation) retains freed heap pages in the allocator cache until OS memory pressure reclaims them; logical active cell structures are released immediately.

### Profile 2 — 100 Persistent Isolated DB + Blob Apps
- **Workload:** 100 concurrent WASI apps each with dedicated `CellDbConfig::dedicated_full()` isolation, executing `CREATE kv SET v = 42; SELECT v FROM kv;` via `nexus_db_query` and writing state via `nexus_blob_put`.
- **Results:**
  - **Wall time (all 100 apps):** `22 ms`
  - **Per-app latency:** `p50 = 10.76 ms`, `p95 = 14.93 ms`, `p99 = 15.22 ms`
  - **Memory delta:** `6,848 KiB` (**`68.5 KiB / isolated DB+Blob app`**)

### Profile 3 — 64 Concurrent Wasm Compute + `NexusSharedArena` SPSC Streaming Workers
- **Workload:** 64 concurrent threads × 25 invocations (`1,600` total WASI cell executions), each allocating a generation-validated `SpscRingBuffer`, streaming 16 × 32-byte frames directly to/from Wasm linear memory (`TransportMode::PortableCopy`, zero intermediate heap `Vec`), and deterministically revoking handles on exit.
- **Results:**
  - **Throughput:** **`34,534` Wasm+SPSC cell invocations / sec** (`1,600` in `0.046 s`)
  - **Tail latency:** `p50 = 255 µs`, `p95 = 2,127 µs`, `p99 = 8,607 µs`
  - **Memory delta:** `1,952 KiB`
  - **Native Rust SPSC baseline (same machine, `100,000 × 64 B`):** `17.17 ms` (`355.4 MiB/s`)
