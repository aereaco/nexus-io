# Nexus-IO Deployment Profiles & Empirical Footprint Benchmarks

This document records empirical measurements across Nexus-IO's configurable deployment profiles, OS target profiles, optional native GUI flag, and automated SurrealDB differential conformance suite.

## 1. Architecture Summary

- **Single platform, zero unnecessary runtime overhead:** `surrealdb 4.0.1` has been removed from all default and production builds in favor of the clean-room, MIT-licensed `crates/nexus-db` embedded multi-model engine (`redb` + `BTreeMap`).
- **Opt-in differential oracle:** `surrealdb 4.0.1` remains available strictly behind `--features surrealdb-ref` / `profile-dev` to run the automated differential conformance test suite (`db::state_engine::differential_tests` — **2 passed, 0 failed**, 100% JSON output parity against SurrealDB 4.0.1).
- **Compile-time modularity + lazy runtime activation:** `CapabilityRegistry` (`GET /_nexus/capabilities`) distinguishes `not_compiled`, `compiled`, `configured`, `initialized`, `active`, and `suspended` states. Heavyweight subsystems (`p2p-storage`, `s3-gateway`, `shell`, `wasm-runtime`, `k8s-bridge`, `vpn`, `hardware-monitoring`, `gui`) are optional Cargo features.
- **Device-native GUI (`--features gui`):** Uses `wry` + `tao` on desktop (`WebView2` on Windows, `WKWebView` on macOS, `WebKitGTK` on Linux) and OS-native WebView host bridges on mobile (`Android System WebView`, iOS `WKWebView`), avoiding Electron or bundled third-party browsers.

---

## 2. Workload Deployment Profiles (Measured on Windows x86_64)

Release measurements (`cargo build --release --no-default-features --features <profile>`) and `js "1 + 2"` fluid short-circuit cold-start timings:

| Profile | Resolved Crates | Release Binary (`nexus.exe`) | Cold-Start (`js "1 + 2"`) | Peak RSS | Unit Tests (`--lib`) | Highlights |
| :--- | ---: | ---: | ---: | ---: | :--- | :--- |
| **`profile-core`** *(default)* | **849** | **68.78 MB** *(pre-trim; smaller with `strip`/`lto`)* | 790 ms | **5.41 MB** | 15 passed (0.08s) | Embedded `nexus-db` (`auth`+`cbor`), local BLAKE3 CAS blob store, lean Salvo (`rustls`+`websocket`), trimmed Tokio, QuickJS + OXC TS, Cells, IAM. Excludes `iroh`, `s3s`, `nu-cli`, `rustyline`, `pgwire`, `sqlite-hrana`, `graphql`, `gql`, Wasmtime, K8s YAML, VPN, NVML, GUI, and SurrealDB. |
| **`profile-app`** | **1,114** | **83.25 MB** | 696 ms | **3.20 MB** | 15 passed | Adds `p2p-storage` (`iroh` + `iroh-blobs`), `s3-gateway` (`s3s`), `sqlite-hrana`, `graphql`, `gql`, `pgwire`, Salvo ACME/QUIC/OpenAPI, and `nexus-db` FTS (BM25), HNSW vector search, Files/Buckets, Auth, and CBOR. |
| **`profile-full`** | **1,187** | **86.36 MB** | 699 ms | **14.28 MB** | 15 passed (0.38s) | Adds Wasmtime 51 Crystal cells, K8s YAML bridge (`serde_norway`), WireGuard VPN (`boringtun` / `wintun`), NVML GPU telemetry, interactive `shell` (`nu-cli` + `rustyline`), and `nexus-db/full` (Geo, Crypto, GraphQL, ML, ISO GQL, PgWire). |
| **`profile-dev`** | **1,406** | — | — | — | **2/2 differential tests passed (0.60s)** | Adds opt-in `surrealdb-ref` (SurrealDB 4.0.1) strictly for automated differential conformance testing (**+450 transitive crates** vs `profile-core` and multi-GB `rustc` compile footprint kept out of production). |

---

## 3. OS Target Profiles & Optional Native `gui` Flag

Measured on Windows x86_64 host via `cargo tree --no-default-features --features <profile> --prefix none | sort -u`:

| Profile / Flag | Resolved Crates (Windows host) | Release Binary (`nexus.exe`) | Native Web Rendering Engine (`--features gui`) | Notes |
| :--- | ---: | ---: | :--- | :--- |
| **`profile-windows`** | **1,186** | — | `WebView2` (Windows Native) | `Wintun` WireGuard + NVML + Cranelift Wasm + `shell` |
| **`profile-linux`** | **1,187** | — | `WebKitGTK` (Linux Native) | Linux `TUN` WireGuard + K8s bridge + NVML + Cranelift Wasm + `shell` |
| **`profile-macos`** | **1,177** | — | `WKWebView` (Apple Native) | macOS `utun` WireGuard + Cranelift Wasm + `shell` (no NVML) |
| **`profile-android`** | **1,146** *(smaller on `aarch64-linux-android`)* | — | `Android System WebView` | Excludes desktop CLI (`nu-cli`/`rustyline`), NVML, and desktop TUN drivers via `cfg(target_os)` |
| **`profile-ios`** | **1,146** *(smaller on `aarch64-apple-ios`)* | — | `WKWebView` (Apple Native) | **Apple `W^X` compliant:** `wasmtime` compiled in `runtime`-only mode (AOT `.cwasm`, no Cranelift JIT) |
| **`profile-windows,gui`** | **1,209** *(+23 crates)* | **85.79 MB** (711 ms, 14.66 MB RSS) | `WebView2` via `wry` + `tao` | 14 passed (0.22s); native OS WebView adds <1 MB vs 150–250 MB for Electron |

---

## 4. Automated Differential Conformance Suite (`--features profile-core,surrealdb-ref`)

Executed live against both `surrealdb 4.0.1` (`Mem`) and `nexus-db` (`NexusDb::open_mem()`):

1. **`differential_nexus_db_matches_surrealdb_4`** — **PASS**: SQLite AST-compiled `CREATE TABLE`/`INSERT`/`SELECT`, Graph `RELATE`, `UPDATE MERGE`/`+=`/`UNSET`, `UNIQUE` index enforcement + `BEGIN TRANSACTION ... COMMIT TRANSACTION` atomic rollback, `DEFINE FIELD ... DEFAULT / ASSERT`, `??` / inline `IF` / `string::lowercase` / `math::abs`, and Cell KV snapshot export/import.
2. **`differential_aggregates_functions_dml_and_stdlib`** — **PASS**: `GROUP BY` with `count()`, `math::sum()`, `math::min()`, `math::max()`, `UPSERT`/`DELETE`/`LIMIT`/`START`/`OMIT`, `SPLIT`, `DEFINE FUNCTION fn::...`, and `array::len`/`array::distinct`/`string::concat`.
