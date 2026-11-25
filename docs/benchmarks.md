# Nexus-IO Deployment Profiles & Footprint Benchmarks

This document tracks the **exact, verified dependency footprint** of each Nexus-IO deployment profile against the current `Cargo.toml` feature graph, along with empirical release measurements and reproducible commands.

---

## 1. Current Profile Dependency Graph (Verified `2026-11-25`)

Measured via `powershell -ExecutionPolicy Bypass -File scripts/check-footprint.ps1`:

| Profile | Unique Crates | Budget | What Is Compiled In | What Is Excluded |
| :--- | :---: | :---: | :--- | :--- |
| **`core`** *(default)* | **422** | `<= 450` | **Wasmtime 51 + WASI** (`runtime-wasm`), **Nexus-DB** (`db-auth`, `db-cbor`), **BlobBridge + CasStore** (3-state ownership + WAL `OwnershipTx` + fenced CAS leases), **UxGateway** (Salvo HTTP/WS), **IAM + CapabilitySet**, **NexusMetrics** | `runtime-oci`, extended `db-*` flags, `net-*` (`net-http3`, `net-acme`, `net-openapi`, `net-vpn`), `storage-*` (`storage-p2p`, `storage-s3`), `serve-*`, `ops-*` (`ops-shell`, `ops-k8s`, `ops-gpu`), `gui-webview` |
| **`full`** | **1,161** | — | `core` + `runtime-all` + `db-all` + `net-all` + `storage-all` + `serve-all` + `ops-all` | `gui-webview` / `gui-all` *(opt-in, OS-autodetected native WebView)* |

> **100% MIT & Wasm-First:** Native `quickrs-core`, `oxc_*`, `sqlparser`, and `surrealdb` crates have been completely removed from `io/Cargo.toml`. JavaScript, TypeScript, and guest SQL/document databases run as Wasm modules inside Wasmtime.

---

## 2. Empirical Release Benchmarks — 422-Crate Pure-Wasmtime `core` (Verified `2026-11-25`)

Measured across **5 fresh process launches** (isolated temporary data directory per run, 2-second idle settle window before memory sampling):

| Measurement | Value |
| :--- | :--- |
| **Release executable size (`nexus.exe`, stripped)** | **15.87 MB** (`16,642,560` bytes) |
| **Cold host process startup (5 fresh launches, TCP port 8080 readiness)** | **Median: `1,036.27 ms`** (range: `1,019.78 ms – 1,889.85 ms`; runs 2–5: `1,019.78 – 1,044.02 ms`; run 1 includes OS cold page cache) |
| **Isolated guest AOT `.cwasm` instantiation + execution (25 fresh runs, `--release`)** | **Median: `114 µs` (`0.114 ms`)** (range: `71 µs – 335 µs`; measured via `aot_guest_instantiation_latency_benchmark`) |
| **Idle Working Set (`WorkingSet64`, 2s settled)** | **Median: `12.02 MB`** (range: `11.93 MB – 25.14 MB`) |
| **Idle Private Memory (`PrivateMemorySize64`, 2s settled)** | **Median: `4.43 MB`** (range: `4.18 MB – 4.70 MB`) |
| **Rust / Cargo versions** | `rustc 1.100.0 (0ef1bc386 2026-11-09)` / `cargo 1.100.0 (3acc79c0c 2026-11-05)` |
| **Build command & profile flags** | `cargo build --release --bin nexus --no-default-features --features core` (`opt-level = "z"`, `lto = "thin"`, `codegen-units = 1`, `strip = true`) |
| **OS & Architecture** | `Microsoft Windows NT 10.0.26300.0` (`AMD64` / `x86_64`) |

### Historical Reference (Legacy Pre-Wasmtime-Core Layout)

> **Composition qualification:** The 76.9% binary-size reduction from the historical `68.78 MB` measurement (`96a3513c`) to `15.87 MB` compares two different profile compositions — the historical layout compiled Nushell, OXC, and native QuickJS into the default profile, whereas the current `core` profile excludes those native toolchains and includes Wasmtime 51 + WASI. It demonstrates footprint reduction through deployment-profile architecture rather than a like-for-like optimization of identical feature sets.

| Historical Profile (`96a3513c`) | Unique Crates | Release Binary (MB) | Idle RSS (MB) |
| :--- | :---: | :---: | :---: |
| Legacy core (with Nushell/OXC/QuickJS) | 849 | 68.78 MB | 5.41 MB |
| Legacy app | — | 83.25 MB | 3.20 MB |
| Legacy full | — | 86.36 MB | 14.28 MB |
| Legacy windows+gui | — | 85.79 MB | 14.66 MB |

---

## 3. Reproducible Measurement Commands

```powershell
# 1. Verify profile crate-count budgets (core <= 450)
powershell -ExecutionPolicy Bypass -File scripts/check-footprint.ps1

# 2. Build stripped release binary for pure-Wasmtime core
cargo build --release --bin nexus --no-default-features --features core

# 3. Measure binary size & live idle RSS (Windows PowerShell)
$exe = "target\release\nexus.exe"
[math]::Round((Get-Item $exe).Length / 1MB, 2)
$p = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$proc = Get-Process -Id $p.Id
[math]::Round($proc.WorkingSet64 / 1MB, 2)
[math]::Round($proc.PrivateMemorySize64 / 1MB, 2)
Stop-Process -Id $p.Id -Force
```
