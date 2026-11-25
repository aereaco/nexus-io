# Nexus-IO Deployment Profiles & Footprint Benchmarks

This document tracks the **exact, verified dependency footprint** of each Nexus-IO deployment profile against the current `Cargo.toml` feature graph, along with reproducible measurement commands.

---

## 1. Current Profile Dependency Graph (Verified `2026-11-25`)

Measured via `powershell -ExecutionPolicy Bypass -File scripts/check-footprint.ps1`:

| Profile | Unique Crates | Budget | What Is Compiled In | What Is Excluded |
| :--- | :---: | :---: | :--- | :--- |
| **`profile-core`** *(default)* | **422** | `<= 450` | **Wasmtime 51 + WASI**, **Nexus-DB** (kernel state), **BlobBridge + CasStore** (3-state ownership + fenced CAS leases), **UxGateway** (Salvo HTTP/WS), **IAM + CapabilitySet**, **NexusMetrics** | Native QuickJS (`js-native`), OXC (`ts-compiler`), OCI client (`oci-registry`), `sqlparser` (`sql-compat`), Nushell (`shell`), P2P Iroh (`p2p-storage`), S3 (`s3-gateway`), WireGuard (`vpn`), K8s (`k8s-bridge`), NVML (`hardware-monitoring`), WebViews (`gui`), SurrealDB (`surrealdb-ref`) |
| **`profile-app`** | **843** | — | `profile-core` + `oci-registry`, `sql-compat`, `js-runtime` (transitional `quickrs-core`), `ts-compiler` (OXC), `p2p-storage` (Iroh), `s3-gateway`, `pgwire`, `mysqlwire`, `sqlite-hrana`, `graphql`, `gql`, QUIC/ACME | Nushell (`shell`), K8s (`k8s-bridge`), WireGuard (`vpn`), NVML (`hardware-monitoring`), WebViews (`gui`), SurrealDB (`surrealdb-ref`) |
| **`profile-full`** | **1,226** | — | `profile-app` + `shell` (Nushell), `k8s-bridge`, `vpn` (WireGuard), `hardware-monitoring` (NVML), `nexus-db/full` | `gui` (opt-in), `surrealdb-ref` (opt-in) |
| **`profile-dev`** | — | — | `profile-full` + `surrealdb-ref` (live SurrealDB 4.0 differential conformance test harness) | — |

---

## 2. Empirical Release Benchmarks — 422-Crate Pure-Wasmtime `profile-core` (Verified `2026-11-25`)

Measured across **5 fresh process launches** (isolated temporary data directory per run, 2-second idle settle window before memory sampling):

| Measurement | Value |
| :--- | :--- |
| **Release executable size (`nexus.exe`, stripped)** | **15.87 MB** (`16,642,560` bytes) — **76.9% smaller** than legacy 849-crate `profile-core` (`68.78 MB`) |
| **Cold startup time (5 fresh launches, TCP port 8080 readiness)** | **Median: `1,036.27 ms`** (range: `1,019.78 ms – 1,889.85 ms`; runs 2–5: `1,019.78 – 1,044.02 ms`; run 1 includes OS cold page cache) |
| **Idle Working Set (`WorkingSet64`, 2s settled)** | **Median: `12.02 MB`** (range: `11.93 MB – 25.14 MB`) |
| **Idle Private Memory (`PrivateMemorySize64`, 2s settled)** | **Median: `4.43 MB`** (range: `4.18 MB – 4.70 MB`) |
| **Rust / Cargo versions** | `rustc 1.100.0 (0ef1bc386 2026-11-09)` / `cargo 1.100.0 (3acc79c0c 2026-11-05)` |
| **Build command & profile flags** | `cargo build --release --bin nexus --no-default-features --features profile-core` (`opt-level = "z"`, `lto = "thin"`, `codegen-units = 1`, `strip = true`) |
| **OS & Architecture** | `Microsoft Windows NT 10.0.26300.0` (`AMD64` / `x86_64`) |
| **Base revision** | `aerea-nexus@bd2adb25` + `OwnershipTx` boot replay & derived-cache AOT self-healing commit |

### Historical Reference (Legacy Pre-Wasmtime-Core Layout)

| Historical Profile (`96a3513c`) | Unique Crates | Release Binary (MB) | Idle RSS (MB) |
| :--- | :---: | :---: | :---: |
| `profile-core` (legacy layout with Nushell/OXC/QuickJS) | 849 | 68.78 MB | 5.41 MB |
| `profile-app` | — | 83.25 MB | 3.20 MB |
| `profile-full` | — | 86.36 MB | 14.28 MB |
| `profile-windows,gui` | — | 85.79 MB | 14.66 MB |

---

## 3. Reproducible Measurement Commands

```powershell
# 1. Verify profile crate-count budgets (profile-core <= 450)
powershell -ExecutionPolicy Bypass -File scripts/check-footprint.ps1

# 2. Build stripped release binary for pure-Wasmtime profile-core
cargo build --release --bin nexus --no-default-features --features profile-core

# 3. Measure binary size & live idle RSS (Windows PowerShell)
$exe = "target\release\nexus.exe"
[math]::Round((Get-Item $exe).Length / 1MB, 2)
$p = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3
[math]::Round((Get-Process -Id $p.Id).WorkingSet64 / 1MB, 2)
Stop-Process -Id $p.Id -Force
```
