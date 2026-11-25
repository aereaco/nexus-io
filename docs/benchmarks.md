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

## 2. Historical Binary Size & Memory Reference (Pre-Wasmtime-Core Revision)

> **Note:** The release binary measurements below were captured on Windows x86_64 (`opt-level = "z"`, `lto = "thin"`, `codegen-units = 1`, `strip = true`) *prior* to moving Wasmtime into `profile-core` and removing Nushell/OXC/QuickJS from `profile-core` (when `profile-core` was 849 crates). Fresh release binary, cold-start, and RSS measurements for the current **422-crate pure-Wasmtime `profile-core`** should be re-recorded with the exact command below on a runner with ≥ 6 GB free disk space.

| Historical Profile (`96a3513c`) | Release Binary (MB) | Idle RSS (MB) |
| :--- | :---: | :---: |
| `profile-core` (legacy 849-crate layout) | 68.78 MB | 5.41 MB |
| `profile-app` | 83.25 MB | 3.20 MB |
| `profile-full` | 86.36 MB | 14.28 MB |
| `profile-windows,gui` | 85.79 MB | 14.66 MB |

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
