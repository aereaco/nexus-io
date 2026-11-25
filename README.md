# Nexus-IO — Policy-Isolated Sovereign Application Microkernel

> **Not the whole VM. Not the OS container. Just the exact compiled binary, secured and isolated by declarative policy.**

**Nexus-IO** is a 100% MIT-licensed, single-binary Rust microkernel built around **Wasmtime + WASI** as its universal compute primitive, paired with **Nexus-DB** (clean-room embedded multi-model database), **BlobBridge** (content-addressed storage & CAS hibernation), **UxGateway** (HTTP/WS/wire protocols), and **IAM** (RBAC & capability grants).

Every workload — **JavaScript/TypeScript (`quickjs.wasm`)**, **PHP/WordPress (`php-cgi.wasm`)**, **Python**, **Go**, **Rust**, **Ruby**, **Wasm OCI images**, and even **pluggable Wasm-hosted database engines (`sqlite.wasm`, `pglite.wasm`, `duckdb.wasm`, `nexus-db.wasm`)** — runs inside the exact same zero-ambient-authority sandbox, governed by declarative `CellPolicy` and `CellDbConfig`.

---

## The Virtualization Progression

| Generation | Unit of Isolation | Overhead | Portability |
| :--- | :--- | :--- | :--- |
| **1. Hardware VMs** | Guest kernel + full OS + app | GBs RAM, seconds to boot | Architecture-bound |
| **2. OS Containers** | Linux/Windows rootfs + libc + app | 100s MBs, wide syscall surface | OS-bound |
| **3. Nexus-IO Microkernel** | **Exact compiled Wasm binary + declarative policy** | **Sub-ms AOT cold start, KBs–MBs RAM** | **Linux, Windows, macOS, Android, iOS (`W^X`-safe `.cwasm`)** |

---

## Host Primitives vs. Installable Guest Modules

Nexus-IO strictly separates **host microkernel primitives** from **installable guest Wasm modules**:

- **Implemented in the host (`core`, 422 crates / 15.87 MB stripped):**
  1. **Compute (`CrystalEngine` + `WasmRuntimeRegistry`):** Wasmtime 51 + WASI Preview 1/2 sandbox with deterministic fuel metering, self-verifying derived AOT `.cwasm` caches (`NXAOT01` BLAKE3 envelopes keyed by `(compat_key, cid)`), zero ambient host authority, and the capability-enforced `nexus_host` syscall ABI.
  2. **State (`nexus-db` + `WasmDbMount`):** Embedded 100% MIT multi-model database (`nexus-db` SurrealQL + optional granular `db-*` extensions) and `WasmDbMount` single-CAS fenced virtual FS mounting for Wasm-hosted database engines.
  3. **Storage (`BlobBridge` + `CasStore`):** BLAKE3 content-addressed object store with 3-state `Live → Tombstoned → Deleting` reclamation, write-ahead `OwnershipTx` journaling, and mandatory startup recovery (`UxGateway::reconcile_storage_on_boot()`).
  4. **Network (`UxGateway`):** Salvo HTTP/WebSocket ingress, `/cells/<app>/<cell_id>` routing, `/cells/_runtimes/<name>` registry API, and fail-closed `BootRecoveryGateMiddleware`.
  5. **Security (`IAM` + `CapabilitySet` + `CellDbConfig`):** Argon2id + HS256/EdDSA/ES256/RS256 JWT + RBAC (`OWNER`/`EDITOR`/`VIEWER`) + syscall-level `CapabilitySet` enforcement.
- **Supplied by installable guest Wasm modules (not linked into the host binary):**
  - **JavaScript / TypeScript:** Executed via Wasm guest runtimes (e.g. `quickjs.wasm`); TypeScript must be pre-transpiled or compiled by a Wasm transpiler module (no native QuickJS or OXC crates in the host).
  - **Relational & External Database Engines:** Real SQLite (`sqlite.wasm`), PostgreSQL (`pglite.wasm`), DuckDB (`duckdb.wasm`), or SurrealDB (`surrealdb.wasm`) run as isolated Wasm guests mounted through `CellDbMode::WasmEngine`, rather than host-side SQL translation.
  - **Polyglot App Runtimes:** PHP (`php-cgi.wasm`), Python, Ruby, Go, Rust, etc., pulled via OCI Distribution v2 (`runtime-oci`) or uploaded directly.

---

## Deployment Profiles & Semantic Feature Domains

| Profile | Included Capabilities |
| :--- | :--- |
| **`core`** *(default)* | Pure microkernel: `runtime-wasm` (Wasmtime 51 + WASI), `nexus-db` (`db-auth`, `db-cbor`), `BlobBridge + CasStore`, `UxGateway` (HTTP/WS), `IAM + CapabilitySet`, `NexusMetrics` |
| **`full`** | `core` + `runtime-all` + `db-all` + `net-all` + `storage-all` + `serve-all` + `ops-all` *(headless-safe; compose any profile with `gui-all` for OS-autodetected native WebView)* |

| Domain | Granular Flags | Bundle Flag | Maturity |
| :--- | :--- | :--- | :--- |
| **Runtime** | `runtime-wasm` *(in `core`)*, `runtime-oci` | `runtime-all` | **Implemented** (Wasmtime 51 + WASI, hardened OCI v2, self-verifying `NXAOT01` AOT cache) |
| **Database (`nexus-db`)** | `db-auth`, `db-cbor`, `db-fts`, `db-vector`, `db-files`, `db-geo`, `db-crypto`, `db-ml`, `db-graphql`, `db-gql`, `db-pgwire`, `db-mysqlwire`, `db-sqlite` | `db-all` | **Implemented** (core SurrealQL/auth/CBOR) / **Partial** (wire listeners `db-pgwire`, `db-mysqlwire`, `db-sqlite` subset) |
| **Network** | `net-http3`, `net-acme`, `net-openapi`, `net-vpn` | `net-all` | **Experimental** (`net-vpn` WireGuard, ACME/HTTP3 integration) |
| **Storage** | `storage-p2p`, `storage-s3` | `storage-all` | **Implemented** (local CAS + `CasStore` WAL/3-state reclamation) / **Experimental** (`storage-p2p` Iroh, `storage-s3`) |
| **Serve** | `serve-web`, `serve-proxy` | `serve-all` | **Implemented** (`serve-web` static + SPA fallback; `serve-proxy` SSRF-hardened, DNS-pinned Hyper HTTP/1.1 reverse proxy) |
| **Operations** | `ops-shell`, `ops-k8s`, `ops-gpu` | `ops-all` | **Experimental** (Nushell CLI, K8s YAML bridge, NVML GPU telemetry) |
| **GUI** | `gui-webview` *(OS-autodetected: WebView2 / WKWebView / WebKitGTK / Android / iOS)* | `gui-all` | **Experimental** (OS-native WebView shell) |
| **Guest Languages & External DBs** | *(Loaded into `WasmRuntimeRegistry` — no host flags)* | — | **Guest-provided** (`quickjs.wasm`, TS transpiler Wasm, `php-cgi.wasm`, `sqlite.wasm`, `pglite.wasm`, `duckdb.wasm`, `surrealdb.wasm`) |

> **Maturity definitions:** **Implemented** = functional host-side implementation with automated tests; **Partial** = working protocol subset (not full upstream parity); **Guest-provided** = supplied by an installable Wasm module rather than the host binary; **Experimental** = available for opt-in use, not yet production-hardened.

---

## Quick Start

```bash
# Run the lean microkernel daemon (Wasmtime + Nexus-DB + UxGateway + IAM)
cargo run --no-default-features --features core

# Compose exact domains (e.g. core + OCI pulls + web server + native OS WebView)
cargo run --no-default-features --features core,runtime-oci,serve-all,gui-all

# Run unit tests
cargo test --lib --no-default-features --features core
```

See [docs/architecture.md](docs/architecture.md) for the full microkernel ABI, `CellDbConfig` policy model, and Wasm-hosted DB lifecycle, and [docs/benchmarks.md](docs/benchmarks.md) for measured binary size and memory footprint across profiles.
