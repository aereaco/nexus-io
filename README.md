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

## The 5 Native Microkernel Primitives (`core`)

Everything in `core` is strictly limited to the five sovereign host primitives — Wasmtime 51 is the **sole** guest runtime (JS, TS, Python, PHP, SQLite, Postgres, SurrealDB all run as Wasm modules), and all additional platform domains are cleanly opt-in:

1. **Compute (`CrystalEngine` + `WasmRuntimeRegistry`):** Wasmtime 51 + WASI Preview 1/2 sandbox with deterministic fuel metering, self-verifying derived AOT `.cwasm` caches (`NXAOT01` BLAKE3 envelopes keyed by `(compat_key, cid)`), zero ambient host authority, and the unified `nexus_host` syscall ABI (`nexus_db_query`, `nexus_blob_get`, `nexus_blob_put`, `nexus_log`).
2. **State (`nexus-db` + `WasmDbMount`):** Kernel-native 100% MIT multi-model DB (`nexus-db`) **plus** per-cell `CellDbMode::WasmEngine` to mount real Wasm database engines (`pglite.wasm`, `sqlite.wasm`, `duckdb.wasm`, `surrealdb.wasm`) backed by single-CAS fenced `WasmDbCellRecord` leases and WAL `OwnershipTx` journals.
3. **Storage (`BlobBridge` + `CasStore`):** Local BLAKE3 content-addressed object store with 3-state `Live → Tombstoned → Deleting` reclamation and write-ahead ownership journaling (optional `storage-p2p` Iroh + `storage-s3` S3 gateway).
4. **Network (`UxGateway`):** Salvo HTTP/WebSocket ingress, `/cells/<app>/<cell_id>` routing, `/cells/_runtimes/<name>` registry API, and opt-in `net-*` (`net-http3`, `net-acme`, `net-openapi`, `net-vpn`) + `serve-*` (`serve-web`, `serve-proxy`) capabilities.
5. **Security (`IAM` + `CapabilitySet` + `CellDbConfig`):** Argon2id + HS256/EdDSA/ES256/RS256 JWT + RBAC (`OWNER`/`EDITOR`/`VIEWER`) + syscall-level `CapabilitySet` enforcement + per-cell declarative database topology.

---

## Deployment Profiles & Semantic Feature Domains

| Profile | Included Capabilities |
| :--- | :--- |
| **`core`** *(default)* | Pure microkernel: `runtime-wasm` (Wasmtime 51 + WASI), `nexus-db` (`db-auth`, `db-cbor`), `BlobBridge + CasStore`, `UxGateway` (HTTP/WS), `IAM + CapabilitySet`, `NexusMetrics` |
| **`full`** | `core` + `runtime-all` + `db-all` + `net-all` + `storage-all` + `serve-all` + `ops-all` *(headless-safe; compose any profile with `gui-all` for OS-autodetected native WebView)* |

| Domain | Granular Flags | Bundle Flag |
| :--- | :--- | :--- |
| **Runtime** | `runtime-wasm` *(in `core`)*, `runtime-oci` | `runtime-all` |
| **Database (`nexus-db`)** | `db-auth`, `db-cbor`, `db-fts`, `db-vector`, `db-files`, `db-geo`, `db-crypto`, `db-ml`, `db-graphql`, `db-gql`, `db-pgwire`, `db-mysqlwire`, `db-sqlite` | `db-all` |
| **Network** | `net-http3`, `net-acme`, `net-openapi`, `net-vpn` | `net-all` |
| **Storage** | `storage-p2p`, `storage-s3` | `storage-all` |
| **Serve** | `serve-web`, `serve-proxy` | `serve-all` |
| **Operations** | `ops-shell`, `ops-k8s`, `ops-gpu` | `ops-all` |
| **GUI** | `gui-webview` *(OS-autodetected: WebView2 / WKWebView / WebKitGTK / Android / iOS)* | `gui-all` |

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
