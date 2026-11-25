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

## The 5 Native Microkernel Primitives (`profile-core`)

Everything in `profile-core` is strictly limited to the five sovereign host primitives — heavy non-kernel tools (interactive Nushell, OXC TypeScript compiler, P2P Iroh, S3 gateway, Kubernetes bridge, WireGuard VPN, NVML GPU monitoring, native WebView GUI) are **opt-in capabilities**:

1. **Compute (`CrystalEngine` + `WasmRuntimeRegistry`):** Wasmtime 51 + WASI Preview 1/2 sandbox with deterministic fuel metering, AOT `.cwasm` precompilation (cached in `BlobBridge`), zero ambient host authority, and the unified `nexus_host` syscall ABI (`nexus_db_query`, `nexus_blob_get`, `nexus_blob_put`, `nexus_log`).
2. **State (`nexus-db` + `WasmDbMount`):** Kernel-native clean-room multi-model DB (SurrealQL, SQLite/Postgres/MySQL SQL, GraphQL, ISO GQL, vector HNSW, FTS, RBAC, WAL) **plus** per-cell `CellDbMode::WasmEngine` to mount real Wasm database engines (`pglite.wasm`, `sqlite.wasm`, `duckdb.wasm`) backed by `BlobBridge` virtual FS persistence.
3. **Storage (`BlobBridge`):** Local BLAKE3 content-addressed object store with CAS single-writer leases (optional distributed `iroh-blobs` P2P + `s3s` S3 gateway in `profile-app`).
4. **Network (`UxGateway`):** Salvo HTTP/WebSocket ingress, `/cells/<app>/<cell_id>` routing, `/cells/_runtimes/<name>` registry API, and opt-in PostgreSQL v3 (`pgwire`), MySQL v10 (`mysqlwire`), and LibSQL/Turso Hrana (`sqlite-hrana`) wire listeners.
5. **Security (`IAM` + `CellDbConfig`):** Argon2id + HS256/EdDSA/ES256/RS256 JWT + RBAC (`OWNER`/`EDITOR`/`VIEWER`) + per-cell declarative database topology (`none`, `dedicated`, `reference`, `mesh`, `wasm_engine`), allowed query flavors, and allowed connection transports.

---

## Deployment Profiles

| Profile | Included Capabilities |
| :--- | :--- |
| **`profile-core`** *(default)* | Microkernel only: `wasm-runtime` (Wasmtime + WASI), `database` (`nexus-db`), `gateway`, `cells`, `iam` (zero Nushell, zero OXC, zero P2P/S3/VPN bloat) |
| **`profile-app`** | `profile-core` + `ts-compiler` (OXC), `p2p-storage`, `s3-gateway`, `pgwire`, `mysqlwire`, `sqlite-hrana`, `graphql`, `gql`, QUIC/ACME |
| **`profile-full`** | `profile-app` + `shell` (Nushell), `k8s-bridge`, `vpn` (WireGuard), `hardware-monitoring` (NVML), `nexus-db/full` |
| **`profile-dev`** | `profile-full` + `surrealdb-ref` (live SurrealDB 4.0 differential conformance test harness) |
| **`profile-{windows,linux,macos,android,ios}`** | OS-tailored profiles (combine with `--features gui` for native OS WebView2 / WKWebView / WebKitGTK; iOS is strictly `W^X`-safe AOT `.cwasm`) |

---

## Quick Start

```bash
# Run the lean microkernel daemon (Wasmtime + Nexus-DB + UxGateway + IAM)
cargo run --no-default-features --features profile-core

# Register a WASI guest runtime (e.g. quickjs.wasm, php-cgi.wasm, sqlite.wasm, pglite.wasm)
# Automatically stored content-addressed in BlobBridge and AOT-precompiled to .cwasm:
curl -X PUT --data-binary @quickjs.wasm http://127.0.0.1:8080/cells/_runtimes/quickjs

# Deploy a JS/TS cell onto Wasmtime (`quickjs.wasm`)
curl -X PUT -H "X-Nexus-Runtime: js-wasm" --data-binary @app.js http://127.0.0.1:8080/cells/demo/api

# Deploy a WASI CGI cell (e.g. PHP/WordPress `php-cgi.wasm`)
curl -X PUT -H "X-Nexus-Runtime: wasi-cgi" --data-binary @php-cgi.wasm http://127.0.0.1:8080/cells/blog/wp

# Configure a cell's declarative database policy (stateless, dedicated, reference, mesh, or wasm_engine)
curl -X PUT -H "Content-Type: application/json" \
  -d '{"mode":{"wasm_engine":{"engine":"pglite","module_cid":"pglite","mount_path":"/data"}},"flavors":["postgres"],"transports":["internal","http_rest"]}' \
  http://127.0.0.1:8080/cells/shop/orders/db-config

# Run unit tests
cargo test --lib --no-default-features --features profile-core
```

See [docs/architecture.md](docs/architecture.md) for the full microkernel ABI, `CellDbConfig` policy model, and Wasm-hosted DB lifecycle, and [docs/benchmarks.md](docs/benchmarks.md) for measured binary size and memory footprint across profiles.
