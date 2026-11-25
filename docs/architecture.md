# Nexus-IO Architecture Specification — Wasmtime Microkernel

## 1. Core Thesis
Nexus-IO replaces both full VMs and OS-level containers with a **single sovereign Rust microkernel** that runs **only the exact compiled Wasm binary** required by each workload, strictly isolated by declarative policy.

```text
+-----------------------------------------------------------------------+
|                     Declarative Policy Layer                          |
|   CellPolicy (Pinned | Elastic)  |  CellDbConfig  |  IAM / RBAC       |
+-----------------------------------------------------------------------+
|                     Guest Workloads (WASI / AOT .cwasm)               |
|  quickjs.wasm (JS/TS) | php-cgi.wasm (WP) | Python/Go/Rust | DB Wasms |
+-------------------------[ nexus_host Syscall ABI ]--------------------+
|                   Nexus-IO Sovereign Microkernel                      |
|  CrystalEngine (Wasmtime 51) | Nexus-DB | BlobBridge | UxGateway| IAM |
+-----------------------------------------------------------------------+
```

## 2. The `nexus_host` Syscall ABI (`src/compute/crystal.rs`)
Every WASI guest module receives **zero ambient OS authority**. Host access is explicitly granted through four capability-checked linear-memory syscalls:

| Import (`nexus_host`) | Purpose | Policy Enforcement |
| :--- | :--- | :--- |
| `nexus_db_query(flavor, query, out)` | Execute multi-flavor DB query (`surql`, `sqlite`, `postgres`, `mysql`, `graphql`, `gql`) | Checked against `CellDbConfig` (`mode`, `flavors`, `transports`, `read_only` Viewer RBAC) |
| `nexus_blob_put(bucket, key, val)` | Write content-addressed bytes to `BlobBridge` | Scoped to cell's `BlobBridge` context |
| `nexus_blob_get(bucket, key, out)` | Read bytes from `BlobBridge` into guest memory | Scoped to cell's `BlobBridge` context |
| `nexus_log(ptr, len)` | Emit structured host log entries | Captured per invocation |

Return codes: `>= 0` bytes written/OK, `-1` missing host context, `-2` denied by `CellDbConfig`/IAM, `-3` execution/storage error, `-4` guest memory/buffer error.

## 3. Declarative Per-Cell Database Policy (`CellDbConfig`)
Every app cell declares **both** its database topology (`CellDbMode`), exposed query flavors, and allowed connection transports (`CellDbTransport`):

* **`CellDbMode::None`**: Stateless cell — zero DB allocation or exposure.
* **`CellDbMode::Dedicated`**: Isolated `(app, cell_id)` kernel-native `nexus-db` instance.
* **`CellDbMode::Reference { target_app, target_cell_id, read_only }`**: Scoped cross-cell DB reference.
* **`CellDbMode::Mesh { cluster, target_app, target_cell_id, role }`**: Bound to the multi-node `ReplicationLog` WAL scaling mesh (`Leader`, `Follower`, `ReadReplica`).
* **`CellDbMode::WasmEngine { engine, module_cid, mount_path }`**: Runs a real database engine (`pglite.wasm`, `sqlite.wasm`, `duckdb.wasm`, or sandboxed `nexus-db.wasm`) inside Wasmtime via `WasmDbMount`, hydrating and flushing its virtual `/data` directory to `BlobBridge` (`nexus-wasm-db` bucket) for unified elastic hibernation and mesh replication.

Allowed connection transports (`CellDbTransport`): `Internal`, `HttpRest`, `WebSocketRpc`, `PgWire`, `MySqlWire`, `SqliteHrana`, `MeshWal`.

## 4. OCI Distribution v2 & Runtime Registry (`WasmRuntimeRegistry`)
Guest runtimes (`quickjs`, `php-cgi`, `sqlite`, `pglite`, `duckdb`, etc.) are distributed using standard **OCI Distribution v2** registries (GHCR, Wasm Directory / `wkg`, Docker Hub, Zot, or local mirrors) — never statically bloated into the host binary:
1. Pulled via `POST /cells/_runtimes/pull` (supporting `@aerea/<pkg>[:tag]` → `ghcr.io/aereaco/<pkg>:<tag>` and arbitrary `oci://registry/org/pkg:tag` references), uploaded via `PUT /cells/_runtimes/<name>`, or loaded from `NEXUS_RUNTIMES_DIR`.
2. Verified against the OCI manifest's **SHA-256 digest** before storage.
3. Optional `application/vnd.nexus.policy.v1+json` OCI layer declares **requested capabilities** (`default_cell_policy`, `max_fuel`, `max_memory_mb`, `requested_capabilities`, `db_flavors`, `wit_world`), which local IAM/operator policy always caps or approves.
4. Stored content-addressed by BLAKE3 CID in `BlobBridge` (`nexus-runtimes` bucket) and pre-compiled ahead-of-time into native `.cwasm` (`CrystalEngine::compile_aot`) on non-iOS hosts for sub-millisecond cold starts and Apple `W^X`-compliant execution on iOS.

## 5. Lean Microkernel Feature Boundaries
* **`profile-core`** excludes Nushell (`shell`), OXC (`ts-compiler`), P2P Iroh (`p2p-storage`), S3 (`s3-gateway`), WireGuard (`vpn`), Kubernetes bridge (`k8s-bridge`), NVML (`hardware-monitoring`), and native WebViews (`gui`).
* **`quickrs-core`** is isolated behind the transitional `js-native` feature flag as workloads standardize on `quickjs.wasm`.
