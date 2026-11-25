# Nexus-IO Architecture Specification — Wasmtime Microkernel

## 1. Core Thesis
Nexus-IO replaces both full VMs and OS-level containers with a **single 100% MIT-licensed Rust microkernel** that runs **only the exact compiled Wasm binary** required by each workload, strictly isolated by declarative policy.

**Wasmtime 51 + WASI is the sole guest execution substrate.** JavaScript, TypeScript, PHP, Python, Go, Rust, and pluggable guest database engines (SQLite, PostgreSQL/PGlite, DuckDB, SurrealDB Wasm) all run inside the same zero-ambient-authority sandbox rather than linking competing native interpreters or compilers into the host binary.

```text
+-----------------------------------------------------------------------+
|                     Declarative Policy Layer                          |
|   CellPolicy (Pinned | Elastic)  |  CellDbConfig  |  IAM / Capability |
+-----------------------------------------------------------------------+
|                Installable Guest Wasm Modules (AOT .cwasm)            |
|  quickjs.wasm (JS) | ts-compiler.wasm | php-cgi.wasm | DB Wasm Guests |
+-------------------------[ nexus_host Syscall ABI ]--------------------+
|               Nexus-IO Sovereign Microkernel (`core`)                 |
|  CrystalEngine (Wasmtime 51) | Nexus-DB | CasStore | UxGateway | IAM  |
+-----------------------------------------------------------------------+
```

## 2. Host Primitives vs. Installable Guest Capabilities

| Layer | Provided By | Examples |
| :--- | :--- | :--- |
| **Host Microkernel (`core`)** | Compiled directly into `nexus` (~422 crates, 15.87 MB stripped) | Wasmtime 51 + WASI (`runtime-wasm`), `nexus-db` (`db-auth`, `db-cbor`), `BlobBridge` + `CasStore`, `UxGateway` (Salvo HTTP/WS), `IamMiddleware` + `CapabilitySet`, `NexusMetrics` |
| **Optional Host Domains** | Composed via semantic Cargo feature flags (`db-*`, `net-*`, `storage-*`, `serve-*`, `ops-*`, `gui-*`) | OCI Distribution v2 client (`runtime-oci`), `nexus-db` extensions (`db-fts`, `db-vector`, `db-pgwire`, `db-mysqlwire`, `db-sqlite`, `db-graphql`, `db-gql`), HTTP/3/ACME/VPN (`net-*`), Iroh P2P/S3 (`storage-*`), static web & proxy (`serve-*`), Nushell/K8s/GPU (`ops-*`), OS-autodetected WebView (`gui-webview`) |
| **Installable Guest Modules** | Pulled via OCI or uploaded to `WasmRuntimeRegistry` | JavaScript (`quickjs.wasm`), TypeScript transpilation (Wasm transpiler / pre-transpiled JS), PHP (`php-cgi.wasm`), Python/Ruby/Go/Rust WASI modules, Wasm database engines (`sqlite.wasm`, `pglite.wasm`, `duckdb.wasm`, `surrealdb.wasm`) |

## 3. The `nexus_host` Syscall ABI (`src/compute/crystal.rs`)
Every WASI guest module receives **zero ambient OS authority**. Host access is granted exclusively through four capability-checked linear-memory syscalls enforced against both `CellDbConfig` and `CapabilitySet`:

| Import (`nexus_host`) | Purpose | Policy Enforcement |
| :--- | :--- | :--- |
| `nexus_db_query(flavor, query, out)` | Execute DB query against cell's configured backend | Enforces `Capability::DbRead` / `DbWrite` + `CellDbConfig` (`mode`, `flavors`, `transports`, `read_only` Viewer RBAC) |
| `nexus_blob_put(bucket, key, val)` | Write content-addressed bytes to `BlobBridge` | Enforces `Capability::BlobWrite` |
| `nexus_blob_get(bucket, key, out)` | Read bytes from `BlobBridge` into guest memory | Enforces `Capability::BlobRead` |
| `nexus_log(ptr, len)` | Emit structured host log entries | Captured per invocation |

Return codes: `>= 0` bytes written/OK, `-1` missing host context, `-2` denied by `CellDbConfig`/IAM/CapabilitySet, `-3` execution/storage error, `-4` guest memory/buffer error.

## 4. Durable Storage, 3-State Reclamation & Startup Recovery (`CasStore` + `WasmDbMount`)
All persistent cell DB files and guest Wasm binaries share one content-addressed storage and ownership substrate (`src/storage/cas_store.rs`):

1. **3-State Ownership Reclamation (`Live → Tombstoned → Deleting`):**
   - `acquire_owner()` / `acquire_owners_batch()` fail fast with typed `BlobDeletingConflict { cid, claim_generation }` if a CID is under an active `DeleteClaim`.
   - `DeleteClaim` stays durable until physical deletion succeeds; expired claims (`30s` default TTL) are recovered idempotently.
2. **Single-CAS Atomic Fenced DB Commits (`WasmDbCellRecord`):**
   - Execution lease, monotonic `fencing_token`, and database filesystem manifest live in ONE CAS-managed record (`cells/<app>/<cell_id>/manifest.json`), eliminating the stale-writer commit window.
3. **Write-Ahead `OwnershipTx` Journal & Startup Boot Gate:**
   - Commit order: write blobs → persist `OwnershipTx` intent journal → acquire new CID ownership → single-CAS commit `WasmDbCellRecord` → release superseded CIDs → delete journal.
   - `UxGateway::start()` runs `reconcile_storage_on_boot()` across both `nexus-wasm-db` and `nexus-runtimes` **before** accepting traffic, and `/cells/*` routes enforce `BootRecoveryGateMiddleware` (`503 Service Unavailable`) until boot recovery succeeds.
   - On clean boots, `reconcile_on_boot()` avoids scanning data blobs (bounded by a `tx/` prefix listing); optional full orphan GC remains an explicit administrative/flagged pass.

## 5. Self-Healing Derived AOT Cache & OCI Distribution v2 (`WasmRuntimeRegistry`)
- **Authoritative Source vs. Derived Cache:** The owned, BLAKE3-verified `cid/<cid>` `.wasm` blob is always authoritative. AOT `.cwasm` files are reproducible derived caches stored at `aot-cid/<compat_key>/<cid>.cwasm`, framed with an `NXAOT01\0` + 32-byte BLAKE3 integrity envelope and published atomically via create-if-absent CAS.
- **Integrity Guarantees:** Deleting or corrupting any derived AOT cache entry transparently evicts and rebuilds from `cid/<cid>`. Corrupting the authoritative `cid/<cid>` source fails explicitly with a BLAKE3 integrity error (never falls through).
- **Hardened OCI Pulls (`runtime-oci`):** HTTPS enforced by default, Bearer credentials stripped on cross-origin redirects, SHA-256 verification of manifest & layers, strict Wasm media-type allowlist, streaming size caps, and `RuntimeTrustPolicy` (`TrustMode::AllowlistOnly` by default).

## 6. Declarative Application Manifest (`AppManifest`), Typed `Chart`s & Control Plane (`src/compute/manifest.rs`)
Application architecture and deployment topology are independent — the same application can start as a single-node **monolith**, evolve into **modular** local cells, and later target **mesh** placement without rewriting application code:

- **Wasmtime is implicit:** `api_version = "nexus.io/v1"` manifests never declare a host runtime. Every cell declares an immutable `blake3:<64-hex>` or digest-pinned `oci://...@sha256:<64-hex>` artifact, `CellDbConfig`, `CellResourceLimits`, default-deny `capabilities.allow`, and evolvable `topology` / `placement` / `lifecycle` / `migration` policies.
- **Authorization separated from declaration:** Manifests may only *request* capabilities. Effective capabilities are strictly `requested ∩ operator_policy ∩ deployer_iam ∩ cell_db_caps`.
- **Stateful safety:** Stateful cells reject `replicas > 1` and unimplemented `MigrationPolicy::Replicated` at `validate()`.
- **Deterministic typed `Chart`s:** `ChartPackage::resolve(&overrides)` applies typed `ChartValues` overrides with explicit precedence and produces a validated, reproducible `AppManifest` + canonical BLAKE3 digest (no string templating).
- **Desired-state reconciliation & Control Plane API:**
  - `POST /_nexus/deploy` (accepts TOML or JSON `AppManifest`, enforces `BootRecoveryGateMiddleware` + `IamMiddleware` + `Capability::CellSpawn`, persists `DeploymentOperation` in `CasStore` before mutating cells, returns `202 Accepted` + `operation_id`).
  - `GET /_nexus/deploy/{operation_id}` (inspect reconciliation status and plan).
  - `GET /_nexus/apps/{app_id}` (inspect reconciled `DeploymentRecord` and cell states).

## 7. Semantic Deployment Profiles (`Cargo.toml`)
- **`core`** *(default, 422 unique crates, 15.87 MB stripped)*: `runtime-wasm`, `db-auth`, `db-cbor` + `BlobBridge`/`CasStore` + `UxGateway` + `IAM` + `NexusMetrics`.
- **`full`** *(1,161 unique crates)*: `core` + `runtime-all`, `db-all`, `net-all`, `storage-all`, `serve-all`, `ops-all`.
- **Composable GUI:** `--features gui-all` (`gui-webview`) adds OS-autodetected native WebView (WebView2 / WKWebView / WebKitGTK / Android / iOS) to any profile.
