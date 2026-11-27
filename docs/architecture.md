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

## 7. Decentralized P2P WireGuard Mesh Fabric & 4D Scheduler (`src/storage/wireguard.rs`, `src/storage/mesh.rs`, `src/compute/router.rs`)
Every Nexus-IO node participates in a decentralized, peer-to-peer compute and storage fabric without a central master node:

- **Deterministic Cryptographic WireGuard Addressing (`src/storage/wireguard.rs`):**
  - Each peer's 32-byte X25519 WireGuard public key deterministically hashes via BLAKE3 into a collision-resistant IPv4 CGNAT address (`100.64.0.0/10` via `derive_mesh_ipv4`) and an IPv6 ULA address (`fd00:6e78::/32` via `derive_mesh_ipv6`), formatted directly into cross-platform Userspace WireGuard UAPI frames (`format_uapi_set_peers`).
- **4D Node Resource Telemetry & Gossip Replication (`src/compute/telemetry.rs`, `src/storage/mesh.rs`):**
  - Nodes advertise real-time 4D capacity (`NodeResources`: CPU cores/load, GPU/VRAM, Memory free/total, Storage disk free/total, green-energy status, and placement labels) via `MeshGossipPayload`.
  - `MeshReactor::ingest_gossip()` applies CRDT Last-Write-Wins (LWW) updates into both the `peer_registry` redb table and the `sys::node` SurrealQL system table.
- **4D Compute + Data-Locality Scheduler (`src/compute/router.rs`):**
  - When a cell targets `PlacementTarget::Mesh`, `InferenceRouter::select_ranked_nodes()` filters and scores all live peers across 4 dimensions (CPU headroom, GPU/VRAM availability, free RAM, free disk storage), adds a **+25.0 BLAKE3 Highest Random Weight (HRW) Rendezvous Hashing data-locality bonus** when a peer already hosts the cell's artifact shard (`select_hrw_replicas`), and applies a **+10.0 green energy bonus**.
- **P2P Mesh HTTP Endpoints & Authenticated Multi-Node Data Plane (`src/ux/gateway.rs`, `src/storage/mesh.rs`, `src/ux/cell_router.rs`):**
  - `GET /_nexus/mesh/status` — Returns active WireGuard tunnel addresses, UAPI configuration preview, and live 4D peer telemetry snapshot.
  - `POST /_nexus/mesh/gossip` — Ingests peer WireGuard + 4D telemetry heartbeats and returns deterministic mesh IPv4/IPv6 assignments; `MeshReactor::push_gossip_to_peer` exchanges 4D cluster state across live nodes.
  - `GET / PUT /_nexus/mesh/blobs/{cid}` — Content-addressed P2P binary blob transfer with end-to-end BLAKE3 verification; `MeshReactor::hydrate_blob_from_peer` streams, verifies, and atomically acquires `CasStore` ownership.
  - **Transparent Remote Cell Dispatch (`CellGatewayHandler`):** When a cell targets `PlacementTarget::Mesh` and is assigned to a remote peer, requests are transparently forwarded with caller identity/delegation headers, bounded hop count (`MAX_MESH_HOPS = 3`), visited-node cycle detection (`508 Loop Detected`), and peer failover (`502 Bad Gateway` when all assigned peers are unreachable).

## 8. Universal Host Foundation: `NexusSharedArena`, Native Hardware HAL & Dual-Mode OS UI (`src/arena.rs`, `src/hardware/mod.rs`, `wit/nexus-host.wit`)
Nexus-IO acts as a **universal application runtime** shared across all Wasm hosted guests (Rust, Go, Python, PHP, QuickJS/TS) and Nexus-UX frontends across Windows, Linux, macOS, Android, iOS, and headless edge nodes:

- **General-Purpose Data Plane (`src/arena.rs` — `NexusSharedArena`):**
  - Provides explicitly bounded `u32` generation-validated handles (`SharedBufferHandle`, `RingBufferHandle`, `BufferLease`), exclusive `RingProducer`/`RingConsumer` endpoints, and lock-free `SpscRingBuffer` streams with runtime-enforced single-producer/single-consumer exclusivity (`Err(ArenaError::Busy)` on same-side concurrency).
  - Uses a 64-bit linearized `LifecycleGate` (`REVOKED_BIT` + active-op count) so `revoke_owner()` drains all in-flight operations before returning, preventing post-revocation cursor publication.
  - Currently implements `TransportMode::PortableCopy` (direct slice transfer to/from Wasm linear memory with zero intermediate heap `Vec` and zero serialization); `TransportMode::SharedMemory` explicitly returns `UnsupportedTransport` until real imported Wasm shared-memory mapping is wired.
- **Capability-Oriented Hardware Discovery & Live OS Consent (`src/hardware/mod.rs`):**
  - Separates device discovery (`HardwareClass::Camera`, `Audio`, `Sensor`, `Gpu`, `OsUi`, etc.) from authority (`Capability::HwInfo`, `HwCamera`, `HwAudio`, `HwSensor`, `HwBus`, `HwGpu`, `HwBiometrics`, `OsUi`, `OsClipboard`).
  - Enforces $C_{\text{effective}} = C_{\text{requested}} \cap C_{\text{operator}} \cap C_{\text{IAM}} \cap C_{\text{OS}}$, querying live OS permission state (`ConsentState::NotDetermined | Granted | Denied | Restricted | Unsupported`) via `ConsentProvider` rather than trusting cached grants.
- **Dual-Mode OS UI (`OsShellProvider` + Versioned Retained-Mode `UiOpHeader`):**
  - Apps choose freely between Native WebView (`gui-webview`) and Native OS Shell/Widget APIs (`ui.window.*`, `ui.dialog.*`, `ui.notify.*`, `ui.tray.*`, `ui.clipboard.*`, `ui.haptics.*`, plus the 16-byte fixed binary `UiOpHeader` batch protocol).
- **Dual Interface Contract (`nexus_host` C-ABI + `wit/nexus-host.wit`):**
  - `nexus_host` Preview 1 C-ABI imports (`nexus_hw_list`, `nexus_hw_call`, `nexus_ui_commit_ops`, `nexus_ring_alloc`, `nexus_ring_write`, `nexus_ring_read`) are active today and route directly to `HardwareRegistry` and `NexusSharedArena`.
  - `wit/nexus-host.wit` (`package nexus:host@0.1.0`) defines the canonical Component Model contract to be bound to the same `HardwareRegistry::dispatch_authorized` & `NexusSharedArena` backend.
  - Gateway exposes `GET /_nexus/hardware` and `POST /_nexus/hardware/call` (strictly IAM + capability gated).

## 9. Federated Nexus Registry & `nexus install` (`src/registry/mod.rs`, `src/ux/gateway.rs`)
Nexus-IO serves as a self-hosted, federated Wasm & application registry backed directly by `CasStore` (immutable BLAKE3 blobs) and `nexus-db` (`sys::registry_release`) — requiring **zero external Docker Registry or Harbor**:

- **Unified Package References (`PackageRef`):** Supports `github:<owner>/<repo>[/<subpath>]@<ref>`, `oci://<host>/<repo>[:<tag>|@sha256:...]`, short-form `<namespace>/<package>@<version>`, and immutable `blake3:<64-hex>`.
- **Security Invariants:** Mandatory digest pinning, BLAKE3 checksum verification before acceptance, optional provenance/signature metadata, strict `AppManifest::validate()` before activation, zero install-script execution, and IAM + `Capability::RuntimeInstall` namespace authorization.
- **Self-Hosted OCI v2 & Nexus Registry Endpoints:** `GET /v2/`, `GET/PUT /v2/{ns}/{repo}/blobs/{digest}`, `GET/PUT /v2/{ns}/{repo}/manifests/{reference}`, `GET /_nexus/registry/packages`, `POST /_nexus/registry/install`, plus CLI `nexus install <ref>`.

## 10. Nexus-IDP: Identity-First, Hierarchical Organizations & Universal Authorization (`src/iam/idp.rs`, `src/ux/gateway.rs`)
Nexus-IO embeds a universal, zero-mode Identity & Access Management engine backed by `nexus-db` (`nexus::system`) using standard workspace cryptography (**Argon2id** + **Ed25519 `EdDSA`**, **0 new crates in `core`**):
- **Identity-First Sovereignty (`NEXUS-ID-v1`):** `Identity` exists independently of every `Organization`. Self-certifying portable ID `nxid_<BLAKE3("NEXUS-ID-v1" || T || N || K_0)>` with Ed25519 signed genesis proof, signed key-rotation chain, and standalone cross-cluster portable package verification (`POST /_nexus/iam/identities`, `POST /_nexus/iam/identities/import`). Revoking an org membership revokes org-scoped tokens without deleting the holder's identity or personal data.
- **Arbitrary-Depth Hierarchical Organizations:** `Organization` uses an immutable `org_id`, human-readable `slug`, `parent_org_id`, and **immutable-ID materialized `path`** (`/org_root/org_emea/org_de`), bounded by configurable `HierarchyLimits` (`max_depth`, `max_subtree_size`) with indexed cycle detection and serialized O(k) descendant path updates on reparenting (where k is the number of affected descendants).
- **Hierarchy != Authorization (`OrgMembership` + `DelegationScope`):** Parent org administration does not implicitly grant child org authority. Memberships carry explicit, auditable, revocable scopes (`SelfOnly`, `Descendants`, `Subtree`, `Selected`), roles resolve to permission bundles, and `POST /_nexus/iam/evaluate` enforces scoped server-side policy decisions.
- **Policy-Specific Composition:** `GET/PUT /_nexus/iam/orgs/{org_id}/policy` composes ancestor policies with per-field semantics (`mfa_required` monotonic tighten-only, `min_password_length` max, `max_session_ttl_secs` min, `allowed_auth_methods` intersection, `branding`/`login_theme` overrideable) and explicit provenance (`InheritedEnforced`, `InheritedDefault`, `LocallyOverridden`, `ProhibitedByParent`).
- **OIDC / OAuth 2.1, TOTP MFA & Forward-Auth Outpost:** `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` (RFC 8037 `OKP`/`Ed25519`), `POST /oauth/v2/authorize` (mandatory PKCE `S256`), `POST /oauth/v2/token` (Argon2id client secrets, EdDSA `id_token`, rotating `refresh_token` with automatic token-family replay revocation, `client_credentials` M2M), `GET /oidc/v1/userinfo`, `POST /oauth/v2/{revoke,introspect}`, RFC 6238 TOTP (`/_nexus/iam/mfa/totp/{enroll,verify}`), immutable `sys_iam_audit`, and `GET /_nexus/outpost/auth`.
- **Declarative Authentication Flow Engine (`src/iam/flows.rs`):** Versioned `AuthFlow` & composable `AuthStage` pipeline (`Identification`, `OrgDiscovery`, `PasswordVerify`, `TotpVerify`, `WebAuthnAssert`, `RecoveryCode`, `ExternalProvider`, `ConditionalBranch`, `WasmPolicyStage`, `Consent`) with 3-tier `AuthAuthority` (`IdentityControlled`, `OrganizationRequired`, `Federated`), retry lockout, hard timeout, immutable per-stage audit, and an unbypassable native `ComposedOrgPolicy` completion gate (`/_nexus/iam/flows*`).
- **W3C WebAuthn / FIDO2 Passkeys (`src/iam/webauthn.rs`):** Nexus-owned `WebAuthnProvider` abstraction and `WebAuthnService` (single-use exact-origin challenges, synced passkey backup-eligibility handling, hardware sign-count clone detection, credential lifecycle & revocation at `/_nexus/iam/webauthn/*`), backed by pinned `webauthn-rs = "=0.6.2"` (`MPL-2.0`) behind optional `--features iam-webauthn` (included in `full`; omitted in `core`).

## 11. Semantic Deployment Profiles (`Cargo.toml`)
- **`core`** *(default, 422 unique crates, 15.87 MB stripped)*: `runtime-wasm`, `db-auth`, `db-cbor` + `BlobBridge`/`CasStore` + `UxGateway` + `IAM` + `NexusMetrics`.
- **`full`** *(1,161 unique crates)*: `core` + `runtime-all`, `db-all`, `net-all`, `storage-all`, `serve-all`, `ops-all`.
- **Composable GUI:** `--features gui-all` (`gui-webview`) adds OS-autodetected native WebView (WebView2 / WKWebView / WebKitGTK / Android / iOS) to any profile.
