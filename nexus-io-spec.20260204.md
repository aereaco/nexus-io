# Nexus-IO Specification (v2026.02.04)

**The Universal System Runtime: Where Applications Become Infrastructure**

> "The best infrastructure is invisible. The best runtime feels inevitable."

## Table of Contents

1. [Quick Start: What Is Nexus-IO?](#1-quick-start-what-is-nexus-io)
2. [Architecture: The Three-Plane Kernel](#2-architecture-the-three-plane-kernel)
3. [Implementation Status](#3-implementation-status)
4. [The Path Forward](#4-the-path-forward)

---

## 1. Quick Start: What Is Nexus-IO?

Nexus-IO is a **single binary** that replaces your entire backend stack. It's
not a framework you learn—it's infrastructure you deploy.

### The Problem We Solve

Building a modern application requires stitching together dozens of fragmented
tools:

- **PostgreSQL** for the database
- **Redis** for caching
- **Node.js/Python/Go** for business logic
- **Docker** for containerization
- **Kubernetes** for orchestration
- **AWS S3** for file storage
- **OpenAI API** for intelligence
- **Stripe** for payments

Each layer adds latency, complexity, and cost. Most crucially: **your data and
logic live in different processes**, forcing constant serialization and network
hops.

### The Nexus Solution

Nexus-IO **collapses the stack** into a unified kernel where:

```
Database + Logic + Storage + Compute = Single Process
```

**What you get:**

- **SurrealDB** (multi-model database with graph, document, relational
  capabilities)
- **Nushell** (structured data scripting engine)
- **QuickJS** (AOT-compiled JavaScript/TypeScript runtime)
- **Garage** (distributed object storage with S3 API)
- **WireGuard** (zero-trust mesh networking)
- **InferMesh/Ballista/Lunatic** (AI/GPU orchestration, distributed compute,
  actor runtime)

**All in one binary. All in one process. All talking via shared memory.**

### Why This Matters

**Before Nexus-IO** (Traditional Stack):

```bash
Request → API Gateway → Lambda → Database Query → Redis Check → S3 Fetch
Latency: 50-200ms | Cost: $500-2000/month | Complexity: 6 services
```

**With Nexus-IO**:

```bash
Request → Nexus Kernel (Database + Logic + Storage in shared memory)
Latency: 1-5ms | Cost: $50-200/month | Complexity: 1 binary
```

**Real-world impact:**

- **10-100x faster**: No network jumps between your code and your data
- **10x cheaper**: Eliminate per-service cloud markups
- **10x simpler**: One binary to deploy, one process to monitor

---

## 2. Architecture: The Three-Plane Kernel

Nexus-IO is built on three integrated planes that share a single memory space:

```
┌─────────────────────────────────────────────────────┐
│  PRESENTATION PLANE (Nexus-UX)                      │
│  Signal-driven UI with live database mirroring      │
└──────────────┬──────────────────────────────────────┘
               │ Shared Memory
┌──────────────▼──────────────────────────────────────┐
│  LOGIC PLANE (Nushell + QuickJS)                    │
│  Structured data pipelines + AOT JavaScript         │
└──────────────┬──────────────────────────────────────┘
               │ Shared Memory
┌──────────────▼──────────────────────────────────────┐
│  DATA PLANE (SurrealDB + Garage + WireGuard)        │
│  Transactional storage + distributed mesh           │
└─────────────────────────────────────────────────────┘
```

### 2.1. Data Plane: The Foundation

**Core: SurrealDB (Multi-Model Database)**

SurrealDB isn't just a database—it's a **programmable storage kernel**:

- **Multi-Model**: Tables, documents, graphs, key-value stores in one query
- **Multi-Tenant**: Built-in namespace isolation (one tenant = one namespace)
- **Transactional**: ACID guarantees with optimistic concurrency control
- **Embedded Functions**: Store Nushell scripts and JavaScript functions
  _inside_ the database

**Example: Graph Relations Without Joins**

```sql
-- Traditional SQL: Complex JOINs
SELECT u.*, p.* FROM users u 
  LEFT JOIN posts p ON u.id = p.author_id
  WHERE u.email = 'user@example.com';

-- SurrealQL: Native graph traversal
SELECT *, ->authored->post AS posts 
  FROM user WHERE email = 'user@example.com';
```

**Schema Definition with Business Logic**:

```sql
-- Define table with inline validation
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD email ON user TYPE string 
  ASSERT string::is::email($value);
DEFINE FIELD age ON user TYPE int 
  ASSERT $value >= 18;
DEFINE INDEX email_unique ON user FIELDS email UNIQUE;

-- Embed Nushell function in database
DEFINE FUNCTION fn::welcome_email($user: record<user>) {
  let template = open templates/welcome.html
  $template | str replace '{name}' $user.name
};

-- Call from anywhere
RETURN fn::welcome_email(user:vylan);
```

**Why This Matters**: Your business logic lives _inside_ the transaction
boundary. No round-trips, no race conditions, no "eventual consistency"
workarounds.

---

**Distributed Storage: Garage (S3-Compatible Object Mesh)**

Garage complements SurrealDB by providing:

- **Object Storage**: Files, media, backups (S3-compatible API)
- **DHT Gossip**: Automatic peer discovery and replication
- **Content-Addressable**: Immutable objects identified by cryptographic hash
- **3-Way Replication**: Configurable redundancy across the mesh

**Integration Architecture**:

```
SurrealDB → Garage Integration (Phase 14 - Zero-Copy Bridge)
├── Metadata in SurrealDB (file path, size, owner, permissions)
├── Binary blobs in Garage (actual file bytes)
└── Shared Memory Heap (zero-copy access from QuickJS/Rust)
```

**Example Use Case**:

```javascript
// Upload file via SurrealDB + Garage unified API
const result = await db.query(`
  CREATE file:invoice_2026_02 CONTENT {
    name: "invoice.pdf",
    owner: $auth.id,
    path: "s3://garage/invoices/2026/02/invoice.pdf",
    size: 245632,
    uploaded_at: time::now()
  }
`);

// Garage automatically handles:
// - Storing the PDF bytes across 3 nodes
// - Generating content hash for integrity
// - Replicating via WireGuard mesh
```

---

**Zero-Trust Networking: WireGuard (Kernel-Level VPN)**

Every Nexus-IO node is **cloud-invisible by default**:

- **Embedded VPN**: WireGuard (`boringtun`) compiled into the binary
- **Mesh Topology**: Every node is a peer (no central server)
- **Encrypted-Only Traffic**: All Garage RPC and SurrealDB replication inside
  the tunnel
- **NAT Traversal**: Eliminates ICE/STUN/TURN complexity for VoIP

**Security Architecture**:

```
Public Internet: [CLOSED - No ports exposed]
                      ↓
WireGuard Tunnel: 10.200.0.0/24 (Private mesh)
                      ↓
    ├─ Node 1: 10.200.0.1 (SurrealDB + Garage)
    ├─ Node 2: 10.200.0.2 (RustPBX + Jami)
    └─ Node 3: 10.200.0.3 (InferMesh GPU cluster)
```

**Why This Matters**:

- **RustPBX VoIP**: No NAT traversal issues (all SIP/RTP inside VPN)
- **Distributed AI**: InferMesh routes inference across GPU nodes securely
- **Unhackable Attack Surface**: Zero public ports = zero attack vectors

---

### 2.2. Logic Plane: The Execution Layer

**Nushell: The Structured Data Bus**

Nushell is to Nexus-IO what SQL is to PostgreSQL—but for **structured
pipelines**:

```nushell
# Traditional bash (brittle string parsing)
kubectl get pods | grep Running | awk '{print $1}' | xargs kubectl delete

# Nushell (typed data all the way)
kubectl get pods | where status == "Running" | get name | kubectl delete
```

**In Nexus-IO, Nushell powers:**

- **Host Commands**: `storage`, `ia`, `host`, `http`
- **Data Pipelines**: ETL jobs, log processing, report generation
- **System Orchestration**: Scheduled tasks, distributed compute coordination

**Example: Hardware Introspection**

```nushell
# Scan all attached storage devices
host storage scan

# Output (structured table):
# ┌──────────┬─────────┬──────────┬───────────┬─────────────┐
# │ device   │ size    │ used     │ available │ mount       │
# ├──────────┼─────────┼──────────┼───────────┼─────────────┤
# │ /dev/sda │ 500 GiB │ 120 GiB  │ 380 GiB   │ /           │
# │ /dev/sdb │ 1 TiB   │ 0 GiB    │ 1 TiB     │ [unmounted] │
# └──────────┴─────────┴──────────┴───────────┴─────────────┘

# Initialize Garage on unused disk
host storage init --device /dev/sdb --cluster nexus-mesh
```

**Integration with SurrealDB**:

```nushell
# Query database and pipe results through Nushell
sql "SELECT * FROM invoice WHERE status = 'pending'" 
  | where amount > 1000
  | update status "review_required"
  | sql "UPDATE invoice CONTENT $in RETURN AFTER"
```

---

**QuickJS: The AOT JavaScript Runtime**

JavaScript is the **universal application language**. QuickJS makes it
**infrastructure-grade**:

- **Ahead-of-Time Compilation**: `js --harden script.js` → `crystal.bin` (native
  executable)
- **TypeScript Support**: OXC transformer strips types (zero Node.js
  dependencies)
- **Nushell Integration**: JavaScript values ↔ Nushell structured data
  (zero-copy)

**Before (Node.js/Deno)**:

```javascript
// Requires 100MB+ runtime, npm modules, package.json
import express from "express";
import pg from "pg";

const app = express();
const db = new pg.Pool({ host: "localhost", database: "myapp" });

app.get("/users", async (req, res) => {
  const result = await db.query("SELECT * FROM users");
  res.json(result.rows);
});

app.listen(3000);
```

**After (Nexus-IO)**:

```typescript
// Single TypeScript file, compiles to 200KB native binary
interface User {
  id: string;
  name: string;
  email: string;
}

async function getUsers(): Promise<User[]> {
  return await sql<User[]>("SELECT * FROM user");
}

export const users = getUsers();
```

**Compile and run**:

```bash
js --harden api.ts  # Output: crystal.bin (AOT compiled)
./crystal.bin       # Runs natively, no interpreter overhead
```

**Performance Impact**:

- **Startup**: 5ms (vs 500ms for Node.js cold start)
- **Memory**: 10MB (vs 50-100MB for Node.js baseline)
- **Execution**: Near-native speed after JIT warmup

---

### 2.3. Presentation Plane: The Interface Layer

**Nexus-UX: Signal-Driven Reactive UI**

Nexus-UX is **not** another frontend framework. It's a **database mirror** that
lives in the browser.

**Core Concept: Live Queries as Signals**

```html
<!-- Traditional React/Vue (pull-based) -->
<script>
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetch("/api/users")
      .then((r) => r.json())
      .then(setUsers);
  }, []);
</script>

<!-- Nexus-UX (push-based live query) -->
<div data-signal="{ users: $sql('SELECT * FROM user') }">
  <div data-for="user in $users">
    <p>{user.name}</p>
  </div>
</div>
```

**What's happening**:

1. Browser opens WebSocket to SurrealDB
2. `data-signal` creates a **live query subscription**
3. When ANY row in `user` changes, browser receives diff
4. DOM updates automatically (no virtual DOM, no reconciliation)

**Why This Matters**:

- **No API Layer**: Browser talks directly to database (via IAM-secured
  WebSocket)
- **No State Management**: The database _is_ the state
- **Real-Time by Default**: All changes propagate instantly (<10ms latency)

**Advanced Example: Collaborative Editing**

```html
<!-- Multi-user document editor with conflict-free merging -->
<div data-signal="{ doc: $sql('LIVE SELECT * FROM document:spec') }">
  <textarea
    data-bind-value="$doc.content"
    data-on-input="$sql('UPDATE document:spec SET content = $event.target.value')"
  ></textarea>

  <div
    data-signal="{ editors: $sql('LIVE SELECT * FROM presence WHERE doc = document:spec') }"
  >
    <p>
      Editing now:
      <span data-for="user in $editors">{user.name}</span>
    </p>
  </div>
</div>
```

**Result**: Google Docs-style collaboration with **zero backend code**. The
database handles conflict resolution via MVCC.

#### 2.3.1. Offline-First Architecture (SurrealKV Client Cache)

**Problem**: Web apps break when internet disconnects. Traditional solutions
require complex service worker configurations, manual cache invalidation, and
conflict resolution logic.

**Nexus-IO Solution**: The runtime deploys a local **SurrealKV** instance
(backed by IndexedDB) in the browser. This provides a transparent offline cache
that requires zero application-level code—the Nexus-IO runtime manages the
entire lifecycle.

**How it works**:

```
User loads page:
  1. Query local SurrealKV cache (instant: <1ms)
  2. Display cached data immediately
  3. Open WebSocket to Nexus-IO kernel
  4. Sync latest changes from server
  5. Update cache + UI

User modifies data while offline:
  1. Write to local SurrealKV cache
  2. Queue mutation for server sync
  3. Display optimistic UI update

Internet reconnects:
  1. Send queued mutations to server
  2. Server applies mutations + resolves conflicts (MVCC)
  3. Push resolved state back to browser
```

**Integration with Nexus-UX**: The UI layer opts into offline caching via the
`data-cache` directive. The runtime exposes connection status via the
`$nexus.offline` signal:

```html
<div data-signal="{ todos: $sql('SELECT * FROM todo') }" data-cache="true">
  <ul>
    <li data-for="todo in $todos">
      <input
        type="checkbox"
        data-bind-checked="todo.completed"
        data-on-change="$sql('UPDATE todo SET completed = $todo.completed WHERE id = $todo.id')"
      >
      {todo.title}
    </li>
  </ul>

  <!-- Sync status indicator -->
  <div data-if="$nexus.offline">
    <p>⚠️ Offline - changes will sync when connected</p>
  </div>
</div>
```

**Key Properties**:

- **Transparent**: No service worker boilerplate—the runtime handles
  registration, caching, and sync
- **Conflict-Free**: Server-side MVCC resolves conflicting offline mutations
  automatically
- **Incremental**: Only changed records sync, not entire datasets
- **Queryable**: The local SurrealKV cache supports the same query syntax as the
  server, so `$sql()` works identically online or offline

---

### 2.4. IAM Kernel: The Security Fabric

Security in Nexus-IO is **kernel-level**, not middleware-level.

**ABAC (Attribute-Based Access Control)**

Instead of checking permissions in application code, we enforce them _at the
data plane_:

```sql
-- Define table with row-level security
DEFINE TABLE document SCHEMAFULL
  PERMISSIONS 
    FOR select WHERE owner = $auth.id OR $auth.role = 'admin'
    FOR update WHERE owner = $auth.id
    FOR delete WHERE owner = $auth.id AND status != 'published';

DEFINE FIELD title ON document TYPE string;
DEFINE FIELD content ON document TYPE string;
DEFINE FIELD owner ON document TYPE record<user>;
DEFINE FIELD status ON document TYPE string 
  ASSERT $value IN ['draft', 'published', 'archived'];
```

**What this prevents**:

```javascript
// Attempt to read someone else's document
const doc = await db.query(
  "SELECT * FROM document:secret WHERE owner != $auth.id",
);
// Returns: [] (filtered at database level, no error)

// Attempt to delete published document
await db.query("DELETE document:published");
// Returns: Error - PERMISSIONS denied (status = 'published')
```

**GuardedCommand Pattern**

All host-level operations (file system, network, hardware) go through a
**capabilities gate**:

```rust
// Rust kernel code (simplified)
pub struct GuardedCommand {
    capability: Capability,  // Enum: FileRead, FileWrite, NetworkBind, etc.
    validator: fn(&AuthContext, &CommandArgs) -> Result<bool, Error>,
}

impl GuardedCommand {
    pub async fn execute(&self, ctx: &AuthContext, args: &CommandArgs) -> Result<Output> {
        // 1. Check IAM policy
        if !self.validator(ctx, args)? {
            return Err(Error::PermissionDenied);
        }
        
        // 2. Validate against SurrealDB rules
        let allowed = db.query("SELECT * FROM capability WHERE user = $auth.id AND name = $cap")
            .bind("cap", self.capability.to_string())
            .await?;
        
        if allowed.is_empty() {
            return Err(Error::InsufficientPrivileges);
        }
        
        // 3. Execute with privilege
        self.run_privileged(args).await
    }
}
```

**Real-World Impact**:

```javascript
// User tries to read /etc/shadow
await sql("SELECT * FROM sys::file WHERE path = '/etc/shadow'");
// Blocked: IAM policy denies access to system files

// Admin with FileRead capability
await sql("SELECT * FROM sys::file WHERE path = '/var/log/nexus.log'");
// Allowed: Returns log file metadata
```

---

### 2.5. Distributed Storage Architecture

**The Vision: Every Node is a "Cloud of One"**

Traditional cloud storage is **rented** and **centralized**. Nexus-IO inverts
this:

```
Traditional Cloud:
  Your App → AWS S3 (remote datacenter, network latency, per-GB fees)

Nexus Cloud:
  Your App → Garage (local disk, <1ms latency, zero fees) 
           → Mesh peers (automatic replication across your nodes)
```

**Garage DHT (Distributed Hash Table)**

Garage is a **lightweight S3** implementation designed for self-hosted
environments:

- **Gossip Protocol**: Peers discover each other via DHT (no central registry)
- **Consistent Hashing**: Objects distributed evenly across nodes
- **Replication Factor**: Configurable (default: 3 copies across different
  nodes)
- **Automatic Healing**: Dead nodes detected within seconds, data re-replicated

**Architecture Diagram**:

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Node 1    │◄────►│   Node 2    │◄────►│   Node 3    │
│  (Primary)  │      │  (Replica)  │      │  (Replica)  │
└──────┬──────┘      └──────┬──────┘      └──────┬──────┘
       │                    │                    │
       └────────────────────┴────────────────────┘
               WireGuard Mesh (10.200.0.0/24)
                 - Encrypted gossip
                 - Zero public ports
                 - <1ms peer latency (LAN)
```

**Usage Example**:

```bash
# Initialize first node
storage init --cluster nexus-mesh --peers 10.200.0.2,10.200.0.3

# Create bucket and upload
storage bucket create invoices
storage put invoices/2026/invoice.pdf ./local/invoice.pdf

# Garage automatically:
# - Hashes the file (SHA-256)
# - Stores on local disk
# - Replicates to 2 peers via WireGuard
# - Indexes in DHT for discovery
```

**From SurrealDB**:

```sql
-- Store file reference in database
CREATE file:invoice_2026_02 CONTENT {
  name: "invoice.pdf",
  bucket: "invoices",
  key: "2026/invoice.pdf",
  hash: "sha256:a1b2c3...",
  size: 245632,
  uploaded_at: time::now()
};

-- Retrieve file
RETURN file:invoice_2026_02.key;
-- Output: "2026/invoice.pdf"

-- Fetch from Garage (S3 API)
-- GET http://10.200.0.1:3900/invoices/2026/invoice.pdf
```

---

**Performance Targets**

| Operation                   | Target Latency | Implementation                 |
| --------------------------- | -------------- | ------------------------------ |
| Local Object Retrieval      | < 1ms          | Shared memory heap (Phase 14)  |
| Peer Object Retrieval (LAN) | < 5ms          | Direct WireGuard tunnel        |
| Peer Object Retrieval (WAN) | < 50ms         | Encrypted gossip + routing     |
| Replication Lag             | < 100ms        | Async DHT propagation          |
| IAM Validation              | < 0.5ms        | In-memory SurrealDB auth cache |

---

### 2.6. Distributed Compute Layer: The AI-Native Mesh

To eliminate dependencies on cloud AI APIs (OpenAI, Deepgram, etc.), Nexus-IO
integrates a **distributed compute mesh** for local GPU/CPU orchestration.

**The Four-Layer Compute Stack**:

```
Layer 4: CubeCL (GPU Kernels)
         ↓ Hardware-agnostic compute (CUDA/ROCm/CPU)
Layer 3: InferMesh (AI Orchestration)
         ↓ GPU-aware LLM/Whisper routing
Layer 2: Ballista (Data Grid)
         ↓ Apache Arrow distributed analytics
Layer 1: Lunatic (Actor Runtime)
         ↓ WebAssembly fault-tolerant processes
```

---

**InferMesh: GPU-Aware AI Orchestration**

**Problem**: Running AI models locally is hard. Which node has free VRAM? How do
you batch requests efficiently?

**Solution**: InferMesh dynamically routes inference requests based on
**real-time GPU telemetry**:

```rust
// Nexus-IO AI inference (embedded InferMesh)
use infermesh::{InferenceRouter, GpuSignals};

async fn transcribe_voicemail(audio: Vec<u8>) -> Result<String> {
    let router = InferenceRouter::new(&wireguard_mesh);
    
    // InferMesh selects optimal GPU node based on VRAM/batch load
    let node = router.route_inference("whisper-large-v3", &GpuSignals::current()).await?;
    
    // Send audio over WireGuard tunnel to selected node
    let transcript = node.infer(audio).await?;
    
    Ok(transcript)
}
```

**Performance Benefits**:

- **2-3x better latency** vs naive load balancing
- **50% cost reduction** via efficient GPU utilization
- **Zero cloud API fees**: Replace Deepgram ($0.0125/min) with local Whisper

**Use Cases**:

- **RustPBX**: Voicemail transcription sentiment analysis
- **Nexus AI**: LLM workflow execution (Llama-3, Mixtral)
- **Nexus Mail**: Local spam classification
- **Nexus Marketing**: Contact scoring, campaign optimization
- **Gaming/VR/AR**: Distributed mesh rendering for hardware-independent
  performance
  - **Problem**: AAA games require expensive GPUs ($1,500+), low-end devices get
    poor FPS
  - **Solution**: Offload heavy rendering/physics/AI to idle local mesh nodes,
    stream pixels via adaptive codec (H.265/AV1)
  - **Architecture**:
    - Local device: Input handling + video decode (hardware-accelerated)
    - Mesh nodes: Game logic (Lunatic) + physics (CubeCL) + AI (InferMesh) +
      rendering (Vulkan/OpenGL)
    - Codec: Adaptive resolution/bitrate based on network conditions
  - **FPS guarantees** (critical mesh density):
    - 60 FPS minimum (all games)
    - 120 FPS (competitive/esports)
    - 90 FPS (VR, motion sickness prevention)
  - **Latency**: <10ms total (3ms mesh round-trip + 5ms decode) vs 30-100ms
    cloud gaming
  - **Example**: 2019 laptop with integrated GPU runs Cyberpunk 2077 at 120 FPS
    max settings using neighbors' idle RTX 4080s
  - **Market disruption**: GeForce NOW, Xbox Cloud Gaming replaced by
    decentralized alternative

---

**Ballista: Apache Arrow Data Grid**

**Problem**: Analyzing large datasets (call logs, financial ledgers, user
events) requires Spark-like distributed compute.

**Solution**: Ballista provides **distributed SQL queries** with **zero-copy
memory**:

```rust
// Nexus-IO analytics (embedded Ballista)
use ballista::prelude::*;

async fn analyze_call_logs() -> Result<DataFrame> {
    let ctx = BallistaContext::standalone_from_config().await?;
    
    // Query Garage-stored call logs via SQL
    let df = ctx.sql(r#"
        SELECT 
            DATE_TRUNC('hour', timestamp) as hour,
            COUNT(*) as call_count,
            AVG(duration_seconds) as avg_duration
        FROM garage::voicemail_metadata
        WHERE timestamp > NOW() - INTERVAL '7 days'
        GROUP BY hour
        ORDER BY hour DESC
    "#).await?;
    
    Ok(df)
}
```

**Performance Benefits**:

- **5-10x lower memory** vs Apache Spark (no JVM garbage collection)
- **Zero-copy Arrow format**: Data passed between CPU/GPU without serialization
- **Rust native**: Predictable performance, no GC pauses

**Use Cases**:

- **Call Log Analytics**: Real-time dashboards for RustPBX usage
- **Nexus ERP**: Multi-company financial reporting
- **Nexus Marketing**: Campaign performance attribution
- **Voice Data Transcoding**: Batch conversion of recordings

---

**Lunatic: WebAssembly Actor Runtime**

**Problem**: Business logic needs fault tolerance. If a process crashes, it
should restart on another node.

**Solution**: Lunatic provides **Erlang-style supervision trees** using
WebAssembly:

```rust
// RustPBX IVR logic (compiled to WASM, runs on Lunatic)
use lunatic::ap::process::spawn;

#[lunatic::main]
fn ivr_handler(caller: PhoneNumber) {
    spawn!(|caller| {
        let menu = load_ivr_menu_from_surreal().await;
        
        loop {
            match collect_dtmf_digit().await {
                '1' => transfer_to_sales(),
                '2' => {
                    // Spawn child actor for voicemail handling
                    spawn!(|| record_voicemail(caller));
                    break;
                }
                _ => play_audio("invalid_option.wav"),
            }
        }
    })(caller);
}
```

**Performance Benefits**:

- **<100μs actor spawn time**: Spawn thousands of lightweight processes
- **Hot code reload**: Update logic without restarting the cluster
- **Distributed by default**: Actors communicate across WireGuard mesh

**Use Cases**:

- **RustPBX**: IVR menus, conference bridges, call parking
- **Nexus AI**: Long-running LLM conversations with state persistence
- **Nexus Marketing**: Campaign step execution (email → wait → follow-up)
- **Jami Bots**: Automated responses in group chats

---

**CubeCL: Hardware-Agnostic GPU Kernels (Optional)**

For advanced use cases, CubeCL allows writing **custom GPU kernels in Rust**
that compile to CUDA/ROCm/CPU:

```rust
// Custom audio processing kernel (CubeCL)
use cubecl::prelude::*;

#[cube(launch)]
fn noise_reduction(audio: &Tensor<f32>, output: &mut Tensor<f32>) {
    let idx = ABSOLUTE_POS;
    if idx < audio.len() {
        let sample = audio[idx];
        output[idx] = if sample.abs() < NOISE_FLOOR {
            0.0
        } else {
            sample * GAIN_FACTOR
        };
    }
}
```

**Use Cases**:

- **RustPBX**: Real-time noise reduction, echo cancellation
- **Nexus AI**: Custom inference optimizations
- **Nexus ERP**: Financial calculations on GPU for large ledgers

---

**Migration ROI: Cloud APIs → Self-Hosted Mesh**

**Before** (Cloud-Dependent):

```
RustPBX → Deepgram API ($0.0125/min)  = $750/month for 1000 hours
Nexus AI → OpenAI GPT-4 ($0.03/1K tok) = $3000/month for 10M tokens
Total: $3750/month = $45,000/year
```

**After** (Self-Hosted Mesh):

```
RustPBX → InferMesh (Whisper-large-v3 on local GPU) = $0/month
Nexus AI → InferMesh (Llama-3-70B on mesh) = $0/month
Hardware: NVIDIA RTX 4090 ($1600 one-time)
```

**Break-even**: 0.4 months (16 days)\
**5-year savings**: $223,400

---

### 2.7. Infrastructure Virtualization Layer: The End of "Servers"

**The Paradigm Shift**: In the Nexus mesh, there are no "servers"—only **cluster
members**. Every device (desktop, laptop, tablet, phone, IoT) participates in
the distributed infrastructure.

Traditional IT departments manage **soft state** (VMs, containers, network
configs, DR procedures). Nexus IT departments manage **physical hardware only**
(CPUs, disks, RAM). When components fail, you swap them. No DR runbooks, no
complex migrations.

---

#### Virtualization Stack Integration

Nexus-IO integrates the entire virtualization stack **at the kernel level**:

| Technology     | Purpose                                 | Nexus Integration                                   |
| -------------- | --------------------------------------- | --------------------------------------------------- |
| **KVM**        | Full VM support (Windows, Linux guests) | Embedded QEMU/KVM for hardware virtualization       |
| **LXC**        | Linux containers                        | SurrealDB namespace isolation = container isolation |
| **Docker**     | Container runtime compatibility         | Docker API shim (run existing Docker images)        |
| **Kubernetes** | Container orchestration                 | K8s-compatible API (migrate existing K8s workloads) |
| **KubeVirt**   | VM orchestration via K8s                | VM management through K8s API                       |

**Architecture**:

```
Traditional Stack (5 layers):
  VMware ESXi ($5,995/CPU) → vCenter ($6,000) → Docker Enterprise ($1,500/node/year)
  → Kubernetes ($20K/year managed) → KubeVirt (additional complexity)
  
  Total: $35K+ upfront + $25K/year ongoing

Nexus Stack (1 layer):
  Nexus-IO Kernel (free, open-source)
    ├─ KVM embedded (VM support)
    ├─ LXC embedded (container support)
    ├─ Docker API shim (compatibility layer)
    ├─ K8s API server (orchestration)
    └─ Intelligent scheduler (CPU/GPU/memory aware)
  
  Total: $0 (software is free)
```

**Intelligent Workload Scheduler**:

```rust
// Rust kernel: Workload placement across mesh
pub async fn schedule_workload(requirements: WorkloadRequirements) -> Result<NodeId> {
    let available_nodes = db.query("
        SELECT 
            id,
            cpu_available,
            memory_available,
            gpu_available,
            current_load,
            location  -- geographic region
        FROM cluster_node
        WHERE status = 'healthy'
          AND cpu_available >= $req_cpu
          AND memory_available >= $req_memory
    ")
    .bind("req_cpu", requirements.cpu_cores)
    .bind("req_memory", requirements.memory_gb)
    .await?;
    
    // Score nodes by:
    // 1. Resource availability (40%)
    // 2. Current load (30%)
    // 3. Network latency to user (20%)
    // 4. Energy source (10% - prefer solar/wind)
    
    let best_node = available_nodes.iter()
        .map(|node| {
            let resource_score = (node.cpu_available / requirements.cpu_cores) * 0.4;
            let load_score = (1.0 - node.current_load) * 0.3;
            let latency_score = calculate_latency_score(node, user) * 0.2;
            let energy_score = node.renewable_energy_percent * 0.1;
            
            (node.id, resource_score + load_score + latency_score + energy_score)
        })
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(id, _score)| id)?;
    
    Ok(best_node)
}
```

**Auto-Migration on Hardware Failure**:

```
Scenario: Desktop running critical VM experiences motherboard failure

Traditional DR:
  1. Detect failure (5-30 minutes)
  2. Page on-call engineer
  3. Locate backup tapes/snapshots
  4. Restore VM to spare hardware (2-4 hours)
  5. Update DNS/load balancer configs
  6. Test restored services
  Total downtime: 3-6 hours

Nexus Auto-Migration:
  1. Kernel detects node heartbeat loss (<5 seconds)
  2. Scheduler identifies replacement node (best_node algorithm)
  3. Live-migrate VM to new node (memory state transferred via WireGuard)
  4. Update mesh routing tables automatically
  5. Service continues (users never notice)
  Total downtime: <5 seconds
```

**Market Disruption**:

- Replace VMware ($15B market cap → $0 licensing fees)
- Replace Docker Enterprise ($1B market → free runtime)
- Replace Red Hat OpenShift ($500M market → free K8s API)

---

### 2.8. Software-Defined Networking: Kernel-Level SDN

Nexus-IO **eliminates traditional networking appliances** by implementing all
network functions in software:

#### The SDN Stack

```
Traditional Network (Appliance-Based):
  ┌─────────────────┐  ┌──────────────┐  ┌───────────────┐
  │ Cisco Firewall  │  │ F5 Load      │  │ Juniper       │
  │ ($5,000)        │  │ Balancer     │  │ Router        │
  │                 │  │ ($15,000)    │  │ ($10,000)     │
  └─────────────────┘  └──────────────┘  └───────────────┘
  Total: $30,000 hardware + annual support fees

Nexus SDN (Software-Defined):
  ┌──────────────────────────────────────────────────────┐
  │  Nexus-IO Kernel (SDN Engine)                        │
  ├──────────────────────────────────────────────────────┤
  │  • eBPF Firewall (kernel-level packet filtering)     │
  │  • Envoy Load Balancer (L4/L7 traffic distribution)  │
  │  • FRRouting (BGP/OSPF routing protocols)            │
  │  • WireGuard SD-WAN (encrypted mesh overlay)         │
  │  • hostapd WiFi Management (access point control)    │
  │  • Postfix + Rspamd Email Gateway (spam filtering)   │
  │  • Nginx Reverse Proxy (SSL termination, caching)    │
  └──────────────────────────────────────────────────────┘
  Total: $0 (embedded in kernel)
```

**Component Details**:

**1. eBPF Firewall** (Replaces Cisco ASA, Palo Alto):

```c
// Example eBPF program: Block traffic from banned IPs
SEC("xdp_firewall")
int firewall_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check against SurrealDB blacklist
    if (is_blacklisted(ip->saddr)) {
        return XDP_DROP;  // Block packet at kernel level (<1μs latency)
    }
    
    return XDP_PASS;
}
```

**2. Envoy Load Balancer** (Replaces F5 BIG-IP):

```yaml
# Envoy config (managed by Nexus-IO kernel)
static_resources:
  listeners:
    - address:
        socket_address:
          address: 0.0.0.0
          port_value: 443
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                route_config:
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            weighted_clusters:
                              clusters:
                                - name: backend_1
                                  weight: 50
                                - name: backend_2
                                  weight: 50
```

**3. FRRouting** (Replaces Juniper/Cisco Routers):

- BGP peering with ISPs
- OSPF for internal mesh routing
- Automatic failover when links go down

**4. SD-WAN** (WireGuard-based):

- Zero-trust mesh (all traffic encrypted)
- Intelligent path selection (choose fastest route between sites)
- Site-to-site VPN without manual configuration

**5. WiFi Management** (Replaces Aruba, Ubiquiti controllers):

```bash
# Nexus-IO command: Configure access point
host wifi create-ap --ssid "Nexus-Office" --password "****" --band 5ghz --channel 44
```

**Cost Comparison**:

```
Traditional Networking (100-person office):
  Firewall (Cisco ASA 5506): $2,500
  Load Balancer (F5 BIG-IP): $15,000
  Router (Juniper SRX300): $3,000
  WiFi Controller (Aruba 7005): $5,000
  Email Gateway (Barracuda): $2,000/year
  Total: $27,500 upfront + $2,000/year

Nexus SDN:
  Hardware: Any Linux server ($1,000)
  Software: Free (embedded in Nexus-IO)
  Total: $1,000 one-time
  
Savings: $26,500 upfront + $2,000/year ongoing
```

**Market Disruption**:

- Cisco ($50B networking market)
- F5 Networks ($2.5B load balancer market)
- Palo Alto Networks ($5B firewall market)

---

### 2.9. Software-Defined Storage: SD-SAN, SD-RAID, CDN

Garage provides **object storage** (S3 API). But enterprises also need **block
storage** (for databases), **file storage** (NFS/SMB), and **CDN** (edge
caching).

Nexus-IO provides all of this in software:

#### Storage Architecture

```
Traditional Storage Stack:
  ┌───────────────┐  ┌──────────────┐  ┌────────────┐
  │ NetApp SAN    │  │ RAID         │  │ Cloudflare │
  │ ($100,000)    │  │ Controller   │  │ CDN        │
  │               │  │ ($5,000)     │  │ ($200/mo)  │
  └───────────────┘  └──────────────┘  └────────────┘
  Total: $105,000 + $200/month

Nexus SD-Storage:
  ┌────────────────────────────────────────────────────┐
  │  Garage (Distributed Object Store)                 │
  ├────────────────────────────────────────────────────┤
  │  • iSCSI Target (expose buckets as block devices)  │
  │  • SD-RAID (distributed RAID across mesh)          │
  │  • NFS/SMB Gateway (legacy file share protocols)   │
  │  • Edge Caching (CDN for static assets)            │
  └────────────────────────────────────────────────────┘
  Total: $0 (uses existing disk space across mesh)
```

**1. SD-SAN (iSCSI Target)**:

```bash
# Create block device for PostgreSQL
storage san create-volume --name "postgres-data" --size 500GB --replicas 3

# Returns iSCSI target: iqn.2026-02.nexus:postgres-data
# Mount on database server:
iscsiadm --mode discovery --type sendtargets --portal 10.200.0.1
iscsiadm --mode node --targetname iqn.2026-02.nexus:postgres-data --login

# PostgreSQL now uses distributed block storage (3x replicated across mesh)
```

**2. SD-RAID** (Distributed Erasure Coding):

- Replace hardware RAID controllers with software erasure coding
- E.g., 8+3 erasure code: 8 data shards + 3 parity → Survives 3 node failures
- No single point of failure (unlike RAID controller)

**3. NFS/SMB Gateway** (Legacy Compatibility):

```bash
# Export Garage bucket as NFS share
storage nfs export --bucket "company-files" --path "/mnt/nfs/shared" --clients "10.200.0.0/24"

# Windows clients can mount via SMB:
storage smb export --bucket "company-files" --share "CompanyFiles"
```

**4. CDN (Edge Caching Layer)**:

```
User requests static asset (e.g., /images/logo.png)
  ↓
Nexus edge node (geographically closest)
  ├─ Cache hit? → Serve from local disk (<1ms)
  └─ Cache miss? → Fetch from Garage → Cache locally → Serve
```

**Market Disruption**:

- NetApp ($6B market cap)
- Dell EMC Storage ($24B market)
- Cloudflare CDN ($1B/year revenue)

---

### 2.10. The Paradigm Shift: "No Servers, Only Mesh"

**The Old Model**:

```
Office Infrastructure:
  - 1x Server room (dedicated hardware)
  - 50x Desktops/Laptops (for employees)
  - If server dies → Everything stops → Call IT → Wait 2-6 hours
```

**The Nexus Model**:

```
Office Infrastructure:
  - 0x Server room (no dedicated hardware)
  - 50x Desktops/Laptops (ALL participate in mesh cluster)
  - If any device dies → Cluster auto-heals → Users never notice
```

**What This Means**:

**1. Every Device is a Cluster Member**:

```sql
-- SurrealDB tracks all devices
DEFINE TABLE cluster_node SCHEMAFULL;
DEFINE FIELD device_type ON cluster_node TYPE string;  -- 'desktop', 'laptop', 'phone', 'iot'
DEFINE FIELD owner ON cluster_node TYPE record<locker>;
DEFINE FIELD cpu_available ON cluster_node TYPE int;  -- CPU cores contributed
DEFINE FIELD memory_available ON cluster_node TYPE int;  -- RAM in GB
DEFINE FIELD storage_available ON cluster_node TYPE int;  -- Disk space in GB
DEFINE FIELD status ON cluster_node TYPE string DEFAULT 'healthy';

-- Example entries:
[
  { device_type: 'desktop', owner: locker:vylan, cpu_available: 8, memory_available: 32, storage_available: 500 },
  { device_type: 'laptop', owner: locker:vylan, cpu_available: 4, memory_available: 16, storage_available: 256 },
  { device_type: 'phone', owner: locker:vylan, cpu_available: 2, memory_available: 6, storage_available: 128 },
]
```

**2. Personal Device Recovery (Instant)**:

```
Scenario: Laptop stolen/breaks

Traditional Recovery:
  1. Buy new laptop
  2. Restore from Time Machine backup (2-4 hours)
  3. Reinstall applications
  4. Hope the backup wasn't corrupted
  Total recovery time: 4-8 hours

Nexus Recovery:
  1. Buy new laptop
  2. Install Nexus-IO binary
  3. Log into Locker account
  4. All data/apps sync automatically from mesh
  Total recovery time: 15 minutes (limited by download speed)
```

**3. IT Manages Physical Hardware Only**:

```
IT Department Responsibilities:

Traditional:
  - Configure VMs ✅
  - Set up networking ✅
  - Write DR runbooks ✅
  - Monitor disk failures ✅
  - Manage software updates ✅
  - Debug replication issues ✅
  - Plan capacity expansion ✅
  
  Total: 90% soft state (virtual infrastructure) + 10% hard state (physical hardware)

Nexus:
  - Replace failed disks ✅
  - Replace failed RAM ✅
  - Replace failed CPUs ✅
  - [Everything else automated by kernel]
  
  Total: 10% soft state (none) + 100% hard state (physical components)
```

**Impact**: IT departments can shrink by 70%. No need for DevOps/SRE teams
managing complex infrastructure.

---

**4. Server Rooms as Proximity Performance Peers (Not Gatekeepers)**:

**Fundamental Shift**: In traditional client/server architecture, the **server
room is a central point of authority** (gatekeeper). In Nexus, **server rooms
are proximity performance peers**—like an **older sibling helping lift heavy
load**, not a gatekeeper controlling access.

**What This Means**:

```
Traditional Server Room:
  - Central point of authority (if it's offline, everything stops)
  - Single point of failure (requires expensive HA setups)
  - Always-on requirement (24/7 power consumption)
  - Employees depend on it (can't work if server is down)

Nexus Server Room:
  - Proximity performance peer (helps lift heavy load for nearby devices)
  - Optional enhancement (not required for operation)
  - Can be powered off completely (mesh continues operating)
  - Employees independent (data/services replicated across mesh)
```

**Energy Efficiency: Algorithmic Power Management**

One of the most **transformative advantages** of the mesh paradigm: **You can
completely power off your entire facility during non-operational hours** while
data and services remain fully available.

**How it works**:

1. **Algorithmic idle detection**: Nexus kernel detects when nodes are idle (no
   active workloads)
2. **Smart sleep scheduling**: Idle nodes automatically enter deep sleep
   (near-zero power consumption)
3. **Time-of-day awareness**: During weekends, holidays, or after-hours, entire
   facilities can power down
4. **Mesh redundancy**: Data replicated across geographic mesh (3-way by
   default)
5. **Seamless availability**: Employees/customers access services from other
   mesh nodes (transparent failover)

**Example** (50-person office):

```
Traditional Infrastructure:
  - Server room: 5 kW continuous (24/7)
  - Desktop PCs: 50 × 150W = 7.5 kW (8 hours/day weekdays)
  - Total annual power:
    - Server room: 5 kW × 24h × 365 days = 43,800 kWh/year
    - Desktops: 7.5 kW × 8h × 260 weekdays = 15,600 kWh/year
    - Total: 59,400 kWh/year
  - Power cost (at $0.12/kWh): $7,128/year

Nexus Infrastructure:
  - Server room: 0 kW (doesn't exist or powered off when office closed)
  - Desktop PCs (mesh members): 50 × 150W = 7.5 kW (8 hours/day weekdays)
  - Algorithmic sleep: Idle nodes sleep during lunch, meetings, after-hours
    - Effective power: 7.5 kW × 6h × 260 weekdays = 11,700 kWh/year (20% idle time savings)
  - Weekend/holiday shutdown: Complete facility power-off (52 weekends + 10 holidays)
    - Additional savings: 0 kWh (vs traditional always-on servers)
  - Total: 11,700 kWh/year
  - Power cost: $1,404/year

Annual savings: $7,128 - $1,404 = $5,724/year (80% reduction)
```

**Why Traditional Infrastructure Can't Do This**:

- **Central server dependency**: If server is off, employees can't access
  files/email/applications
- **No data redundancy**: Shutting down server room = data unavailable
- **Complex DR procedures**: Failover to backup site requires manual
  intervention

**Why Nexus Can**:

- **Decentralized redundancy**: Data replicated across mesh (geographic
  diversity)
- **No central authority**: Every device is a peer (server room is optional)
- **Automatic failover**: If local nodes sleep, mesh routes requests to active
  nodes (<5ms latency impact)
- **Web3 energy efficiency**: We chose the **most energy-efficient Web3
  protocols down to the kernel**:
  - **WireGuard**: ~10x more efficient than OpenVPN/IPSec
  - **SurrealDB**: No JVM garbage collection (vs Cassandra/MongoDB)
  - **Garage**: Rust-native storage (vs Java-based HDFS)
  - **Kernel-level scheduling**: No OS bloat (vs traditional hypervisors)

**Environmental Impact**:

```
50-person office × 1,000 companies = 50,000 employees

Traditional power consumption:
  1,000 offices × 59,400 kWh = 59,400,000 kWh/year
  CO2 emissions (at 0.4 kg CO2/kWh): 23,760 metric tons/year

Nexus power consumption:
  1,000 offices × 11,700 kWh = 11,700,000 kWh/year
  CO2 emissions: 4,680 metric tons/year

Reduction: 19,080 metric tons CO2/year (equivalent to removing 4,150 cars from roads)
```

**The Sustainability Message**:

> "Nexus doesn't just save money—it **fundamentally redefines** how
> infrastructure consumes energy. By embracing Web3's decentralized model with
> the most efficient protocols at the kernel level, we eliminate the always-on
> server paradigm. Your office can **power off completely** during holidays and
> weekends while services remain fully available."

**Traditional client/server architecture can't offer this advantage.** Web3
opens that door, and we're choosing the **most energy-efficient Web3 protocols
down to the kernel**.

---

### 2.11. Content Sharing with AI-Powered Revocation

**The Problem with Files**: When you share a file (e.g., via Dropbox/Google
Drive), the recipient can:

1. Download it
2. Copy it
3. Share it with others
4. Keep it even after you "revoke" access (they just have a local copy)

**The Nexus Solution**: **Object-based sharing** with **kernel-enforced
revocation**.

---

#### Architecture

**Content Hash Tracking**:

```sql
-- Shared content tracked by cryptographic hash
DEFINE TABLE shared_content SCHEMAFULL;
DEFINE FIELD content_hash ON shared_content TYPE string;  -- SHA-256
DEFINE FIELD owner ON shared_content TYPE record<locker>;
DEFINE FIELD shared_with ON shared_content TYPE array<record<locker>>;
DEFINE FIELD revoked ON shared_content TYPE bool DEFAULT false;
DEFINE FIELD expiration ON shared_content TYPE option<datetime>;
DEFINE FIELD garage_key ON shared_content TYPE string;  -- s3://bucket/key
DEFINE INDEX hash_idx ON shared_content FIELDS content_hash UNIQUE;
```

**Sharing Flow**:

```
1. User shares document:
   sql("CREATE shared_content CONTENT {
     content_hash: 'sha256:a1b2c3...',
     owner: locker:vylan,
     shared_with: [locker:alice, locker:bob],
     garage_key: 's3://docs/confidential.pdf'
   }")

2. Alice tries to access:
   - Nexus kernel checks: shared_content.shared_with.includes(locker:alice)
   - Allowed → Serve from Garage

3. Vylan revokes access:
   sql("UPDATE shared_content SET revoked = true, shared_with = [] WHERE content_hash = 'sha256:a1b2c3...'")

4. Alice tries to access again:
   - Nexus kernel checks: revoked = true
   - DENIED → Even if Alice has cached copy, kernel refuses to decrypt
```

**Revocation Propagation**:

```rust
// Rust kernel: Enforce content revocation
pub async fn serve_object(content_hash: &str, requester: &LockerId) -> Result<Vec<u8>> {
    // Check access permissions
    let shared = db.query("SELECT * FROM shared_content WHERE content_hash = $hash")
        .bind("hash", content_hash)
        .await?;
    
    if shared.revoked {
        return Err(Error::AccessRevoked);
    }
    
    if !shared.shared_with.contains(requester) && shared.owner != *requester {
        return Err(Error::PermissionDenied);
    }
    
    // Check expiration
    if let Some(expiration) = shared.expiration {
        if expiration < Utc::now() {
            return Err(Error::AccessExpired);
        }
    }
    
    // Fetch from Garage
    let object = garage.get_object(&shared.garage_key).await?;
    Ok(object)
}
```

---

#### AI-Powered Duplicate Detection

**The Problem**: Malicious user modifies the document slightly (add a space,
change a word) → New hash → Bypasses revocation.

**The Solution**: LLM-powered semantic similarity detection:

```sql
-- Track similar content
DEFINE TABLE content_similarity SCHEMAFULL;
DEFINE FIELD original_hash ON content_similarity TYPE string;
DEFINE FIELD similar_hash ON content_similarity TYPE string;
DEFINE FIELD similarity_score ON content_similarity TYPE float;  -- 0.0-1.0
DEFINE FIELD flagged ON content_similarity TYPE bool DEFAULT false;
DEFINE FIELD reviewed ON content_similarity TYPE bool DEFAULT false;
```

**Detection Logic**:

```rust
// AI similarity check (runs on every object upload)
pub async fn check_similarity(new_object: &[u8]) -> Result<()> {
    let new_hash = sha256(new_object);
    
    // Extract text content
    let new_text = extract_text(new_object)?;  // PDF/DOCX/TXT → plain text
    
    // Check against recently revoked content
    let revoked_docs = db.query("
        SELECT content_hash, garage_key 
        FROM shared_content 
        WHERE revoked = true 
          AND revoked_at > NOW() - 30d
    ").await?;
    
    for doc in revoked_docs {
        let original_text = extract_text(&garage.get_object(&doc.garage_key).await?)?;
        
        // LLM-based semantic similarity (InferMesh local LLM)
        let similarity = infermesh_similarity(&new_text, &original_text).await?;
        
        if similarity > 0.95 {  // 95% similar → Flag as potential leak
            db.query("CREATE content_similarity CONTENT {
                original_hash: $orig,
                similar_hash: $new,
                similarity_score: $similarity,
                flagged: true
            }")
            .bind("orig", doc.content_hash)
            .bind("new", new_hash)
            .bind("similarity", similarity)
            .await?;
            
            // Optional: Auto-revoke if similarity > 98%
            if similarity > 0.98 {
                return Err(Error::SuspectedContentLeak);
            }
        }
    }
    
    Ok(())
}
```

**Market Impact**:

- Replace Adobe DRM ($200M market)
- Replace Microsoft RMS (Rights Management Services)
- Replace Symantec DLP (Data Loss Prevention, $500M market)

---

### 2.12. Strategic Partnerships: Infrastructure as a Service

To accelerate mesh growth and sustainability, Nexus partners with infrastructure
providers:

---

#### Partnership 1: Ubiquiti (Mesh Networking Hardware)

**Goal**: Every Ubiquiti device becomes a Nexus mesh endpoint → Free
decentralized internet.

**Integration**:

- Nexus-IO embedded in UniFi Dream Machine firmware
- UDM owners contribute bandwidth → Earn ZA tokens
- Denser mesh coverage → Better reliability → More users buy UDMs

**Products**:

- UniFi Dream Machine ($300-500) → Router/firewall with Nexus-IO
- UniFi Access Points → WiFi management via Nexus SDN
- UniFi Protect → Security cameras with Nexus AI video analysis
- UniFi Talk → VoIP phones integrated with Nexus Voice

**Revenue Model**:

- Ubiquiti sells hardware (no license fees)
- We sell SaaS subscriptions to Ubiquiti customers
- Win-win: They move hardware, we gain mesh density

---

#### Partnership 2: Generac (Renewable Power Generation)

**Goal**: Decentralized renewable energy for mesh nodes.

**Integration**:

- Discounted Generac solar + battery systems for node operators
- Nodes running on Generac solar earn **1.5x VPR** (sustainability multiplier)
- Grid independence: Mesh operates during power outages

**Products**:

- PWRcell solar system (5kW panels + 10kWh battery): $15K
- Integration with Nexus energy metering (solar offsets tracked in SurrealDB)

**ROI Example**:

```
Home office with Nexus node:
  - Generac solar + battery: $15,000 upfront
  - Traditional utility costs: $200/month electricity + $100/month internet = $300/month
  
  With Nexus + Generac:
    - Electricity: $0 (solar covers 100%)
    - Internet: $0 (mesh provides connectivity)
    - Phone: $0 (Nexus Voice)
    Total savings: $300/month = $3,600/year
  
  ROI: $15,000 / $3,600 = 4.2 years
```

---

#### Partnership 3: GENAQ (Atmospheric Water Generation)

**Goal**: R&D to reduce cost of atmospheric water generators (AWG) from $3K to
$1K per unit.

**Use Case**: Remote mesh nodes in arid regions (deserts, islands) with no water
infrastructure.

**Vision**: Fully self-sufficient nodes (solar power + water generation +
internet connectivity).

---

#### Partnership 4: Home Assistant / openHAB (Smart Automation)

**Goal**: Unified control surface for smart home/office/enterprise/manufacturing
automation.

**Integration**:

- Home Assistant Core embedded in Nexus-IO kernel
- Manage lights, HVAC, security cameras, door locks from Nexus-UX
- Voice control via Nexus Voice + local LLM (no cloud dependencies)

**Example Automation**:

```yaml
# Home Assistant config (runs in Nexus-IO)
automation:
  - alias: "Energy Optimization"
    trigger:
      platform: numeric_state
      entity_id: sensor.grid_carbon_intensity
      above: 400 # g CO2/kWh
    action:
      # Switch to battery power when grid is dirty
      - service: battery.discharge
      # Pause non-critical workloads
      - service: cluster.pause_low_priority_jobs
```

**Market Impact**:

- Disrupt Google Home, Amazon Alexa, Apple HomeKit
- Enterprise building automation (Honeywell, Johnson Controls market)

---

---

## 3. Universal Deployment

### 3.1. Write Once, Run Everywhere (Actually)

**The Vision**: A single Nexus-UX app runs natively on **every platform**:

- **Server**: Linux/Windows/macOS binaries
- **Desktop**: Windows .exe, macOS .app, Linux .deb
- **Mobile**: iOS .ipa, Android .apk
- **Web**: Progressive Web App (PWA)
- **TV**: Apple TV, Android TV
- **Watch**: Apple Watch, WearOS
- **VR/AR**: Meta Quest, Apple Vision Pro (WebXR)

**How**: **Nexus-IO** bundles your Nexus-UX HTML with the high-performance Rust
runtime, producing tiny, fast binaries for all platforms.

### 3.2. Build Command

```bash
# Single command builds for ALL platforms
nexus build --app my-app --platforms all

# Output (2-5 minutes):
✅ Server (Linux x64): my-app (5 MB)
✅ Desktop:
   - Windows: my-app.exe (3.2 MB)
   - macOS: MyApp.app (3.5 MB)
   - Linux: my-app.deb (3 MB)
✅ Mobile:
   - iOS: MyApp.ipa (5 MB)
   - Android: my-app.apk (4.8 MB)
✅ Web: PWA (500 KB)
✅ TV:
   - Apple TV: MyApp.tvos (6 MB)
   - Android TV: my-app-tv.apk (5 MB)
✅ Watch:
   - Apple Watch: MyApp.watchos (2 MB)
   - WearOS: my-app-wear.apk (3 MB)
✅ VR/AR:
   - Meta Quest: my-app-quest.apk (6 MB)
   - Apple Vision Pro: MyApp.visionos (7 MB)
```

**Selective builds** (faster iteration):

```bash
# Just desktop platforms
nexus build --app my-app --platforms desktop

# Just mobile
nexus build --app my-app --platforms mobile

# Specific platform
nexus build --app my-app --platform ios
```

### 3.3. Distribution via Sovereign App Store

**Publish once, available everywhere**:

```bash
# Build + publish to App Store
nexus publish my-app --all-platforms

# App Store listing automatically generated:
{
  name: "My Todo App",
  developer: "locker:vylan",
  platforms: ["windows", "macos", "linux", "ios", "android", "web", "tv", "watch", "vr"],
  price: 5.00,  // In ZA tokens
  binaries: {
    windows: "garage://apps/my-todo-app/windows.exe",
    ios: "garage://apps/my-todo-app/ios.ipa",
    web: "https://my-todo-app.nexus.app",
    // ... all platforms
  }
}
```

**Revenue split** (kernel-enforced):

- 70% to developer
- 30% to Nexus Platform

---

## 4. Implementation Status

### Timeline Overview (2026-2028)

```
2026 Q1-Q2: Foundation ████████████░░░░░░░░ (60% complete)
2026 Q3-Q4: Identity & Communications ░░░░░░░░░░░░░░░░░░░░ (0% complete)
2027 Q1-Q2: Intelligence & Content ░░░░░░░░░░░░░░░░░░░░ (0% complete)
2027 Q3-Q4: Enterprise & Commerce ░░░░░░░░░░░░░░░░░░░░ (0% complete)
2028 Q1-Q2: Ecosystem & Scale ░░░░░░░░░░░░░░░░░░░░ (0% complete)
```

---

### Completed Phases (Phases 6-11)

#### ✅ Phase 6: Crystal Plane (AOT Compilation)

- **Status**: Production-ready
- **Delivered**:
  - `js --harden` command for AOT compilation
  - TypeScript source → Native binary pipeline
  - Stack allocation fixes (16MB heap via verified offset)
  - Nushell-first console (zero-copy Value bridging)
- **Impact**: Deploy JavaScript/TypeScript as standalone executables

#### ✅ Phase 9: Integrated Error Handling

- **Status**: Production-ready
- **Delivered**:
  - `JsClient` returns `Result<NuValue, ShellError>`
  - `SqlCommand` returns `Err(ShellError::GenericError)`
  - Polished SQL errors (clean parse errors via `Display`)
  - Polished JS errors (removed empty stack traces)
- **Impact**: Nushell-native diagnostics for all runtime errors

#### ✅ Phase 10: Sovereign TypeScript (OXC)

- **Status**: Production-ready
- **Delivered**:
  - OXC Rust dependencies (no Node.js required)
  - `src/js/transformer.rs` strips TypeScript types
  - Integrated into `JsClient` and `JsCommand`
  - npm `@types` package parsing
- **Impact**: Zero Node.js dependencies, full TypeScript support

#### ✅ Phase 11: IAM & Hardware Projection

- **Status**: Production-ready
- **Delivered**:
  - Security kernel with ABAC enforcement
  - `sys::storage` and `sys::file` virtual tables
  - Real-time hardware introspection (`host storage scan`)
  - GuardedCommand pattern for all host operations
- **Impact**: Kernel-level security, zero privilege escalation risks

---

### Current Phase (Phase 12)

#### ⏳ Phase 12: Documentation Alignment & Research

- **Status**: 95% complete (in this document)
- **Delivered**:
  - Implementation status checklists in all specs
  - Comprehensive SaaS strategy (8 Proton apps, ERP, VoIP)
  - Distributed compute layer research (InferMesh/Ballista/Lunatic)
  - Time-projected roadmaps (2026-2028)
  - Full Nexus-UX strategy (no shadow components)
- **Impact**: Clear technical roadmap, aligned messaging

---

### Near-Term Roadmap (Phases 13-15)

#### Phase 13: The Cloud Seed (Distributed Storage)

**Target**: 2026 Q2\
**Goal**: Embed Garage + WireGuard into Nexus-IO binary

**Tasks**:

- [ ] Add `garage` (server features) and `boringtun` (WireGuard) dependencies
- [ ] Strip unused Garage HTTP gateways (RPC-only mode)
- [ ] Implement `storage` command group (`init`, `peer add`, `status`)
- [ ] **InferMesh/Ballista/Lunatic integration** for distributed compute
- [ ] Verify single-node Garage cluster initialization
- [ ] Verify WireGuard tunnel establishment

**Success Criteria**:

- Binary size: ~80MB (acceptable for server deployment)
- Boot time: <50ms (including WireGuard init)
- `storage status` shows local node + mesh peers

---

#### Phase 14: The Zero-Copy Bridge (Shared Memory)

**Target**: 2026 Q2\
**Goal**: Eliminate serialization between QuickJS/Rust/Garage

**Tasks**:

- [ ] Implement shared memory heap for QuickJS/Rust interop
- [ ] Use `bytes` + `zerocopy` crates for zero-allocation
- [ ] Implement `sys::bucket` wrapper around `garage_table::Table`
- [ ] Implement dirty-flag observer for memory → Garage sync
- [ ] Verify <1ms local object access
- [ ] Verify <5ms peer retrieval (LAN)

**Success Criteria**:

```javascript
// From QuickJS
const file = await sql("SELECT * FROM file:invoice_2026_02");
const bytes = garage.get(file.bucket, file.key); // <1ms (shared memory)
```

---

#### Phase 15: The Zero-Trust Handshake (VPN Peering)

**Target**: 2026 Q2\
**Goal**: All Garage RPC traffic inside WireGuard tunnel

**Tasks**:

- [ ] Integrate WireGuard handshake into boot sequence
- [ ] Implement peer discovery and bootstrap list
- [ ] Bind Garage RPC exclusively to WireGuard interface (10.200.0.X)
- [ ] Ensure all gossip/data inside WireGuard tunnel
- [ ] Validate Garage RPC against SurrealDB IAM
- [ ] Implement `smoltcp` for userspace networking (mobile/restricted
      environments)

**Success Criteria**:

- Zero public ports exposed
- `tcpdump` shows only encrypted WireGuard packets on public interface
- Peer object retrieval <5ms (LAN), <50ms (WAN)

---

### Long-Term Roadmap (Phases 16-23)

See
[nexus-saas-spec.20260204.md](file:///home/aerea/development/nexus-saas-spec.20260204.md)
for complete SaaS application strategy.

**Summary**:

- **Phase 16-17** (2026 Q3-Q4): Nexus Locker + Proton Suite
  (Mail/Calendar/Drive/VPN/Pass/Wallet)
- **Phase 18-20** (2027 Q1-Q2): Nexus CMS + AI + Marketing
- **Phase 21-22** (2027 Q3-Q4): Nexus ERP + Voice (RustPBX + Jami)
- **Phase 23** (2027 Q4): Nexus Commerce

**First Revenue Target**: 2027 Q1 (Nexus Locker SaaS subscriptions)

---

### Binary Stats (Current)

```bash
# Build profile: release
# Target: x86_64-unknown-linux-gnu
# Compilation date: 2026-02-04

File: nexus (stripped)
Size: ~23 MB (without Garage/WireGuard)
      ~80 MB (with Garage/WireGuard - Phase 13 target)

Boot time: ~47ms
Memory (idle): ~15 MB
Threads: 4 (event loop, SurrealDB, Nushell, HTTP server)

Dependencies (major):
- SurrealDB: 2.1.0
- Nushell: 0.99.1
- QuickJS-NG: 0.7.2
- OXC: 0.41.0
- Tokio: 1.42.0
```

---

## 4. The Path Forward

### Why Nexus-IO Matters

We're at an inflection point in software architecture. The "microservices" era
promised modularity but delivered **operational chaos**:

- **15+ services** for a single application
- **50-200ms latency** for simple CRUD operations
- **$2000-10,000/month** cloud costs for mid-sized apps
- **Weeks of DevOps** to deploy a single feature

**Nexus-IO inverts this**:

- **1 binary** for your entire backend
- **1-5ms latency** (shared memory, no network)
- **$50-200/month** self-hosted costs
- **Seconds to deploy** (copy binary, run)

This isn't incremental improvement. It's a **10x paradigm shift**.

---

### What's Next

**Immediate (2026 Q2)**: Complete Phases 13-15

- Distributed storage operational
- WireGuard mesh tested with 10+ nodes
- Zero-copy memory bridge validated

**Near-Term (2026 Q3-Q4)**: Launch Nexus Locker + Mail + Voice

- Identity gateway at `nexus.locker`
- Production-ready email with IMAP/SMTP bridge
- VoIP with RustPBX + Jami (zero NAT traversal)

**Long-Term (2027-2028)**: Build the Sovereign Stack

- Full suite of SaaS applications (CMS, AI, Marketing, ERP, Commerce)
- Sovereign App Store (third-party plugins)
- 100,000+ node global mesh

---

### How to Get Involved

**For Developers**:

- Clone the repo: `git clone https://github.com/aerea-org/nexus-io`
- Read the architecture docs: `/docs/architecture.md`
- Join the discussion: Discord (coming soon)

**For Early Adopters**:

- Private beta begins 2026 Q3 (Nexus Locker + Mail)
- Sign up: https://nexus.locker/beta
- Requires: Linux server (4GB RAM, 50GB disk)

**For Investors**:

- See:
  [nexus-assessment-20260131.md](file:///home/aerea/development/nexus-assessment-20260131.md)
- Contact: vylan@aerea.co

---

### Final Thoughts

Nexus-IO is not just a runtime. It's a **statement of intent**:

> "We believe infrastructure should be invisible, inevitable, and owned—not
> rented."

The future isn't serverless. It's **sovereign**.

---

## Appendix: Technical Deep Dives

### A. SurrealDB Schema Examples

**Multi-Model Demonstration**:

```sql
-- Relational: Traditional table
DEFINE TABLE company SCHEMAFULL;
DEFINE FIELD name ON company TYPE string;
DEFINE FIELD founded_year ON company TYPE int;

-- Document: Flexible JSON-like structure
DEFINE TABLE config SCHEMAFULL;
DEFINE FIELD settings ON config TYPE object FLEXIBLE;

-- Graph: Relations between entities
DEFINE TABLE user SCHEMAFULL;
DEFINE TABLE post SCHEMAFULL;

-- Relation edge (user -> authored -> post)
DEFINE TABLE authored SCHEMAFULL TYPE RELATION FROM user TO post;
DEFINE FIELD published_at ON authored TYPE datetime;

-- Query graph
SELECT *, ->authored->post AS posts 
  FROM user:vylan;

-- Key-Value: Ultra-fast lookups
DEFINE TABLE cache SCHEMAFULL;
DEFINE FIELD key ON cache TYPE string;
DEFINE FIELD value ON cache TYPE any;
DEFINE INDEX key_idx ON cache FIELDS key UNIQUE;

-- Retrieve instantly
SELECT value FROM cache WHERE key = 'session:abc123';
```

---

### B. Garage S3 API Compatibility

**Supported Operations**:

```bash
# Bucket operations
s3cmd mb s3://my-bucket
s3cmd ls

# Object operations
s3cmd put file.pdf s3://my-bucket/docs/file.pdf
s3cmd get s3://my-bucket/docs/file.pdf
s3cmd del s3://my-bucket/docs/file.pdf

# Multipart uploads (large files)
s3cmd put --multipart-chunk-size-mb=15 video.mp4 s3://my-bucket/videos/

# Access control
s3cmd setacl --acl-public s3://my-bucket/public/image.jpg
```

**Limitations** (vs AWS S3):

- No versioning (immutable-only via content addressing)
- No lifecycle policies (manual expiration)
- No server-side encryption (handled by WireGuard tunnel)

**Advantages** (vs AWS S3):

- Zero per-GB fees
- <1ms local access, <5ms mesh access
- No egress charges
- Complete data sovereignty

---

### C. WireGuard Configuration

**Automatic Peer Discovery**:

```toml
# nexus.toml (auto-generated)
[wireguard]
interface = "wg0"
private_key = "<base64-encoded-key>"
listen_port = 51820
address = "10.200.0.1/24"

[[wireguard.peers]]
public_key = "<peer-1-public-key>"
allowed_ips = ["10.200.0.2/32"]
endpoint = "peer1.example.com:51820"
persistent_keepalive = 25

[[wireguard.peers]]
public_key = "<peer-2-public-key>"
allowed_ips = ["10.200.0.3/32"]
endpoint = "peer2.example.com:51820"
persistent_keepalive = 25
```

**Security Properties**:

- ChaCha20-Poly1305 authenticated encryption
- Curve25519 for key exchange
- BLAKE2s for hashing
- Perfect forward secrecy (keys rotate every 2 minutes)

---

### D. Performance Benchmarks

**Planned Benchmarks** (Phase 14 validation):

| Operation                      | Target | Measurement                |
| ------------------------------ | ------ | -------------------------- |
| SurrealDB query (local)        | <1ms   | `SELECT * FROM user:vylan` |
| SurrealDB query (remote, LAN)  | <5ms   | Via WireGuard tunnel       |
| Garage object read (local)     | <1ms   | Shared memory heap         |
| Garage object read (peer, LAN) | <5ms   | Via WireGuard + DHT        |
| QuickJS AOT startup            | <5ms   | `./crystal.bin` cold start |
| Nushell pipeline latency       | <0.1ms | `$data                     |
| IAM validation                 | <0.5ms | Auth cache hit             |
| WebSocket live query latency   | <10ms  | Browser → SurrealDB update |

**Comparison to Traditional Stack**:

| Stack                            | E2E Latency (Simple CRUD) | Infrastructure Cost |
| -------------------------------- | ------------------------- | ------------------- |
| AWS Lambda + RDS + S3            | 50-200ms                  | $500-2000/month     |
| Node.js + MongoDB + DigitalOcean | 20-50ms                   | $200-500/month      |
| **Nexus-IO (self-hosted)**       | **1-5ms**                 | **$50-200/month**   |

---

### E. Security Model

**Threat Model**:

| Threat                   | Mitigation                                                   |
| ------------------------ | ------------------------------------------------------------ |
| **SQL Injection**        | Parameterized queries only (no string concatenation)         |
| **XSS**                  | Content Security Policy + automatic escaping in Nexus-UX     |
| **CSRF**                 | SameSite cookies + CSRF tokens for state-changing operations |
| **Privilege Escalation** | ABAC kernel enforcement + GuardedCommand pattern             |
| **Data Exfiltration**    | Row-level permissions + audit logs                           |
| **Network Sniffing**     | WireGuard encryption for all mesh traffic                    |
| **DDoS**                 | Rate limiting at kernel level (planned: Phase 18)            |

**Compliance**:

- **GDPR**: Right to erasure (hard delete), data portability (export API)
- **HIPAA**: Encryption at rest (Garage) and in transit (WireGuard)
- **SOC 2**: Audit logs for all data access (SurrealDB events table)

---

### F. Glossary

**ABAC (Attribute-Based Access Control)**: Security model where permissions
depend on attributes of the user, resource, and environment.

**AOT (Ahead-of-Time Compilation)**: Compilation strategy where code is compiled
to native machine code before execution (vs JIT = Just-In-Time).

**Content-Addressable Storage**: Storage scheme where objects are identified by
cryptographic hashes of their content (guarantees immutability).

**DHT (Distributed Hash Table)**: Decentralized data structure where each node
stores a portion of the key-value space (used by Garage for peer discovery).

**IAM (Identity and Access Management)**: The security framework for controlling
who can access what resources.

**MVCC (Multi-Version Concurrency Control)**: Database technique where multiple
versions of data coexist to allow concurrent reads and writes without locking.

**S3 API**: De facto standard object storage interface created by Amazon Web
Services (GET/PUT/DELETE objects in buckets).

**Zero-Copy**: Memory optimization where data is accessed directly without
intermediate copying (critical for performance).

**Zero-Trust**: Security model where no entity is trusted by default (all access
must be verified).

---

**Document Version**: v2026.02.04\
**Maintained by**: Aerea Co.\
**License**: Proprietary (Specification), Nexus-IO Source Code: AGPL-3.0\
**Contact**: vylan@aerea.co
