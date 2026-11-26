use anyhow::{anyhow, Result};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use wasmtime::{Caller, Config, Engine, Instance, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

use crate::db::sql_compiler::execute_unified_query;
use crate::db::StateEngine;
use crate::iam::capabilities::{is_mutating_query, Capability, CapabilitySet};
use crate::js::cell::{CellDbConfig, CellDbTransport, CellManager};
use crate::observability::global_metrics;
use crate::storage::BlobBridge;

fn wt_err(e: wasmtime::Error) -> anyhow::Error {
    anyhow!("{}", e)
}

/// Capability-scoped host context exposed to WASI guests via the `nexus_host` ABI.
/// Every guest language (JS/TS via `quickjs.wasm`, PHP/WordPress, Python, Go, Rust)
/// inherits `EffectiveCapabilities`, `CellDbConfig` enforcement, and `BlobBridge` isolation
/// through this single microkernel syscall boundary.
#[derive(Clone)]
pub struct NexusHostContext {
    pub app: String,
    pub cell_id: String,
    pub db_config: CellDbConfig,
    pub capabilities: CapabilitySet,
    pub request_id: Option<String>,
    pub engine: Arc<dyn StateEngine>,
    pub blobs: Arc<BlobBridge>,
    pub logs: Arc<Mutex<Vec<String>>>,
}

impl NexusHostContext {
    pub fn new(
        app: impl Into<String>,
        cell_id: impl Into<String>,
        db_config: CellDbConfig,
        engine: Arc<dyn StateEngine>,
        blobs: Arc<BlobBridge>,
    ) -> Self {
        let capabilities = CapabilitySet::resolve_effective(
            &CapabilitySet::standard_cell(),
            &CapabilitySet::standard_cell(),
            None,
            &db_config,
        );
        Self {
            app: app.into(),
            cell_id: cell_id.into(),
            db_config,
            capabilities,
            request_id: None,
            engine,
            blobs,
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_capabilities(mut self, caps: CapabilitySet) -> Self {
        self.capabilities = caps;
        self
    }

    /// Re-derive effective capabilities intersected with the caller's verified IAM `AuthContext`.
    pub fn with_auth(mut self, auth: Option<&nexus_db::auth::AuthContext>) -> Self {
        self.capabilities = CapabilitySet::resolve_effective(
            &CapabilitySet::standard_cell(),
            &CapabilitySet::standard_cell(),
            auth,
            &self.db_config,
        );
        self
    }

    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }
}

struct CrystalWasiState {
    wasi: WasiP1Ctx,
    host: Option<NexusHostContext>,
    arena_owner: Option<String>,
}

/// Capability-scoped configuration for executing any WASI polyglot module
/// (PHP/WordPress `php-cgi.wasm`, CPython `python.wasm`, Go `wasip1`, Rust, C/C++, Ruby).
///
/// Zero ambient host authority: env vars, argv, stdin, and preopened directories must be
/// explicitly granted per invocation.
#[derive(Debug, Clone)]
pub struct WasiRunConfig {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    /// `(host_path, guest_mount_path, writable)`
    pub preopen_dirs: Vec<(PathBuf, String, bool)>,
    pub fuel_limit: u64,
}

impl Default for WasiRunConfig {
    fn default() -> Self {
        Self {
            args: vec!["cell.wasm".to_string()],
            env: Vec::new(),
            stdin: Vec::new(),
            preopen_dirs: Vec::new(),
            fuel_limit: 50_000_000,
        }
    }
}

/// Captured output & resource accounting from a WASI Crystal cell invocation.
#[derive(Debug, Clone)]
pub struct WasiRunOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub fuel_consumed: u64,
}

/// Parsed HTTP/CGI response returned by `CrystalEngine::invoke_wasi_cgi` (e.g. PHP/WordPress cells).
#[derive(Debug, Clone)]
pub struct WasiCgiResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub stderr: String,
    pub fuel_consumed: u64,
}

/// Wasmtime Crystal Cell & WASI Polyglot Primitive Engine:
/// - **Non-iOS (`#[cfg(not(target_os = "ios"))]`):** Supports Cranelift JIT and AOT pre-compilation (`.cwasm`).
/// - **iOS (`#[cfg(target_os = "ios")]`):** Strictly AOT-only (`runtime` feature, zero JIT — 100% Apple `W^X` compliant).
/// - **WASI Sandbox:** Runs PHP/WordPress, Python, Go, Rust, Ruby, and Wasm OCI components with
///   zero ambient OS access, scoped virtual filesystem mounts, and deterministic fuel metering.
pub struct CrystalEngine {
    engine: Engine,
    module_cache: RwLock<HashMap<String, Module>>,
}

impl CrystalEngine {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(wt_err)?;
        Ok(Self {
            engine,
            module_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Resolve a cached `Module` by BLAKE3 hash of its AOT `.cwasm` bytes, deserializing only on first use.
    fn get_or_deserialize_aot(&self, aot_bytes: &[u8]) -> Result<Module> {
        let key = format!("aot:{}", blake3::hash(aot_bytes).to_hex());
        if let Some(m) = self.module_cache.read().unwrap().get(&key).cloned() {
            return Ok(m);
        }
        let module = unsafe { Module::deserialize(&self.engine, aot_bytes).map_err(wt_err)? };
        self.module_cache.write().unwrap().insert(key, module.clone());
        Ok(module)
    }

    /// Resolve a cached `Module` by BLAKE3 hash of raw `.wasm`/`.wat` bytes, compiling only on first use.
    #[cfg(not(target_os = "ios"))]
    fn get_or_compile_wasm(&self, wasm_or_wat: &[u8]) -> Result<Module> {
        let key = format!("wasm:{}", blake3::hash(wasm_or_wat).to_hex());
        if let Some(m) = self.module_cache.read().unwrap().get(&key).cloned() {
            return Ok(m);
        }
        let module = Module::new(&self.engine, wasm_or_wat).map_err(wt_err)?;
        self.module_cache.write().unwrap().insert(key, module.clone());
        Ok(module)
    }

    /// Pre-compile a `.wasm` or `.wat` module ahead-of-time into native `.cwasm` bytes
    /// suitable for storing in `BlobBridge` and executing on iOS or edge nodes with zero JIT.
    #[cfg(not(target_os = "ios"))]
    pub fn compile_aot(&self, wasm_or_wat: &[u8]) -> Result<Vec<u8>> {
        let module = Module::new(&self.engine, wasm_or_wat).map_err(wt_err)?;
        let bytes = module.serialize().map_err(wt_err)?;
        Ok(bytes)
    }

    /// Execute an exported `(i64, i64) -> i64` function from pre-compiled AOT `.cwasm` bytes
    /// with strict fuel metering. Works on all 5 platforms including iOS.
    pub fn run_aot_i64(
        &self,
        aot_bytes: &[u8],
        fn_name: &str,
        a: i64,
        b: i64,
        fuel_limit: u64,
    ) -> Result<i64> {
        // SAFETY: `aot_bytes` must come from a trusted `CrystalEngine::compile_aot` build
        // (verified by BLAKE3 hash via `BlobBridge` / IAM before deserialization).
        let module = unsafe { Module::deserialize(&self.engine, aot_bytes).map_err(wt_err)? };
        self.exec_module_i64(&module, fn_name, a, b, fuel_limit)
    }

    /// Directly compile and execute a `.wasm` or `.wat` module on non-iOS platforms with fuel metering.
    #[cfg(not(target_os = "ios"))]
    pub fn run_wasm_i64(
        &self,
        wasm_or_wat: &[u8],
        fn_name: &str,
        a: i64,
        b: i64,
        fuel_limit: u64,
    ) -> Result<i64> {
        let module = Module::new(&self.engine, wasm_or_wat).map_err(wt_err)?;
        self.exec_module_i64(&module, fn_name, a, b, fuel_limit)
    }

    /// Execute a WASI Preview 1 polyglot module (`.wasm` or `.wat`) with capability-scoped
    /// stdio pipes, argv, env vars, preopened directories, and deterministic fuel metering.
    #[cfg(not(target_os = "ios"))]
    pub fn run_wasi_p1(&self, wasm_or_wat: &[u8], cfg: WasiRunConfig) -> Result<WasiRunOutput> {
        let module = self.get_or_compile_wasm(wasm_or_wat)?;
        self.exec_wasi_p1_module(&module, cfg, None)
    }

    /// Execute a WASI Preview 1 polyglot module with the `nexus_host` ABI bound to a cell's
    /// `StateEngine`, `BlobBridge`, and `CellDbConfig`.
    #[cfg(not(target_os = "ios"))]
    pub fn run_wasi_with_host(
        &self,
        wasm_or_wat: &[u8],
        cfg: WasiRunConfig,
        host: NexusHostContext,
    ) -> Result<WasiRunOutput> {
        let module = self.get_or_compile_wasm(wasm_or_wat)?;
        self.exec_wasi_p1_module(&module, cfg, Some(host))
    }

    /// Execute a pre-compiled AOT `.cwasm` WASI Preview 1 module (works on all 5 platforms including iOS).
    pub fn run_wasi_p1_aot(&self, aot_bytes: &[u8], cfg: WasiRunConfig) -> Result<WasiRunOutput> {
        let module = self.get_or_deserialize_aot(aot_bytes)?;
        self.exec_wasi_p1_module(&module, cfg, None)
    }

    /// Execute a pre-compiled AOT `.cwasm` WASI Preview 1 module with `nexus_host` ABI attached (iOS-safe).
    pub fn run_wasi_aot_with_host(
        &self,
        aot_bytes: &[u8],
        cfg: WasiRunConfig,
        host: NexusHostContext,
    ) -> Result<WasiRunOutput> {
        let module = self.get_or_deserialize_aot(aot_bytes)?;
        self.exec_wasi_p1_module(&module, cfg, Some(host))
    }

    /// Execute a JS/TS cell inside a WASI JavaScript engine guest module (e.g., `quickjs.wasm` / Javy)
    /// with `nexus_host` ABI imports (`nexus_db_query`, `nexus_blob_*`, `nexus_log`) automatically bound.
    #[cfg(not(target_os = "ios"))]
    pub fn invoke_js_wasm(
        &self,
        quickjs_wasm: &[u8],
        source_js: &str,
        input_json: &[u8],
        host: Option<NexusHostContext>,
        fuel_limit: u64,
    ) -> Result<WasiRunOutput> {
        let cfg = WasiRunConfig {
            args: vec!["quickjs.wasm".to_string()],
            env: vec![("NEXUS_JS_SOURCE".to_string(), source_js.to_string())],
            stdin: input_json.to_vec(),
            preopen_dirs: Vec::new(),
            fuel_limit,
        };
        let module = Module::new(&self.engine, quickjs_wasm).map_err(wt_err)?;
        self.exec_wasi_p1_module(&module, cfg, host)
    }

    /// Execute a WASI HTTP/CGI polyglot handler (e.g. `php-cgi.wasm` for WordPress/Laravel,
    /// `python.wasm`, or Go/Rust WASI binaries) and parse its HTTP status, headers, and body.
    #[cfg(not(target_os = "ios"))]
    pub fn invoke_wasi_cgi(
        &self,
        wasm_or_wat: &[u8],
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
        doc_root: Option<&Path>,
        fuel_limit: u64,
    ) -> Result<WasiCgiResponse> {
        self.invoke_wasi_cgi_with_host(
            wasm_or_wat,
            method,
            path,
            query_string,
            body,
            doc_root,
            None,
            fuel_limit,
        )
    }

    /// Execute a WASI HTTP/CGI polyglot handler with optional `nexus_host` ABI attached.
    #[cfg(not(target_os = "ios"))]
    #[allow(clippy::too_many_arguments)]
    pub fn invoke_wasi_cgi_with_host(
        &self,
        wasm_or_wat: &[u8],
        method: &str,
        path: &str,
        query_string: &str,
        body: &[u8],
        doc_root: Option<&Path>,
        host: Option<NexusHostContext>,
        fuel_limit: u64,
    ) -> Result<WasiCgiResponse> {
        let mut env = vec![
            ("REQUEST_METHOD".to_string(), method.to_ascii_uppercase()),
            ("PATH_INFO".to_string(), path.to_string()),
            ("REQUEST_URI".to_string(), if query_string.is_empty() { path.to_string() } else { format!("{}?{}", path, query_string) }),
            ("QUERY_STRING".to_string(), query_string.to_string()),
            ("CONTENT_LENGTH".to_string(), body.len().to_string()),
            ("SERVER_PROTOCOL".to_string(), "HTTP/1.1".to_string()),
            ("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string()),
            ("REDIRECT_STATUS".to_string(), "200".to_string()),
        ];
        let mut preopen_dirs = Vec::new();
        if let Some(root) = doc_root {
            env.push(("DOCUMENT_ROOT".to_string(), "/var/www".to_string()));
            env.push(("SCRIPT_FILENAME".to_string(), format!("/var/www/{}", path.trim_start_matches('/'))));
            preopen_dirs.push((root.to_path_buf(), "/var/www".to_string(), true));
        }

        let module = Module::new(&self.engine, wasm_or_wat).map_err(wt_err)?;
        let out = self.exec_wasi_p1_module(
            &module,
            WasiRunConfig {
                args: vec!["wasi-cgi".to_string()],
                env,
                stdin: body.to_vec(),
                preopen_dirs,
                fuel_limit,
            },
            host,
        )?;

        let (status, headers, resp_body) = parse_cgi_response(&out.stdout);
        Ok(WasiCgiResponse {
            status,
            headers,
            body: resp_body,
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            fuel_consumed: out.fuel_consumed,
        })
    }

    fn exec_wasi_p1_module(
        &self,
        module: &Module,
        cfg: WasiRunConfig,
        host: Option<NexusHostContext>,
    ) -> Result<WasiRunOutput> {
        let stdout_pipe = MemoryOutputPipe::new(4 * 1024 * 1024);
        let stderr_pipe = MemoryOutputPipe::new(1024 * 1024);
        let stdin_pipe = MemoryInputPipe::new(cfg.stdin);

        let mut builder = WasiCtxBuilder::new();
        builder
            .stdin(stdin_pipe)
            .stdout(stdout_pipe.clone())
            .stderr(stderr_pipe.clone());

        if !cfg.args.is_empty() {
            builder.args(&cfg.args);
        }
        for (k, v) in &cfg.env {
            builder.env(k, v);
        }
        for (host_path, guest_path, writable) in &cfg.preopen_dirs {
            let perms = if *writable {
                FsPerms::ReadWrite
            } else {
                FsPerms::ReadOnly
            };
            builder
                .preopened_dir(host_path, guest_path, perms)
                .map_err(wt_err)?;
        }

        let owner_key = host.as_ref().map(|h| {
            crate::arena::NexusSharedArena::global()
                .mint_owner_id(&h.app, &h.cell_id)
                .as_canonical()
        });

        let state = CrystalWasiState {
            wasi: builder.build_p1(),
            host,
            arena_owner: owner_key.clone(),
        };
        let mut store = Store::new(&self.engine, state);
        store.set_fuel(cfg.fuel_limit).map_err(wt_err)?;

        let mut linker: Linker<CrystalWasiState> = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |s| &mut s.wasi).map_err(wt_err)?;
        register_nexus_host_abi(&mut linker)?;

        let instance = linker.instantiate(&mut store, module).map_err(wt_err)?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| anyhow!("WASI module missing '_start' entrypoint: {}", e))?;

        let exit_res = start.call(&mut store, ());

        // Deterministic ZCZS arena cleanup: revoke all active buffer/ring handles owned by this cell
        if let Some(ref owner) = owner_key {
            crate::arena::NexusSharedArena::global().revoke_owner(owner);
        }

        let exit_code = match exit_res {
            Ok(()) => 0,
            Err(err) => {
                if let Some(exit) = err.downcast_ref::<wasmtime_wasi::I32Exit>() {
                    exit.0
                } else {
                    global_metrics().inc_compute_trap();
                    return Err(wt_err(err));
                }
            }
        };

        let remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = cfg.fuel_limit.saturating_sub(remaining);
        global_metrics().inc_compute_exec(fuel_consumed);

        Ok(WasiRunOutput {
            exit_code,
            stdout: stdout_pipe.contents().to_vec(),
            stderr: stderr_pipe.contents().to_vec(),
            fuel_consumed,
        })
    }

    fn exec_module_i64(
        &self,
        module: &Module,
        fn_name: &str,
        a: i64,
        b: i64,
        fuel_limit: u64,
    ) -> Result<i64> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(fuel_limit).map_err(wt_err)?;
        let instance = Instance::new(&mut store, module, &[]).map_err(wt_err)?;
        let func = instance
            .get_typed_func::<(i64, i64), i64>(&mut store, fn_name)
            .map_err(|e| anyhow!("Crystal export '{}' not found or signature mismatch: {}", fn_name, e))?;
        let res = func.call(&mut store, (a, b)).map_err(wt_err)?;
        Ok(res)
    }
}

fn read_guest_bytes(caller: &mut Caller<'_, CrystalWasiState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let mem = caller.get_export("memory")?.into_memory()?;
    let mut buf = vec![0u8; len as usize];
    mem.read(&*caller, ptr as usize, &mut buf).ok()?;
    Some(buf)
}

fn write_guest_bytes(
    caller: &mut Caller<'_, CrystalWasiState>,
    ptr: i32,
    cap: i32,
    data: &[u8],
) -> i32 {
    if ptr < 0 || cap < 0 {
        return -4;
    }
    if data.len() > cap as usize {
        return -4;
    }
    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return -4;
    };
    if mem.write(&mut *caller, ptr as usize, data).is_err() {
        return -4;
    }
    data.len() as i32
}

fn run_host_future<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create host ABI runtime");
        rt.block_on(fut)
    }
}

/// Register the unified `nexus_host` microkernel syscall ABI on a Wasmtime `Linker`.
/// Error return codes: `-1` = missing host context, `-2` = denied by `CellDbConfig`/IAM,
/// `-3` = execution/storage error, `-4` = guest linear memory or buffer too small.
fn register_nexus_host_abi(linker: &mut Linker<CrystalWasiState>) -> Result<()> {
    linker
        .func_wrap(
            "nexus_host",
            "nexus_log",
            |mut caller: Caller<'_, CrystalWasiState>, ptr: i32, len: i32| {
                if let Some(bytes) = read_guest_bytes(&mut caller, ptr, len) {
                    let msg = String::from_utf8_lossy(&bytes).to_string();
                    if let Some(host) = &caller.data().host {
                        let entry = match &host.request_id {
                            Some(rid) => format!("[req:{}] {}", rid, msg),
                            None => msg,
                        };
                        if let Ok(mut logs) = host.logs.lock() {
                            logs.push(entry);
                        }
                    }
                }
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_db_query",
            |mut caller: Caller<'_, CrystalWasiState>,
             flavor_ptr: i32,
             flavor_len: i32,
             query_ptr: i32,
             query_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(flavor_bytes) = read_guest_bytes(&mut caller, flavor_ptr, flavor_len) else {
                    return -4;
                };
                let Some(query_bytes) = read_guest_bytes(&mut caller, query_ptr, query_len) else {
                    return -4;
                };
                let flavor = String::from_utf8_lossy(&flavor_bytes).to_string();
                let query = String::from_utf8_lossy(&query_bytes).to_string();
                let Some(host) = caller.data().host.clone() else {
                    return -1;
                };
                // Enforce formal EffectiveCapabilities before touching StateEngine
                let mutating = is_mutating_query(&query);
                if (mutating && !host.capabilities.has(Capability::DbWrite))
                    || (!mutating && !host.capabilities.has(Capability::DbRead))
                {
                    global_metrics().inc_iam_auth_denial();
                    return -2;
                }
                let Ok(binding) = CellManager::check_db_config(
                    &host.db_config,
                    &host.app,
                    &host.cell_id,
                    CellDbTransport::Internal,
                    &flavor,
                ) else {
                    return -2;
                };
                let Some(nexus) = host.engine.as_nexus_db() else {
                    return -3;
                };
                let auth_opt = if binding.read_only {
                    Some(nexus_db::auth::AuthContext {
                        level: nexus_db::auth::AuthLevel::Database(
                            binding.target_ns.clone(),
                            binding.target_db.clone(),
                        ),
                        roles: vec![nexus_db::auth::Role::Viewer],
                        actor: Some(format!("cell:{}/{}", host.app, host.cell_id)),
                        access_name: None,
                        token_claims: None,
                    })
                } else {
                    None
                };
                let res = execute_unified_query(
                    nexus,
                    &binding.target_ns,
                    &binding.target_db,
                    &flavor,
                    &query,
                    Vec::new(),
                    auth_opt,
                );
                match res {
                    Ok(val) => {
                        let json = serde_json::to_vec(&val).unwrap_or_else(|_| b"null".to_vec());
                        write_guest_bytes(&mut caller, out_ptr, out_cap, &json)
                    }
                    Err(_) => -3,
                }
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_blob_put",
            |mut caller: Caller<'_, CrystalWasiState>,
             bucket_ptr: i32,
             bucket_len: i32,
             key_ptr: i32,
             key_len: i32,
             val_ptr: i32,
             val_len: i32|
             -> i32 {
                let Some(b) = read_guest_bytes(&mut caller, bucket_ptr, bucket_len) else {
                    return -4;
                };
                let Some(k) = read_guest_bytes(&mut caller, key_ptr, key_len) else {
                    return -4;
                };
                let Some(v) = read_guest_bytes(&mut caller, val_ptr, val_len) else {
                    return -4;
                };
                let Some(host) = caller.data().host.clone() else {
                    return -1;
                };
                if !host.capabilities.has(Capability::BlobWrite) {
                    global_metrics().inc_iam_auth_denial();
                    return -2;
                }
                let bucket = String::from_utf8_lossy(&b).to_string();
                let key = String::from_utf8_lossy(&k).to_string();
                let res = run_host_future(async move {
                    let _ = host.blobs.create_bucket(&bucket).await;
                    host.blobs
                        .put_object(&bucket, &key, bytes::Bytes::from(v))
                        .await
                });
                if res.is_ok() { 0 } else { -3 }
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_blob_get",
            |mut caller: Caller<'_, CrystalWasiState>,
             bucket_ptr: i32,
             bucket_len: i32,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(b) = read_guest_bytes(&mut caller, bucket_ptr, bucket_len) else {
                    return -4;
                };
                let Some(k) = read_guest_bytes(&mut caller, key_ptr, key_len) else {
                    return -4;
                };
                let Some(host) = caller.data().host.clone() else {
                    return -1;
                };
                if !host.capabilities.has(Capability::BlobRead) {
                    global_metrics().inc_iam_auth_denial();
                    return -2;
                }
                let bucket = String::from_utf8_lossy(&b).to_string();
                let key = String::from_utf8_lossy(&k).to_string();
                match run_host_future(host.blobs.get_object(&bucket, &key)) {
                    Ok(Some(bytes)) => write_guest_bytes(&mut caller, out_ptr, out_cap, &bytes),
                    Ok(None) => 0,
                    Err(_) => -3,
                }
            },
        )
        .map_err(wt_err)?;

    // --- Universal Native Hardware & OS Native UI C-ABI (`nexus_host`) ---
    linker
        .func_wrap(
            "nexus_host",
            "nexus_hw_list",
            |mut caller: Caller<'_, CrystalWasiState>,
             class_ptr: i32,
             class_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(host) = caller.data().host.clone() else {
                    return -1;
                };
                if !host.capabilities.has(Capability::HwInfo) {
                    global_metrics().inc_iam_auth_denial();
                    return -2;
                }
                let filter = if class_len > 0 {
                    let Some(bytes) = read_guest_bytes(&mut caller, class_ptr, class_len) else {
                        return -4;
                    };
                    crate::hardware::HardwareClass::from_str_filter(&String::from_utf8_lossy(&bytes))
                } else {
                    None
                };
                let devices = crate::hardware::HardwareRegistry::global().list_devices(filter);
                let json = serde_json::to_vec(&devices).unwrap_or_else(|_| b"[]".to_vec());
                write_guest_bytes(&mut caller, out_ptr, out_cap, &json)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_hw_call",
            |mut caller: Caller<'_, CrystalWasiState>,
             op_ptr: i32,
             op_len: i32,
             payload_ptr: i32,
             payload_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(op_bytes) = read_guest_bytes(&mut caller, op_ptr, op_len) else {
                    return -4;
                };
                let payload_bytes = if payload_len > 0 {
                    let Some(b) = read_guest_bytes(&mut caller, payload_ptr, payload_len) else {
                        return -4;
                    };
                    b
                } else {
                    b"{}".to_vec()
                };
                let Some(host) = caller.data().host.clone() else {
                    return -1;
                };
                let op = String::from_utf8_lossy(&op_bytes).to_string();
                let req_cap = crate::hardware::required_capability_for_op(&op);
                if !host.capabilities.has(req_cap) {
                    global_metrics().inc_iam_auth_denial();
                    return -2;
                }
                let payload_val: serde_json::Value =
                    serde_json::from_slice(&payload_bytes).unwrap_or_else(|_| serde_json::json!({}));
                let resp = crate::hardware::HardwareRegistry::global().dispatch(&op, &payload_val);
                let json = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
                write_guest_bytes(&mut caller, out_ptr, out_cap, &json)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_ui_commit_ops",
            |mut caller: Caller<'_, CrystalWasiState>,
             batch_ptr: i32,
             batch_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(batch) = read_guest_bytes(&mut caller, batch_ptr, batch_len) else {
                    return -4;
                };
                let Some(host) = caller.data().host.clone() else {
                    return -1;
                };
                if !host.capabilities.has(Capability::OsUi) {
                    global_metrics().inc_iam_auth_denial();
                    return -2;
                }
                let resp = crate::hardware::HardwareRegistry::global().commit_ui_ops(&batch);
                let json = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
                write_guest_bytes(&mut caller, out_ptr, out_cap, &json)
            },
        )
        .map_err(wt_err)?;

    // --- General-Purpose `NexusSharedArena` SPSC Ring Buffer C-ABI ---
    linker
        .func_wrap(
            "nexus_host",
            "nexus_ring_alloc",
            |caller: Caller<'_, CrystalWasiState>, capacity: i32| -> i64 {
                if capacity <= 0 {
                    return -4;
                }
                let Some(owner) = caller.data().arena_owner.clone() else {
                    return -1;
                };
                match crate::arena::NexusSharedArena::global().alloc_ring(
                    owner,
                    "guest.ring",
                    capacity as usize,
                    crate::arena::TransportMode::PortableCopy,
                ) {
                    Ok(desc) => desc.handle.pack_i64(),
                    Err(_) => -3,
                }
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_ring_write",
            |mut caller: Caller<'_, CrystalWasiState>,
             packed_handle: i64,
             src_ptr: i32,
             src_len: i32|
             -> i32 {
                if src_ptr < 0 || src_len < 0 {
                    return -4;
                }
                let Some(owner) = caller.data().arena_owner.clone() else {
                    return -1;
                };
                let handle = crate::arena::RingBufferHandle::unpack_i64(packed_handle);
                let ring = match crate::arena::NexusSharedArena::global().get_ring(handle, Some(&owner)) {
                    Ok(r) => r,
                    Err(crate::arena::ArenaError::PermissionDenied) => return -2,
                    Err(_) => return -3,
                };
                let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                    return -4;
                };
                let start = src_ptr as usize;
                let end = match start.checked_add(src_len as usize) {
                    Some(v) => v,
                    None => return -4,
                };
                let data = mem.data(&caller);
                if end > data.len() {
                    return -4;
                }
                // Direct slice transfer from Wasm linear memory into SPSC ring (zero temp Vec)
                match ring.write(&data[start..end]) {
                    Ok(n) => n as i32,
                    Err(crate::arena::ArenaError::Busy) => -5,
                    Err(_) => -3,
                }
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "nexus_host",
            "nexus_ring_read",
            |mut caller: Caller<'_, CrystalWasiState>,
             packed_handle: i64,
             dst_ptr: i32,
             dst_cap: i32|
             -> i32 {
                if dst_ptr < 0 || dst_cap < 0 {
                    return -4;
                }
                let Some(owner) = caller.data().arena_owner.clone() else {
                    return -1;
                };
                let handle = crate::arena::RingBufferHandle::unpack_i64(packed_handle);
                let ring = match crate::arena::NexusSharedArena::global().get_ring(handle, Some(&owner)) {
                    Ok(r) => r,
                    Err(crate::arena::ArenaError::PermissionDenied) => return -2,
                    Err(_) => return -3,
                };
                let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                    return -4;
                };
                let start = dst_ptr as usize;
                let end = match start.checked_add(dst_cap as usize) {
                    Some(v) => v,
                    None => return -4,
                };
                let data = mem.data_mut(&mut caller);
                if end > data.len() {
                    return -4;
                }
                // Direct slice transfer from SPSC ring into Wasm linear memory (zero temp Vec)
                match ring.read(&mut data[start..end]) {
                    Ok(n) => n as i32,
                    Err(crate::arena::ArenaError::Busy) => -5,
                    Err(_) => -3,
                }
            },
        )
        .map_err(wt_err)?;

    Ok(())
}

fn parse_cgi_response(raw: &[u8]) -> (u16, BTreeMap<String, String>, Vec<u8>) {
    let mut status = 200u16;
    let mut headers = BTreeMap::new();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)));

    let Some((idx, sep_len)) = split else {
        return (status, headers, raw.to_vec());
    };
    let head_str = String::from_utf8_lossy(&raw[..idx]);
    for line in head_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("Status") {
                if let Some(code) = val.split_whitespace().next().and_then(|s| s.parse::<u16>().ok()) {
                    status = code;
                }
            } else {
                headers.insert(key, val);
            }
        }
    }
    (status, headers, raw[idx + sep_len..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_aot_crystal_and_enforces_fuel_limit() {
        let crystal = CrystalEngine::new().unwrap();

        let add_wat = br#"
            (module
                (func (export "add") (param i64 i64) (result i64)
                    local.get 0
                    local.get 1
                    i64.add)
            )
        "#;

        let aot = crystal.compile_aot(add_wat).unwrap();
        assert!(!aot.is_empty());
        let sum = crystal.run_aot_i64(&aot, "add", 19, 23, 10_000).unwrap();
        assert_eq!(sum, 42);

        let spin_wat = br#"
            (module
                (func (export "spin") (param i64 i64) (result i64)
                    (loop $l
                        br $l)
                    i64.const 0)
            )
        "#;
        let trapped = crystal.run_wasm_i64(spin_wat, "spin", 0, 0, 1_000);
        assert!(trapped.is_err());
    }

    #[test]
    fn runs_wasi_p1_polyglot_module_and_cgi_http_response() {
        let crystal = CrystalEngine::new().unwrap();
        // Minimal WASI Preview 1 module writing a CGI HTTP response via `fd_write(1, ...)`
        let wasi_cgi_wat = br#"
            (module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 16) "Status: 201 Created\r\nContent-Type: text/plain\r\n\r\nhello from wasi crystal")
                (func (export "_start")
                    ;; iovec at offset 0: { ptr: 16, len: 72 }
                    (i32.store (i32.const 0) (i32.const 16))
                    (i32.store (i32.const 4) (i32.const 72))
                    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                )
            )
        "#;

        let cgi = crystal
            .invoke_wasi_cgi(wasi_cgi_wat, "GET", "/index.php", "p=1", b"", None, 1_000_000)
            .unwrap();
        assert_eq!(cgi.status, 201);
        assert_eq!(cgi.headers.get("Content-Type").map(String::as_str), Some("text/plain"));
        assert_eq!(String::from_utf8_lossy(&cgi.body), "hello from wasi crystal");
        assert!(cgi.fuel_consumed > 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wasi_guest_calls_nexus_host_db_query_and_enforces_cell_db_config() {
        let db = Arc::new(crate::db::Database::open_mem());
        let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());

        // WASI guest calling `nexus_host::nexus_db_query("surql", "RETURN 42", 256, 256)`
        // and writing the returned JSON bytes to stdout via `fd_write(1, ...)`
        let guest_wat = br#"
            (module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (import "nexus_host" "nexus_db_query"
                    (func $db_query (param i32 i32 i32 i32 i32 i32) (result i32)))
                (import "nexus_host" "nexus_log"
                    (func $log (param i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 32) "surql")
                (data (i32.const 64) "RETURN 42")
                (data (i32.const 96) "wasi-guest-ran")
                (func (export "_start")
                    (local $n i32)
                    (call $log (i32.const 96) (i32.const 14))
                    (local.set $n
                        (call $db_query
                            (i32.const 32) (i32.const 5)
                            (i32.const 64) (i32.const 9)
                            (i32.const 256) (i32.const 256)))
                    (if (i32.gt_s (local.get $n) (i32.const 0))
                        (then
                            (i32.store (i32.const 0) (i32.const 256))
                            (i32.store (i32.const 4) (local.get $n))
                            (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                        )
                    )
                )
            )
        "#;

        // 1. Dedicated DB allowed -> guest receives live JSON result `[42]` from nexus-db
        let host_ok = NexusHostContext::new(
            "demo",
            "wasi_cell",
            CellDbConfig::dedicated_minimal(),
            db.clone(),
            blobs.clone(),
        );
        let host_ok_clone = host_ok.clone();
        let out = tokio::task::spawn_blocking(move || {
            let crystal = CrystalEngine::new().unwrap();
            crystal
                .run_wasi_with_host(guest_wat, WasiRunConfig::default(), host_ok_clone)
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(String::from_utf8_lossy(&out.stdout).contains("42"));
        assert_eq!(host_ok.logs.lock().unwrap().as_slice(), &["wasi-guest-ran"]);

        // 2. Stateless CellDbConfig -> `nexus_db_query` returns -2 (denied) and stdout stays empty
        let host_denied = NexusHostContext::new(
            "demo",
            "stateless_cell",
            CellDbConfig::stateless(),
            db,
            blobs,
        );
        let out_denied = tokio::task::spawn_blocking(move || {
            let crystal = CrystalEngine::new().unwrap();
            crystal
                .run_wasi_with_host(guest_wat, WasiRunConfig::default(), host_denied)
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(out_denied.exit_code, 0);
        assert!(out_denied.stdout.is_empty());
    }
}
