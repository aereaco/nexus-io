use anyhow::{anyhow, Result};
use wasmtime::{Config, Engine, Instance, Module, Store};

fn wt_err(e: wasmtime::Error) -> anyhow::Error {
    anyhow!("{}", e)
}

/// Wasmtime Crystal Cell Engine:
/// - **Non-iOS (`#[cfg(not(target_os = "ios"))]`):** Supports Cranelift JIT and AOT pre-compilation (`.cwasm`).
/// - **iOS (`#[cfg(target_os = "ios")]`):** Strictly AOT-only (`runtime` feature, zero JIT — 100% Apple `W^X` compliant).
/// - **Fuel Metering:** Every Crystal cell runs with a strict fuel budget so runaway compute cannot starve the shared-memory host.
pub struct CrystalEngine {
    engine: Engine,
}

impl CrystalEngine {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(wt_err)?;
        Ok(Self { engine })
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

        // 1. Pre-compile to native AOT bytes and execute (iOS-compatible path)
        let aot = crystal.compile_aot(add_wat).unwrap();
        assert!(!aot.is_empty());
        let sum = crystal.run_aot_i64(&aot, "add", 19, 23, 10_000).unwrap();
        assert_eq!(sum, 42);

        // 2. Verify fuel metering traps runaway loops
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
}
