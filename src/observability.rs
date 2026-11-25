use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Zero-dependency, lock-free observability contract shared across all Nexus-IO subsystems:
/// Compute (Wasmtime), Cells, Database, BlobBridge/CAS, Runtime Registry, Gateway, and IAM.
#[derive(Default)]
pub struct NexusMetrics {
    pub compute_executions: AtomicU64,
    pub compute_fuel_consumed: AtomicU64,
    pub compute_traps: AtomicU64,
    pub cells_wakes: AtomicU64,
    pub cells_hibernations: AtomicU64,
    pub cells_failures: AtomicU64,
    pub db_queries: AtomicU64,
    pub db_errors: AtomicU64,
    pub blob_reads: AtomicU64,
    pub blob_writes: AtomicU64,
    pub blob_cas_conflicts: AtomicU64,
    pub blob_corrupt_reads: AtomicU64,
    pub registry_pulls: AtomicU64,
    pub registry_registrations: AtomicU64,
    pub registry_aot_failures: AtomicU64,
    pub gateway_requests: AtomicU64,
    pub iam_auth_failures: AtomicU64,
    pub iam_auth_denials: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub compute_executions: u64,
    pub compute_fuel_consumed: u64,
    pub compute_traps: u64,
    pub cells_wakes: u64,
    pub cells_hibernations: u64,
    pub cells_failures: u64,
    pub db_queries: u64,
    pub db_errors: u64,
    pub blob_reads: u64,
    pub blob_writes: u64,
    pub blob_cas_conflicts: u64,
    pub blob_corrupt_reads: u64,
    pub registry_pulls: u64,
    pub registry_registrations: u64,
    pub registry_aot_failures: u64,
    pub gateway_requests: u64,
    pub iam_auth_failures: u64,
    pub iam_auth_denials: u64,
}

static GLOBAL_METRICS: Lazy<NexusMetrics> = Lazy::new(NexusMetrics::default);

pub fn global_metrics() -> &'static NexusMetrics {
    &GLOBAL_METRICS
}

impl NexusMetrics {
    pub fn inc_compute_exec(&self, fuel: u64) {
        self.compute_executions.fetch_add(1, Ordering::Relaxed);
        self.compute_fuel_consumed.fetch_add(fuel, Ordering::Relaxed);
    }
    pub fn inc_compute_trap(&self) {
        self.compute_traps.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cell_wake(&self) {
        self.cells_wakes.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cell_hibernate(&self) {
        self.cells_hibernations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cell_failure(&self) {
        self.cells_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_db_query(&self) {
        self.db_queries.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_db_error(&self) {
        self.db_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blob_read(&self) {
        self.blob_reads.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blob_write(&self) {
        self.blob_writes.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cas_conflict(&self) {
        self.blob_cas_conflicts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_corrupt_read(&self) {
        self.blob_corrupt_reads.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_registry_pull(&self) {
        self.registry_pulls.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_registry_register(&self) {
        self.registry_registrations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_registry_aot_failure(&self) {
        self.registry_aot_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_gateway_request(&self) {
        self.gateway_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_iam_auth_failure(&self) {
        self.iam_auth_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_iam_auth_denial(&self) {
        self.iam_auth_denials.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            compute_executions: self.compute_executions.load(Ordering::Relaxed),
            compute_fuel_consumed: self.compute_fuel_consumed.load(Ordering::Relaxed),
            compute_traps: self.compute_traps.load(Ordering::Relaxed),
            cells_wakes: self.cells_wakes.load(Ordering::Relaxed),
            cells_hibernations: self.cells_hibernations.load(Ordering::Relaxed),
            cells_failures: self.cells_failures.load(Ordering::Relaxed),
            db_queries: self.db_queries.load(Ordering::Relaxed),
            db_errors: self.db_errors.load(Ordering::Relaxed),
            blob_reads: self.blob_reads.load(Ordering::Relaxed),
            blob_writes: self.blob_writes.load(Ordering::Relaxed),
            blob_cas_conflicts: self.blob_cas_conflicts.load(Ordering::Relaxed),
            blob_corrupt_reads: self.blob_corrupt_reads.load(Ordering::Relaxed),
            registry_pulls: self.registry_pulls.load(Ordering::Relaxed),
            registry_registrations: self.registry_registrations.load(Ordering::Relaxed),
            registry_aot_failures: self.registry_aot_failures.load(Ordering::Relaxed),
            gateway_requests: self.gateway_requests.load(Ordering::Relaxed),
            iam_auth_failures: self.iam_auth_failures.load(Ordering::Relaxed),
            iam_auth_denials: self.iam_auth_denials.load(Ordering::Relaxed),
        }
    }
}
