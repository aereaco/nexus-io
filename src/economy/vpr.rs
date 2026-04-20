// Variable Payout Rate (VPR) Engine
// Formula: VPR = BASE_RATE * UPTIME_MULT * SUSTAINABILITY_MULT

/// Configuration for VPR calculation
pub struct VprConfig {
    pub base_rate: f64,          // Base payout per unit of work
    pub uptime_target: f64,      // Target uptime for 1.0 multiplier
}

impl Default for VprConfig {
    fn default() -> Self {
        Self {
            base_rate: 1.0,      // 1 ZA per unit
            uptime_target: 0.99, // 99% uptime
        }
    }
}

/// Calculate the payout rate for a node
pub fn calculate_payout_rate(
    config: &VprConfig,
    uptime: f64,
    is_green: bool,
    cpu_cores: u32,
    gpu_count: u32,
) -> f64 {
    // 1. Uptime Multiplier
    let uptime_mult = if uptime >= config.uptime_target {
        1.0 + (uptime - config.uptime_target) * 2.0
    } else {
        (uptime / config.uptime_target).powi(2)
    };

    // 2. Sustainability Multiplier
    let green_mult = if is_green { 1.15 } else { 1.0 };

    // 3. Performance Score (Hardware Weight)
    // Every 4 cores gives a 1.0 multiplier base, and each GPU gives a massive boost
    let performance_score = (cpu_cores as f64 / 4.0) + (gpu_count as f64 * 10.0);

    config.base_rate * uptime_mult * green_mult * performance_score
}

/// Pricing service to calculate job costs
pub struct PricingService {
    config: VprConfig,
}

impl PricingService {
    pub fn new(config: VprConfig) -> Self {
        Self { config }
    }

    /// Calculate cost for a compute job in ZA credits
    pub fn estimate_compute_cost(
        &self,
        flavor: &str,
        duration_secs: u64,
    ) -> f64 {
        let flavor_mult = match flavor {
            "gpu-small" => 5.0,
            "gpu-large" => 20.0,
            "cpu-only" => 1.0,
            _ => 1.0,
        };

        self.config.base_rate * flavor_mult * (duration_secs as f64 / 3600.0)
    }
}
