use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::stdlib::value_to_vec;
use crate::value::Value;

/// Pure-Rust linear/dot-product ML model registry (`feature = "ml"`).
/// Provides SurrealML (`ml::<model>`) inference parity in embedded mode without pulling in ONNX C++ runtime.
#[derive(Debug, Clone)]
pub struct LinearModel {
    pub name: String,
    pub version: String,
    pub weights: Vec<f64>,
    pub bias: f64,
}

impl LinearModel {
    pub fn predict(&self, inputs: &[f64]) -> f64 {
        let dot: f64 = self
            .weights
            .iter()
            .zip(inputs.iter())
            .map(|(w, x)| w * x)
            .sum();
        dot + self.bias
    }
}

#[derive(Default)]
pub struct MlRegistry {
    models: Mutex<HashMap<String, LinearModel>>,
}

impl MlRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, model: LinearModel) {
        let key = format!("ml::{}<{}>", model.name, model.version);
        let short = format!("ml::{}", model.name);
        let mut guard = self.models.lock().unwrap();
        guard.insert(key, model.clone());
        guard.insert(short, model);
    }

    pub fn eval(&self, fn_name: &str, args: &[Value]) -> Result<Value> {
        let guard = self.models.lock().unwrap();
        let model = guard
            .get(fn_name)
            .ok_or_else(|| anyhow!("ML model '{}' is not registered", fn_name))?;
        let inputs: Vec<f64> = if args.len() == 1 {
            if let Some(v) = value_to_vec(&args[0]) {
                v
            } else if let Some(x) = args[0].as_f64() {
                vec![x]
            } else {
                Vec::new()
            }
        } else {
            args.iter().filter_map(|v| v.as_f64()).collect()
        };
        Ok(Value::Float(model.predict(&inputs)))
    }
}
