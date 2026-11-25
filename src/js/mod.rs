pub mod cell;
#[cfg(feature = "ops-shell")]
pub mod command;
pub mod transformer;

#[cfg(feature = "ops-shell")]
mod client {
    use nu_protocol::{ShellError, Span, Value as NuValue};
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct JsClient;

    impl JsClient {
        pub fn new(
            _db: Arc<crate::db::Database>,
            _blobs: Arc<crate::storage::BlobBridge>,
        ) -> Self {
            Self
        }

        pub fn eval(&self, _code: String) -> Result<NuValue, ShellError> {
            Err(ShellError::GenericError {
                error: "Wasmtime-only runtime".into(),
                msg: "Nexus-IO uses Wasmtime as its sole guest runtime; deploy JS/TS via Wasm cells (`POST /cells/_runtimes/pull` + cell deployment).".into(),
                span: Some(Span::unknown()),
                help: None,
                inner: vec![],
            })
        }
    }
}

#[cfg(feature = "ops-shell")]
pub use client::JsClient;
