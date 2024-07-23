use gloo_utils::format::JsValueSerdeExt;
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
  EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;
use tracing::{debug, info};
use std::panic;

use client::{Config, prover_inner};

pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub async fn prover(config: JsValue) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));
  let config: Config = config.into_serde().unwrap(); // TODO replace unwrap
  let proof = prover_inner(config)
    .await
    .map_err(|e| JsValue::from_str(&format!("Could not produce proof: {:?}", e)))?;
  serde_json::to_string_pretty(&proof)
    .map_err(|e| JsValue::from_str(&format!("Could not serialize proof: {:?}", e)))
}

#[wasm_bindgen]
pub fn setup_tracing(logging_filter: &str) {
  let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        // .with_thread_ids(true)
        // .with_thread_names(true)
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console
  let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

  let filter_layer = EnvFilter::builder().parse(logging_filter).unwrap_or_default();

  tracing_subscriber::registry().with(filter_layer).with(fmt_layer).with(perf_layer).init(); // Install these as subscribers to tracing events
  debug!("Logging set up")
}
