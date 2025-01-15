use std::panic;

use client::config::Config;
use tlsn_core::proof::TlsProof;
use tracing::debug;
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
  EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

/// ProvingParamsWasm interface is for efficiently moving data between
/// the javascript and wasm runtime. Using wasm_bindgen creates a
/// mirrored representation in javascript.
///
/// This allows us to directly read javascript runtime memory from rust,
/// enabling more efficient serde.
#[wasm_bindgen(getter_with_clone)]
pub struct ProvingParamsWasm {
  pub aux_params: js_sys::Uint8Array, // Custom byte parser for aux_params
}

#[wasm_bindgen]
impl ProvingParamsWasm {
  #[wasm_bindgen(constructor)]
  pub fn new(ap: js_sys::Uint8Array) -> ProvingParamsWasm { Self { aux_params: ap } }
}

#[wasm_bindgen]
pub async fn prover(config: JsValue, proving_params: ProvingParamsWasm) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));

  debug!("start config serde");
  let config: Config = serde_wasm_bindgen::from_value(config).unwrap(); // TODO replace unwrap
  config.set_session_id();
  debug!("end config serde");

  let proof = client::prover_inner(config, Some(proving_params.aux_params.to_vec()))
    .await
    .map_err(|e| JsValue::from_str(&format!("Could not produce proof: {:?}", e)))?;

  serde_json::to_string_pretty(&proof)
    .map_err(|e| JsValue::from_str(&format!("Could not serialize proof: {:?}", e)))
}

#[wasm_bindgen]
pub async fn verify(proof: &str, notary_pubkey_str: &str) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));

  let proof: TlsProof = serde_json::from_str(proof)
    .map_err(|e| JsValue::from_str(&format!("Could not deserialize proof: {:?}", e)))?;

  let result = client::tlsn::verify(proof, notary_pubkey_str).await;
  // .map_err(|e| JsValue::from_str(&format!("Could not verify proof: {:?}", e)))?;

  serde_json::to_string_pretty(&result)
    .map_err(|e| JsValue::from_str(&format!("Could not serialize result: {:?}", e)))
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
