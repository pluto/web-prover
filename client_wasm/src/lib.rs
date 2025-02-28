use std::panic;

use client::config::Config;
use proofs::program::data::UninitializedSetup;
use tlsn_core::presentation::Presentation;
use tracing::debug;
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
  EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub fn get_web_prover_circuits_version() -> String { client::get_web_prover_circuits_version() }

/// `ProvingParamsWasm` interface is for efficiently moving data between
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
pub struct UninitializedSetupWasm {
  pub(crate) r1cs_types: Vec<js_sys::Uint8Array>,
}

#[wasm_bindgen]
impl UninitializedSetupWasm {
  #[wasm_bindgen(constructor)]
  pub fn new(r1cs_types: Vec<js_sys::Uint8Array>) -> Self { Self { r1cs_types } }
}

impl UninitializedSetupWasm {
  pub fn to_canonical(&self) -> UninitializedSetup {
    let r1cs_types = self.r1cs_types.iter().map(|r1cs| r1cs.to_vec()).collect();
    UninitializedSetup::from_raw_r1cs_types_with_browser_witness(r1cs_types)
  }
}

#[wasm_bindgen]
pub async fn prover(
  config: &JsValue,
  proving_params: &ProvingParamsWasm,
  setup_data: &UninitializedSetupWasm,
) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));

  debug!("start config serde");
  let mut config: Config = serde_wasm_bindgen::from_value(config.clone())?;
  config.set_session_id();
  debug!("end config serde");

  let setup_data = setup_data.to_canonical();

  debug!("start prover");
  let proof =
    client::prover_inner(config, Some(proving_params.aux_params.to_vec()), Some(setup_data))
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
