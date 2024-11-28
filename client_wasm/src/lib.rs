use std::{collections::HashMap, panic};

use base64::prelude::*;
use client::config::{self, Config};
use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::Full;
use hyper::{body::Bytes, Body, Request};
use serde::{Deserialize, Serialize};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, info, trace};
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
  EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
pub use wasm_bindgen_rayon::init_thread_pool;
use ws_stream_wasm::WsMeta;

/// ProvingParamsWasm interface is for efficiently moving data between
/// the javascript and wasm runtime. Using wasm_bindgen creates a
/// mirrored representation in javascript.
///
/// This allows us to directly read javascript runtime memory from rust,
/// saving the overhead of serde incurred by using techniques
/// like json or bincode.
#[wasm_bindgen(getter_with_clone)]
pub struct ProvingParamsWasm {
  pub powers_of_g:    js_sys::Uint8Array, // Custom byte parser to G1Affine
  pub powers_of_h:    js_sys::Uint8Array, // Custom byte parser to G2Affine
  pub hash_params:    js_sys::Uint8Array, // Deserialized via bincode, expects list of bytes.
  pub witnesses:      Vec<js_sys::Uint8Array>, // Custom byte parser
  pub circuit_params: JsValue,            // Deserialized via JSON
}

#[wasm_bindgen]
impl ProvingParamsWasm {
  #[wasm_bindgen(constructor)]
  pub fn new(
    g: js_sys::Uint8Array,
    h: js_sys::Uint8Array,
    hp: js_sys::Uint8Array,
    w: Vec<js_sys::Uint8Array>,
    cp: JsValue,
  ) -> ProvingParamsWasm {
    Self {
      powers_of_g:    g,
      powers_of_h:    h,
      hash_params:    hp,
      witnesses:      w,
      circuit_params: cp,
    }
  }
}

#[wasm_bindgen]
pub async fn prover(config: JsValue, proving_params: ProvingParamsWasm) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));

  debug!("prover: pre-serde");
  let mut config: Config = serde_wasm_bindgen::from_value(config).unwrap(); // TODO replace unwrap
  debug!("prover: post-serde");

  // TODO: Refactor this object to remove witnesses from here.
  config.proving.witnesses = Some(proving_params.witnesses.iter().map(|w| w.to_vec()).collect());

  // TODO: Add into impls to convert our wasm object to this
  // TODO: Add into impls to transformed these raw params into aux params
  use proofs::program::data::RawProvingParams;
  let raw_pp = RawProvingParams {
    circuit_params: serde_wasm_bindgen::from_value(proving_params.circuit_params).unwrap(),
    hash_params:    proving_params.hash_params.to_vec(),
    powers_of_g:    proving_params.powers_of_g.to_vec(),
    powers_of_h:    proving_params.powers_of_h.to_vec(),
  };

  let proof = client::prover_inner(config, Some(raw_pp))
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
