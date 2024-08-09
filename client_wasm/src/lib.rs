use std::panic;

use base64::prelude::*;
use client::config::Config;
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

#[wasm_bindgen]
pub async fn prover(config: JsValue) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));

  let config: Config = serde_wasm_bindgen::from_value(config).unwrap(); // TODO replace unwrap

  let proof = client::prover_inner(config)
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

  let result = client::verify(proof, notary_pubkey_str)
    .await;
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
