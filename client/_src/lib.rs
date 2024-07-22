pub mod client;
use std::panic;

use client::{prover_inner, Config};
use tracing::{debug, info, subscriber, trace, Level};

cfg_if::cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use wasm_bindgen::prelude::*;
    use gloo_utils::format::JsValueSerdeExt;
    use tracing_subscriber::{
      fmt::{format::Pretty, time::UtcTime},
      prelude::*,
      EnvFilter,
    };
    use tracing_web::{performance_layer, MakeWebConsoleWriter};

  } else if #[cfg(target_os = "ios")] {
    // TODO
  } else {
    // TODO
  }
}

// This file contains lib entrypoints ...
//  - prover()
//  - setup_tracing()
// for all targets ...
//  - wasm32
//  - ios
//  - native (aarch64, x86_64)

// WASM target
// -----------
#[cfg(target_arch = "wasm32")]
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

#[cfg(target_arch = "wasm32")]
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

// iOS target
// ----------
#[cfg(target_os = "ios")]
#[no_mangle]
// TODO: We should probably clarify this safety doc
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn prover(config_json: *const c_char) -> *const c_char {
  let result: Result<TlsProof, ClientErrors> =
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let config_str = unsafe {
        assert!(!config_json.is_null());
        CStr::from_ptr(config_json).to_str().map_err(ClientErrors::from)
      };
      let config: Config = serde_json::from_str(config_str?)?;
      let rt = tokio::runtime::Runtime::new()?;
      rt.block_on(prover_inner(config))
    }))
    .map_err(|e| panic!("{e:?}"))
    .unwrap();
  let proof = result
    .map_err(|e| {
      let backtrace = std::backtrace::Backtrace::capture();
      panic!(
        "Error:{e:?}/n
  Stack:{backtrace:?}"
      )
    })
    .unwrap();
  CString::new(
    serde_json::to_string_pretty(&Output {
      proof: Some(serde_json::to_string_pretty(&proof).unwrap()),
      error: None,
    })
    .map_err(|e| panic!("{e:?}"))
    .unwrap(),
  )
  .map_err(|e| panic!("{e:?}"))
  .unwrap()
  .into_raw()
}

#[cfg(target_os = "ios")]
#[no_mangle]
pub fn setup_tracing(logging_filter: *const c_char) {
  let collector = tracing_subscriber::fmt().with_max_level(Level::TRACE).finish(); // TODO use actual logging_filter
  subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();
}

// aarch64 and x86_64 targets
// --------------------------
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub async fn prover(config: Config) -> Result<TlsProof, ClientErrors> { prover_inner(config).await }

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn setup_tracing(logging_filter: Level) {
  let collector = tracing_subscriber::fmt().with_max_level(logging_filter).finish();
  subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();
}
