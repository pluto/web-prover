pub(crate) mod hyper_io;
mod request_opt;
mod requests;

pub mod prover;
pub use prover::prover;

pub mod verify;
use tracing::error;
pub use verify::verify;

use wasm_bindgen::prelude::*;

pub use crate::request_opt::{RequestOptions, VerifyResult};

pub use wasm_bindgen_rayon::init_thread_pool;

use js_sys::JSON;

use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

use std::panic;
use tracing::debug;
use tracing_subscriber::fmt::format::Pretty;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use tracing_web::{performance_layer, MakeWebConsoleWriter};

extern crate console_error_panic_hook;

#[wasm_bindgen]
pub fn setup_tracing_web(logging_filter: &str) {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        // .with_thread_ids(true)
        // .with_thread_names(true)
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console
    let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

    let filter_layer = EnvFilter::builder()
        .parse(logging_filter)
        .unwrap_or_default();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(perf_layer)
        .init(); // Install these as subscribers to tracing events

    // https://github.com/rustwasm/console_error_panic_hook
    panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));

    debug!("🪵 Logging set up 🪵")
}

pub async fn fetch_as_json_string(url: &str, opts: &RequestInit) -> Result<String, JsValue> {
    let request = Request::new_with_str_and_init(url, opts)?;
    let window = web_sys::window().expect("Window object");
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into()?;
    let json = JsFuture::from(resp.json()?).await?;
    let stringified = JSON::stringify(&json)?;
    stringified
        .as_string()
        .ok_or_else(|| JsValue::from_str("Could not stringify JSON"))
}
