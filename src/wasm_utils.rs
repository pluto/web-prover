use core::slice;
use std::{
  pin::Pin,
  task::{Context, Poll},
};

use js_sys::JSON;
use pin_project_lite::pin_project;
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
  EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
pub use wasm_bindgen_rayon::init_thread_pool;
use web_sys::{Request, RequestInit, Response};

#[cfg(feature = "tracing")] use super::*;

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

  let filter_layer = EnvFilter::builder().parse(logging_filter).unwrap_or_default();

  tracing_subscriber::registry().with(filter_layer).with(fmt_layer).with(perf_layer).init(); // Install these as subscribers to tracing events

  #[cfg(feature = "tracing")]
  debug!("🪵 Logging set up 🪵")
}

#[deprecated]
pub async fn fetch_as_json_string(url: &str, opts: &RequestInit) -> Result<String, JsValue> {
  let request = Request::new_with_str_and_init(url, opts)?;
  let window = web_sys::window().expect("Window object");
  let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
  assert!(resp_value.is_instance_of::<Response>());
  let resp: Response = resp_value.dyn_into()?;
  let json = JsFuture::from(resp.json()?).await?;
  let stringified = JSON::stringify(&json)?;
  stringified.as_string().ok_or_else(|| JsValue::from_str("Could not stringify JSON"))
}

pin_project! {
    #[derive(Debug)]
    pub(crate) struct WasmAsyncIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> WasmAsyncIo<T> {
  /// Create a new `FuturesIo` wrapping the given I/O object.
  ///
  /// # Safety
  ///
  /// This wrapper is only safe to use if the inner I/O object does not under any circumstance
  /// read from the buffer passed to `poll_read` in the `futures::AsyncRead` implementation.
  pub(crate) fn new(inner: T) -> Self { Self { inner } }
}

impl<T> hyper::rt::Write for WasmAsyncIo<T>
where T: futures::AsyncWrite + Unpin
{
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_close(cx)
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write_vectored(cx, bufs)
  }
}

// Adapted from https://github.com/hyperium/hyper-util/blob/99b77a5a6f75f24bc0bcb4ca74b5f26a07b19c80/src/rt/tokio.rs
impl<T> hyper::rt::Read for WasmAsyncIo<T>
where T: futures::AsyncRead + Unpin
{
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    mut buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    // Safety: buf_slice should only be written to, so it's safe to convert `&mut [MaybeUninit<u8>]`
    // to `&mut [u8]`.
    let buf_slice = unsafe {
      slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
    };

    let n = match futures::AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
      Poll::Ready(Ok(n)) => n,
      other => return other.map_ok(|_| ()),
    };

    unsafe {
      buf.advance(n);
    }
    Poll::Ready(Ok(()))
  }
}
