use core::slice;
use std::{
  collections::HashMap,
  io::{BufReader, Cursor},
  ops::Deref,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
};

use caratls::client::TeeTlsConnector;
use futures::{channel::oneshot, AsyncWriteExt};
use hyper::StatusCode;
use proofs::{circom::witness::load_witness_from_bin_reader, F, G1};
use serde_json::Value;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{config, config::NotaryMode, errors, tls_client_async2::bind_client};

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct WitnessOutput {
  pub data: Vec<js_sys::Uint8Array>,
}

#[wasm_bindgen]
impl WitnessOutput {
  #[wasm_bindgen(constructor)]
  pub fn new(wit: Vec<js_sys::Uint8Array>) -> WitnessOutput { Self { data: wit } }
}
// TODO(WJ 2024-12-12): move to wasm client lib?
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = witness, js_name = createWitness)]
  async fn create_witness_js(input: &JsValue, rom: &JsValue) -> JsValue;
}

// #[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_witness(input: JsValue, rom: JsValue) -> Result<WitnessOutput, JsValue> {
  // Convert the Rust WitnessInput to a JsValue
  let js_witnesses_output = create_witness_js(&input, &rom).await;

  // Call JavaScript function and await the Promise
  info!("result: {:?}", js_witnesses_output);
  let js_obj = js_sys::Object::from(js_witnesses_output);
  let data_value = js_sys::Reflect::get(&js_obj, &JsValue::from_str("data"))?;
  let array = js_sys::Array::from(&data_value);
  let mut data = Vec::with_capacity(array.length() as usize);

  for i in 0..array.length() {
    let item = array.get(i);
    if let Ok(uint8_array) = item.dyn_into::<js_sys::Uint8Array>() {
      data.push(uint8_array);
    }
  }
  debug!("data: {:?}", data);
  Ok(WitnessOutput { data })
}

pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<tls_client2::origo::OrigoConnection, errors::ClientErrors> {
  // TODO build sanitized query
  let wss_url = format!(
    "wss://{}:{}/v1/{}?session_id={}&target_host={}&target_port={}",
    config.notary_host,
    config.notary_port,
    if config.mode == NotaryMode::TEE { "tee" } else { "origo" },
    session_id.clone(),
    config.target_host()?,
    config.target_port()?,
  );

  let root_store = crate::tls::tls_client2_default_root_store();

  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let origo_conn = Arc::new(std::sync::Mutex::new(tls_client2::origo::OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
    tls_client2::ServerName::try_from(config.target_host()?.as_str())?,
  )?;

  let (_, ws_stream) = WsMeta::connect(wss_url.to_string(), None).await?;

  // Either bind client to TEE TLS connection or plain websocket connection
  let (mut client_tls_conn, tls_fut) = if config.mode == NotaryMode::TEE {
    let tee_tls_connector = TeeTlsConnector::new("example.com"); // TODO example.com
    let tee_tls_stream = tee_tls_connector.connect(ws_stream.into_io()).await?;
    bind_client(tee_tls_stream.compat(), client)
  } else {
    bind_client(ws_stream.into_io(), client)
  };

  let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

  let (tls_sender, _tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await;
    // Triggered when the server shuts the connection.
    let _ = tls_sender.send(result);
  };
  spawn_local(handled_tls_fut);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await?;

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  spawn_local(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let mut client_socket = connection_receiver.await.unwrap()?.io.into_inner();
  client_socket.close().await.unwrap();

  let origo_conn = origo_conn.lock().unwrap().deref().clone();
  Ok(origo_conn)
}

pub async fn build_witness_data_from_wasm(
  private_inputs: Vec<HashMap<String, Value>>,
  rom_opcodes: Vec<u64>,
) -> Result<Vec<Vec<F<G1>>>, errors::ClientErrors> {
  let js_witness_input = serde_wasm_bindgen::to_value(&private_inputs).unwrap();
  let js_witness_rom = serde_wasm_bindgen::to_value(&rom_opcodes).unwrap();

  let js_witnesses_output = create_witness(js_witness_input, js_witness_rom).await.unwrap();
  let js_computed_witnesses: Vec<Vec<u8>> =
    js_witnesses_output.data.iter().map(|w| w.to_vec()).collect();
  let mut witnesses = Vec::new();
  for w in js_computed_witnesses {
    witnesses.push(load_witness_from_bin_reader(BufReader::new(Cursor::new(w)))?);
  }

  Ok(witnesses)
}

use pin_project_lite::pin_project;

pin_project! {
    #[derive(Debug)]
    pub(crate) struct FuturesIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> FuturesIo<T> {
  /// Create a new `FuturesIo` wrapping the given I/O object.
  ///
  /// # Safety
  ///
  /// This wrapper is only safe to use if the inner I/O object does not under
  /// any circumstance read from the buffer passed to `poll_read` in the
  /// `futures::AsyncRead` implementation.
  pub(crate) unsafe fn new(inner: T) -> Self { Self { inner } }

  pub(crate) fn into_inner(self) -> T { self.inner }
}

impl<T> hyper::rt::Write for FuturesIo<T>
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
impl<T> hyper::rt::Read for FuturesIo<T>
where T: futures::AsyncRead + Unpin
{
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    mut buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    // Safety: buf_slice should only be written to, so it's safe to convert `&mut
    // [MaybeUninit<u8>]` to `&mut [u8]`.
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
