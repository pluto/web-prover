use std::{ops::Range, panic, time::Duration};

use elliptic_curve::pkcs8::DecodePublicKey;
use futures::{channel::oneshot, AsyncWriteExt};
use hyper::{Request, StatusCode};
use js_sys::{Array, JSON};
use strum::EnumMessage;
use strum_macros;
use tlsn_core::proof::{SessionProof, TlsProof};
use tlsn_prover::tls::{
  state::{Closed, Notarize},
  Prover, ProverConfig,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
};
use tracing_web::{performance_layer, MakeConsoleWriter};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{spawn_local, JsFuture};
pub use wasm_bindgen_rayon::init_thread_pool;
use web_sys::{Headers, Request as WebsysRequest, RequestInit, RequestMode, Response};
use web_time::Instant;
use ws_stream_wasm::*;

use crate::{config::Config, send_request};

// uses websockets to connect to notary and websocket proxy
pub async fn setup_connection(config: &mut Config, prover_config: ProverConfig) -> Prover<Closed> {
  let session_id = config.session_id();

  let websocket_proxy_url = config.websocket_proxy_url.clone().unwrap();

  let wss_url = format!(
    "wss://{}:{}/v1/tlsnotary?session_id={}",
    config.notary_host,
    config.notary_port,
    session_id.clone(),
  );

  let (_, notary_ws_stream) = WsMeta::connect(wss_url, None).await.unwrap();
  let notary_ws_stream_into = notary_ws_stream.into_io();

  let prover = Prover::new(prover_config).setup(notary_ws_stream_into).await.unwrap();

  let ws_query = url::form_urlencoded::Serializer::new(String::new())
    .extend_pairs([
      ("target_host", config.target_host()),
      ("target_port", config.target_port().to_string()),
    ])
    .finish();

  let (_, client_ws_stream) =
    WsMeta::connect(format!("{}?{}", websocket_proxy_url, ws_query), None).await.unwrap();
  let client_ws_stream_into = client_ws_stream.into_io();

  let (mpc_tls_connection, prover_fut) = prover.connect(client_ws_stream_into).await.unwrap();

  let (prover_sender, prover_receiver) = oneshot::channel();
  let handled_prover_fut = async {
    let result = prover_fut.await;
    let _ = prover_sender.send(result);
  };
  spawn_local(handled_prover_fut);

  let mpc_tls_connection = unsafe { FuturesIo::new(mpc_tls_connection) };

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(mpc_tls_connection).await.unwrap();

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  spawn_local(handled_connection_fut);

  send_request(request_sender, config.to_request()).await;

  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner();
  client_socket.close().await.unwrap();

  prover_receiver.await.unwrap().unwrap()
}

use core::slice;
use std::{
  pin::Pin,
  task::{Context, Poll},
};

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
