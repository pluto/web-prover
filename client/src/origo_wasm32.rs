use core::slice;
use std::{
  ops::Deref,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
  time::Duration,
};

#[cfg(feature = "tee-dummy-token-verifier")]
use caratls_ekm_client::DummyTokenVerifier;
use caratls_ekm_client::TeeTlsConnector;
#[cfg(feature = "tee-google-confidential-space-token-verifier")]
use caratls_ekm_google_confidential_space_client::GoogleConfidentialSpaceTokenVerifier;
use futures::{channel::oneshot, AsyncReadExt, AsyncWriteExt};
use hyper::StatusCode;
use tls_client2::origo::OrigoConnection;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::window;
use ws_stream_wasm::WsMeta;

use crate::{
  config, config::NotaryMode, errors, errors::ClientErrors, origo::OrigoSecrets,
  tls_client_async2::bind_client, TeeProof,
};

async fn sleep(ms: u64) {
  let promise = js_sys::Promise::new(&mut |resolve, _| {
    window()
      .unwrap()
      .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
      .unwrap();
  });
  JsFuture::from(promise).await.unwrap();
}

pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<(tls_client2::origo::OrigoConnection, Option<TeeProof>), errors::ClientErrors> {
  if config.mode == NotaryMode::TEE {
    let (conn, tee_proof) = handle_tee_mode(config, session_id).await?;
    return Ok((conn, Some(tee_proof)));
  } else {
    let conn = handle_origo_mode(config, session_id).await?;
    return Ok((conn, None));
  }
}

async fn handle_origo_mode(
  config: config::Config,
  session_id: String,
) -> Result<OrigoConnection, ClientErrors> {
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

  let root_store =
    crate::tls::tls_client2_default_root_store(config.notary_ca_cert.clone().map(|c| vec![c]));

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

  let (mut client_tls_conn, tls_fut) = bind_client(ws_stream.into_io(), client);

  let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

  let (tls_sender, _tls_receiver) = oneshot::channel();
  spawn_local(async {
    let result = tls_fut.await;
    let _ = tls_sender.send(result);
  });

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await?;

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  spawn_local(async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  });

  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let mut client_socket = connection_receiver.await.unwrap()?.io.into_inner();
  client_socket.close().await.unwrap();

  let origo_conn = origo_conn.lock().unwrap().deref().clone();
  Ok(origo_conn)
}

async fn handle_tee_mode(
  config: config::Config,
  session_id: String,
) -> Result<(OrigoConnection, TeeProof), ClientErrors> {
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

  let root_store =
    crate::tls::tls_client2_default_root_store(config.notary_ca_cert.clone().map(|c| vec![c]));

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

  #[cfg(feature = "tee-google-confidential-space-token-verifier")]
  let token_verifier = GoogleConfidentialSpaceTokenVerifier::new("audience").await; // TODO pass in as function input

  #[cfg(feature = "tee-dummy-token-verifier")]
  let token_verifier = DummyTokenVerifier { expect_token: "dummy".to_string() };

  let tee_tls_connector = TeeTlsConnector::new(token_verifier, "example.com"); // TODO example.com
  let tee_tls_stream = tee_tls_connector.connect(ws_stream.into_io()).await?;
  let (mut client_tls_conn, client_tls_fut) = bind_client(tee_tls_stream.compat(), client);

  let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

  let (tls_sender, tls_receiver) = oneshot::channel();
  spawn_local(async {
    let result = client_tls_fut.await;
    let _ = tls_sender.send(result);
  });

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await?;

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  spawn_local(async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  });

  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let origo_conn = origo_conn.lock().unwrap().deref().clone();

  let (_, mut reunited_socket) = tls_receiver.await.unwrap().unwrap();

  let mut buffer = [0u8; 1];
  loop {
    reunited_socket.read_exact(&mut buffer).await?;
    if buffer.len() == 1 && buffer[0] == 0xAA {
      debug!("Magic byte 0xAA received, server is ready");
      break;
    }
    sleep(100).await;
    debug!("Waiting for magic byte, received: {:?}", buffer[0]);
  }

  let manifest_bytes = config.proving.manifest.unwrap().to_wire_bytes();
  reunited_socket.write_all(&manifest_bytes).await?;

  let origo_secret_bytes = OrigoSecrets::from_origo_conn(&origo_conn).to_wire_bytes();
  reunited_socket.write_all(&origo_secret_bytes).await?;

  let tee_proof_bytes = crate::origo::read_wire_struct(&mut reunited_socket).await;
  let tee_proof = TeeProof::from_wire_bytes(&tee_proof_bytes);

  // TODO something will be dropped here. if it's dropped, it closes ...
  // let mut client_socket = connection_receiver.await.unwrap()?.io.into_inner();
  // client_socket.close().await.unwrap();

  Ok((origo_conn, tee_proof))
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
