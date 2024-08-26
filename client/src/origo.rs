use std::sync::Arc;

use futures::{channel::oneshot, AsyncWriteExt};
use hyper::{body::HttpBody, StatusCode};
use hyper_util::rt::TokioIo;
use tlsn_core::proof::TlsProof;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;

use crate::{config, errors};

pub async fn prover_inner_origo(
  mut config: config::Config,
) -> Result<TlsProof, errors::ClientErrors> {
  let session_id = config.session_id();
  let root_store = default_root_store();

  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let origo_conn = tls_proxy2::OrigoConnection::new();
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn)),
    tls_client2::ServerName::try_from(config.target_host().as_str()).unwrap(),
  )
  .unwrap();

  let client_notary_config = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(crate::prover::default_root_store())
    .with_no_client_auth();

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
      .await
      .unwrap();

  let notary_tls_socket = notary_connector
    .connect(rustls::ServerName::try_from(config.notary_host.as_str()).unwrap(), notary_socket)
    .await
    .unwrap();

  let (mut request_sender, connection) =
    hyper::client::conn::handshake(notary_tls_socket).await.unwrap();
  let connection_task = tokio::spawn(connection.without_shutdown());

  let request = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/origo?session_id={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      session_id.clone(),
    ))
    .method("GET")
    .header("Host", config.notary_host.clone())
    .header("Connection", "Upgrade")
    .header("Upgrade", "TCP")
    .body(hyper::Body::empty())
    .unwrap();

  let response = request_sender.send_request(request).await.unwrap();
  assert!(response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS);

  // Claim back the TLS socket after the HTTP to TCP upgrade is done
  let hyper::client::conn::Parts { io: notary_tls_socket, .. } =
    connection_task.await.unwrap().unwrap();

  let (mut client_tls_conn, tls_fut) =
    tls_client_async2::bind_client(notary_tls_socket.compat(), client);

  //   let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn);

  //   let client_tls_conn = TokioIo::new(client_tls_conn);
  //   let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) }; // TODO is this needed?

  // TODO: What do with tls_fut? what do with tls_receiver?
  let (tls_sender, tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await;
    // Triggered when the server shuts the connection.
    debug!("tls_sender.send({:?})", result);
    let _ = tls_sender.send(result);
  };
  tokio::spawn(handled_tls_fut);

  //   let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn);

  // use tokio::io::{AsyncReadExt, AsyncWriteExt};

  use tokio_util::compat::FuturesAsyncReadCompatExt;

  let (mut request_sender, connection) =
    hyper::client::conn::handshake(client_tls_conn.compat()).await.unwrap();
  // hyper1::client::conn::http1::handshake(client_tls_conn).await.unwrap();

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    debug!("connection_sender.send({:?})", result);
    let _ = connection_sender.send(result);
  };
  tokio::spawn(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()).await.unwrap();

  assert_eq!(response.status(), StatusCode::OK);

  let payload = response.into_body().collect().await.unwrap().to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server
  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner();
  client_socket.close().await.unwrap();

  todo!("return something");
}

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

// TODO default_root_store is duplicated in prover.rs because of
// tls_client::RootCertStore vs rustls::RootCertStore

/// Default root store using mozilla certs.
fn default_root_store() -> tls_client2::RootCertStore {
  let mut root_store = tls_client2::RootCertStore::empty();
  root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    tls_client2::OwnedTrustAnchor::from_subject_spki_name_constraints(
      ta.subject.as_ref(),
      ta.subject_public_key_info.as_ref(),
      ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
    )
  }));

  #[cfg(feature = "notary_ca_cert")]
  {
    debug!("notary_ca_cert feature enabled");
    let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
    let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
    assert_eq!(added, 1); // TODO there is probably a better way
  }

  root_store
}

// use core::slice;
// use std::{
//   pin::Pin,
//   task::{Context, Poll},
// };

// use pin_project_lite::pin_project;

// pin_project! {
//     #[derive(Debug)]
//     pub(crate) struct FuturesIo<T> {
//         #[pin]
//         inner: T,
//     }
// }

// impl<T> FuturesIo<T> {
//   /// Create a new `FuturesIo` wrapping the given I/O object.
//   ///
//   /// # Safety
//   ///
//   /// This wrapper is only safe to use if the inner I/O object does not under
//   /// any circumstance read from the buffer passed to `poll_read` in the
//   /// `futures::AsyncRead` implementation.
//   pub(crate) unsafe fn new(inner: T) -> Self { Self { inner } }

//   pub(crate) fn into_inner(self) -> T { self.inner }
// }

// // hyper::rt::io::Read
// impl<T> tokio::io::AsyncWrite for FuturesIo<T>
// // impl<T> hyper::rt::io::Write for FuturesIo<T>
// where T: futures::AsyncWrite + Unpin
// {
//   fn poll_write(
//     self: Pin<&mut Self>,
//     cx: &mut Context<'_>,
//     buf: &[u8],
//   ) -> Poll<Result<usize, std::io::Error>> {
//     self.project().inner.poll_write(cx, buf)
//   }

//   fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
//     self.project().inner.poll_flush(cx)
//   }

//   fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
//     self.project().inner.poll_close(cx)
//   }

//   fn poll_write_vectored(
//     self: Pin<&mut Self>,
//     cx: &mut Context<'_>,
//     bufs: &[std::io::IoSlice<'_>],
//   ) -> Poll<Result<usize, std::io::Error>> {
//     self.project().inner.poll_write_vectored(cx, bufs)
//   }
// }

// // Adapted from https://github.com/hyperium/hyper-util/blob/99b77a5a6f75f24bc0bcb4ca74b5f26a07b19c80/src/rt/tokio.rs
// impl<T> tokio::io::AsyncRead for FuturesIo<T>
// // impl<T> hyper::rt::Read for FuturesIo<T>
// where T: futures::AsyncRead + Unpin
// {
//   fn poll_read(
//     self: Pin<&mut Self>,
//     cx: &mut Context<'_>,
//     mut buf: hyper::rt::ReadBufCursor<'_>,
//   ) -> Poll<Result<(), std::io::Error>> {
//     // Safety: buf_slice should only be written to, so it's safe to convert `&mut
//     // [MaybeUninit<u8>]` to `&mut [u8]`.
//     let buf_slice = unsafe {
//       slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
//     };

//     let n = match futures::AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
//       Poll::Ready(Ok(n)) => n,
//       other => return other.map_ok(|_| ()),
//     };

//     unsafe {
//       buf.advance(n);
//     }
//     Poll::Ready(Ok(()))
//   }
// }
