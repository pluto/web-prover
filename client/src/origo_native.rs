use std::{ops::Deref, sync::Arc};

use caratls_ekm_client::TeeTlsConnector;
use caratls_ekm_google_confidential_space_client::GoogleConfidentialSpaceTokenVerifier;
use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use tls_client2::origo::OrigoConnection;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{
  config::{self, NotaryMode},
  errors::ClientErrors,
};

/// We want to be able to specify somewhere in here what cipher suite to use.
/// Perhaps the config object should have this information.
pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<tls_client2::origo::OrigoConnection, ClientErrors> {
  let root_store = crate::tls::tls_client2_default_root_store();

  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let origo_conn = Arc::new(std::sync::Mutex::new(OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
    tls_client2::ServerName::try_from(config.target_host()?.as_str()).unwrap(),
  )?;

  let client_notary_config = if cfg!(feature = "unsafe_skip_cert_verification") {
    // if feature `unsafe_skip_cert_verification` is active, build a TLS client
    // which does not verify the certificate
    rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(crate::tls::unsafe_tls::SkipServerVerification::new())
      .with_no_client_auth()
  } else {
    rustls::ClientConfig::builder()
      .with_root_certificates(crate::tls::rustls_default_root_store())
      .with_no_client_auth()
  };

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port)).await?;

  let notary_tls_socket = notary_connector
    .connect(rustls::pki_types::ServerName::try_from(config.notary_host.clone())?, notary_socket)
    .await?;

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);
  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await?;
  let connection_task = tokio::spawn(connection.without_shutdown());

  // TODO build sanitized query
  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/{}?session_id={}&target_host={}&target_port={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      if config.mode == NotaryMode::TEE { "tee" } else { "origo" },
      session_id.clone(),
      config.target_host()?,
      config.target_port()?,
    ))
    .method("GET")
    .header("Host", config.notary_host.clone())
    .header("Connection", "Upgrade")
    .header("Upgrade", "TCP")
    .body(http_body_util::Full::default())?;

  let response = request_sender.send_request(request).await?;
  assert_eq!(response.status(), hyper::StatusCode::SWITCHING_PROTOCOLS);

  // Claim back the TLS socket after the HTTP to TCP upgrade is done
  let hyper::client::conn::http1::Parts { io: notary_tls_socket, .. } = connection_task.await??;

  // TODO notary_tls_socket needs to implement futures::AsyncRead/Write, find a better wrapper here
  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  // Either bind client to TEE TLS connection or plain TLS connection
  let (client_tls_conn, tls_fut) = if config.mode == NotaryMode::TEE {
    let token_verifier = GoogleConfidentialSpaceTokenVerifier::new("audience").await; // TODO pass in as function input
    let tee_tls_connector = TeeTlsConnector::new(token_verifier, "example.com"); // TODO example.com
    let tee_tls_stream = tee_tls_connector.connect(notary_tls_socket).await?;
    crate::tls_client_async2::bind_client(tee_tls_stream.compat(), client)
  } else {
    crate::tls_client_async2::bind_client(notary_tls_socket.compat(), client)
  };

  // TODO: What do with tls_fut? what do with tls_receiver?
  let (tls_sender, _tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await.unwrap();
    let _ = tls_sender.send(result);
  };
  tokio::spawn(handled_tls_fut);

  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await?;

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  tokio::spawn(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let payload = response.into_body().collect().await?.to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server
  // TODO this closes the TLS Connection, do we want to maybe close the TCP stream instead?
  let mut client_socket = connection_receiver.await??.io.into_inner().into_inner();
  client_socket.close().await?;

  let origo_conn = origo_conn.lock().unwrap().deref().clone();
  Ok(origo_conn)
}
