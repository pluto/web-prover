use std::{
  ops::Deref,
  sync::{Arc, Mutex},
};

#[cfg(feature = "tee-dummy-token-verifier")]
use caratls_ekm_client::DummyTokenVerifier;
use caratls_ekm_client::TeeTlsConnector;
#[cfg(feature = "tee-google-confidential-space-token-verifier")]
use caratls_ekm_google_confidential_space_client::GoogleConfidentialSpaceTokenVerifier;
use futures::AsyncWriteExt;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use tls_client2::{origo::OrigoConnection, ClientConnection};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{
  config::{self, Config, NotaryMode},
  errors::ClientErrors,
  origo::OrigoSecrets,
};
use crate::tls_client_async2::TlsConnection;

// TODO: Can be refactored further with shared logic from origo_wasm32.rs

/// We want to be able to specify somewhere in here what cipher suite to use.
/// Perhaps the config object should have this information.
pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<tls_client2::origo::OrigoConnection, ClientErrors> {
  let root_store =
    crate::tls::tls_client2_default_root_store(config.notary_ca_cert.clone().map(|c| vec![c]));

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

  // TODO: do we actually need this feature flag?!
  let client_notary_config = if cfg!(feature = "unsafe_skip_cert_verification") {
    // if feature `unsafe_skip_cert_verification` is active, build a TLS client
    // which does not verify the certificate
    rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(crate::tls::unsafe_tls::SkipServerVerification::new())
      .with_no_client_auth()
  } else {
    rustls::ClientConfig::builder()
      .with_root_certificates(crate::tls::rustls_default_root_store(
        config.notary_ca_cert.clone().map(|c| vec![c]),
      ))
      .with_no_client_auth()
  };

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config.clone()));

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
  let origo_conn = if config.mode == NotaryMode::TEE {
    handle_tee_mode(config, notary_tls_socket, client, origo_conn).await?
  } else {
    handle_generic_mode(config, notary_tls_socket, client, origo_conn).await?
  };
  Ok(origo_conn)
}

async fn handle_generic_mode(
  config: Config,
  notary_tls_socket: TokioIo<TokioIo<TlsStream<TcpStream>>>,
  client: ClientConnection,
  origo_conn: Arc<Mutex<OrigoConnection>>,
) -> Result<OrigoConnection, ClientErrors> {
  let (client_tls_conn, _) =
    crate::tls_client_async2::bind_client(notary_tls_socket.compat(), client);

  client_handshake(&config, client_tls_conn).await?;

  let origo_conn = origo_conn.lock().unwrap().deref().clone();

  Ok(origo_conn)
}

async fn handle_tee_mode(
  config: Config,
  notary_tls_socket: TokioIo<TokioIo<TlsStream<TcpStream>>>,
  client: ClientConnection,
  origo_conn: Arc<Mutex<OrigoConnection>>,
) -> Result<OrigoConnection, ClientErrors> {
  // Either bind client to TEE TLS connection or plain TLS connection
  #[cfg(feature = "tee-google-confidential-space-token-verifier")]
  let token_verifier = GoogleConfidentialSpaceTokenVerifier::new("audience").await; // TODO pass in as function input

  #[cfg(feature = "tee-dummy-token-verifier")]
  let token_verifier = DummyTokenVerifier { expect_token: "dummy".to_string() };

  let tee_tls_connector = TeeTlsConnector::new(token_verifier, "example.com"); // TODO example.com
  let notary_tls_stream = tee_tls_connector.connect(notary_tls_socket).await?;
  let (client_tls_conn, client_tls_fut) =
    crate::tls_client_async2::bind_client(notary_tls_stream.compat(), client);

  // start client tls connection
  let tls_fut_task = tokio::spawn(client_tls_fut);

  client_handshake(&config, client_tls_conn).await?;

  let origo_conn = origo_conn.lock().unwrap().deref().clone();

  // wait for tls connection
  let (_, mut reunited_socket) = tls_fut_task.await?.unwrap();

  let manifest_bytes = config.proving.manifest.unwrap().to_wire_bytes();
  reunited_socket.write_all(&manifest_bytes).await?;

  let origo_secret_bytes = OrigoSecrets::from_origo_conn(&origo_conn).to_wire_bytes();
  reunited_socket.write_all(&origo_secret_bytes).await?;

  // TODO: read web proof (a bit awkward but proxy will have to return the it)
  Ok(origo_conn)
}

/// Perform an HTTP handshake on client TLS connection and sends request
async fn client_handshake(config: &Config, client_tls_conn: TlsConnection) -> Result<(), ClientErrors> {
  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());
  let (mut request_sender, connection) =
      hyper::client::conn::http1::handshake(client_tls_conn).await?;
  let connection_task = tokio::spawn(connection.without_shutdown());
  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let payload = response.into_body().collect().await?.to_bytes();
  debug!("Response: {:?}", payload);

  let hyper::client::conn::http1::Parts { io: _client_tls_conn, .. } = connection_task.await??;
  Ok(())
}
