use std::{ops::Deref, sync::Arc};

#[cfg(feature = "tee-dummy-token-verifier")]
use caratls_ekm_client::DummyTokenVerifier;
use caratls_ekm_client::TeeTlsConnector;
#[cfg(feature = "tee-google-confidential-space-token-verifier")]
use caratls_ekm_google_confidential_space_client::GoogleConfidentialSpaceTokenVerifier;
use futures::{
  channel::oneshot, AsyncReadExt, AsyncWriteExt as FuturesWriteExt, SinkExt, StreamExt,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::{
  codec::{Framed, LengthDelimitedCodec},
  compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
};
use tracing::debug;

use crate::{
  config::{self, Config, NotaryMode},
  errors::ClientErrors,
  TeeProof,
};

// TODO: Can be refactored further with shared logic from origo_wasm32.rs

/// We want to be able to specify somewhere in here what cipher suite to use.
/// Perhaps the config object should have this information.
pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<TeeProof, ClientErrors> {
  handle_tee_mode(config, session_id).await
}

async fn handle_tee_mode(
  config: config::Config,
  session_id: String,
) -> Result<TeeProof, ClientErrors> {
  let root_store =
    crate::tls::tls_client2_default_root_store(config.notary_ca_cert.clone().map(|c| vec![c]));

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

  let client_config =
    rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

  let client = rustls::ClientConnection::new(
    Arc::new(client_config),
    rustls::ServerName::try_from(config.target_host()?.as_str()).unwrap(),
  )?;

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
      "tee",
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

  #[cfg(feature = "tee-google-confidential-space-token-verifier")]
  let token_verifier = GoogleConfidentialSpaceTokenVerifier::new("audience").await; // TODO pass in as function input

  #[cfg(feature = "tee-dummy-token-verifier")]
  let token_verifier = DummyTokenVerifier { expect_token: "dummy".to_string() };

  let tee_tls_connector = TeeTlsConnector::new(token_verifier, "example.com"); // TODO example.com
  let tee_tls_stream = tee_tls_connector.connect(notary_tls_socket).await?;

  // todo; I need to find a way to do this with rustls, so we are not using tls_client_async2. 
  // perhapse we don't even need to manually do this
  // Update ## 09:11 2025-03-06: I there is logic in tlsn we can use for the time being.
  // let (client_tls_conn, client_tls_fut) =
  //   tls_client_async::bind_client(tee_tls_stream.compat(), client);


  // let client_tls_conn = rustls::ConnectionCommon::from(client);

  // start client tls connection
  let tls_fut_task = tokio::spawn(client_tls_fut);

  // client_handshake(&config, client_tls_conn).await?;

  // // wait for tls connection
  // let (_, mut reunited_socket) = tls_fut_task.await?.unwrap();


  let mut buffer = [0u8; 1];
  loop {
    tee_tls_stream.read_exact(&mut buffer).await?;
    if buffer.len() == 1 && buffer[0] == 0xAA {
      debug!("Magic byte 0xAA received, server is ready");
      break;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    debug!("Waiting for magic byte, received: {:?}", buffer[0]);
  }

  // let mut framed_reunited_socket =
  //   Framed::new(tee_tls_stream.compat(), LengthDelimitedCodec::new());

  let manifest_bytes: Vec<u8> = config.proving.manifest.unwrap().try_into()?;

  tee_tls_stream.write_all_plaintext(&manifest_bytes).await?;
  tee_tls_stream.flush().await?;

  let tee_thing = tee_tls_stream.read().unwrap();

  let tee_proof = TeeProof::try_from(tee_thing.as_ref())?;
  debug!("TeeProof: {:?}", tee_proof);

  Ok(tee_proof)
}

