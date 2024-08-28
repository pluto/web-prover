use std::sync::Arc;

use http_body_util::Full;
use hyper::{body::Bytes, Request};
// use futures::AsyncWriteExt;
// use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use tlsn_prover::tls::{state::Closed, Prover, ProverConfig};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug; // needed for notary_ca_cert feature below

use crate::{config::Config, send_request};

// uses websocket to connect to notary
// TODO decide if that means it's using the websocket proxy as well?
pub async fn setup_websocket_connection(
  _config: &mut Config,
  _prover_config: ProverConfig,
) -> Prover<Closed> {
  todo!("client type websocket not implemented for non-wasm target");
}

// uses raw TCP socket to connect to notary
pub async fn setup_tcp_connection(
  config: &mut Config,
  prover_config: ProverConfig,
) -> Prover<Closed> {
  let session_id = config.session_id();
  let root_store = default_root_store();

  let client_notary_config = ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
      .await
      .unwrap();

  let notary_tls_socket = notary_connector
    .connect(rustls::ServerName::try_from(config.notary_host.as_str()).unwrap(), notary_socket)
    .await
    .unwrap();

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await.unwrap();
  let connection_task = tokio::spawn(connection.without_shutdown());

  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/tlsnotary?session_id={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      session_id.clone(),
    ))
    .method("GET")
    .header("Host", config.notary_host.clone())
    .header("Connection", "Upgrade")
    .header("Upgrade", "TCP")
    .body(http_body_util::Full::default())
    .unwrap();

  let response = request_sender.send_request(request).await.unwrap();
  assert!(response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS);

  // Claim back the TLS socket after the HTTP to TCP upgrade is done
  let hyper::client::conn::http1::Parts { io: notary_tls_socket, .. } =
    connection_task.await.unwrap().unwrap();

  // TODO notary_tls_socket needs to implement futures::AsyncRead/Write, find a better wrapper here
  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let prover = Prover::new(prover_config).setup(notary_tls_socket.compat()).await.unwrap();

  let client_socket =
    tokio::net::TcpStream::connect((config.target_host(), config.target_port())).await.unwrap();

  let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

  let prover_task = tokio::spawn(prover_fut);

  let mpc_tls_connection = hyper_util::rt::TokioIo::new(mpc_tls_connection.compat());

  let (request_sender, connection) =
    hyper::client::conn::http1::handshake(mpc_tls_connection).await.unwrap();

  let connection_task = tokio::spawn(connection.without_shutdown());

  send_request(request_sender, config.to_request()).await;

  let client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

  use futures::AsyncWriteExt;
  client_socket.compat().close().await.unwrap();

  prover_task.await.unwrap().unwrap()
}

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

// TODO default_root_store() duplicates lib.rs::default_root_store() but returns
// rustls::RootCertStore instead of tls_client::RootCertStore. Can we make the ClientConfig
// above accept the tls_client version or can we somehow convert types? The underlying
// implementation is the same.

/// Default root store using mozilla certs.
pub fn default_root_store() -> rustls::RootCertStore {
  let mut root_store = rustls::RootCertStore::empty();
  root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
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
