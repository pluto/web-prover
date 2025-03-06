use std::sync::Arc;

use http_body_util::Full;
use hyper::{body::Bytes, Request};
use rustls::ClientConfig;
use tlsn_prover::{state::Closed, Prover, ProverConfig};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::{config::Config, tlsn::send_request};

// uses websocket to connect to notary
// TODO decide if that means it's using the websocket proxy as well?
pub async fn setup_websocket_connection(
  _config: &mut Config,
  _prover_config: ProverConfig,
) -> Prover<Closed> {
  todo!("client type websocket not implemented for native target");
}

// uses raw TCP socket to connect to notary
pub async fn setup_tcp_connection(
  config: &mut Config,
  prover_config: ProverConfig,
) -> Prover<Closed> {
  let session_id = config.set_session_id();
  let root_store =
    crate::tls::rustls_default_root_store(config.notary_ca_cert.clone().map(|c| vec![c]));

  let client_notary_config =
    ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

  let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port)).await.unwrap();

  let notary_tls_socket = notary_connector
    .connect(
      rustls::pki_types::ServerName::try_from(config.notary_host.clone()).unwrap(),
      notary_socket,
    )
    .await
    .unwrap();

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await.unwrap();
  let connection_task = tokio::spawn(connection.without_shutdown());

  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/{}?session_id={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      config.mode,
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
    tokio::net::TcpStream::connect((config.target_host().unwrap(), config.target_port().unwrap()))
      .await
      .unwrap();

  let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

  let prover_task = tokio::spawn(prover_fut);

  let mpc_tls_connection = hyper_util::rt::TokioIo::new(mpc_tls_connection.compat());

  let (request_sender, connection) =
    hyper::client::conn::http1::handshake(mpc_tls_connection).await.unwrap();

  let connection_task = tokio::spawn(connection.without_shutdown());

  send_request(request_sender, config.to_request().unwrap()).await;

  let client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

  use futures::AsyncWriteExt;
  client_socket.compat().close().await.unwrap();

  prover_task.await.unwrap().unwrap()
}
