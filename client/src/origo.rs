use std::sync::Arc;

use tlsn_core::proof::TlsProof;

use crate::{config, errors};

// use tls_client::{ClientConnection, RustCryptoBackend, RustCryptoBackend13, ServerName};
// use tls_client_async::bind_client;

pub async fn prover_inner_origo(
  mut config: config::Config,
) -> Result<TlsProof, errors::ClientErrors> {
  let session_id = config.session_id();
  let root_store = crate::default_root_store();

  let config = tls_client::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  //   let origo_conn = OrigoConnection::new();
  let client = tls_client::ClientConnection::new(
    Arc::new(config),
    Box::new(tls_client::RustCryptoBackend13::new(origo_conn)),
    tls_client::ServerName::try_from(target_host).unwrap(),
  )
  .unwrap();
  let (mut client_tls_conn, tls_fut) = tls_client_async::bind_client(ws_stream.into_io(), client);

  //   let client_notary_config = rustls::ClientConfig::builder()
  //     .with_safe_defaults()
  //     .with_root_certificates(root_store)
  //     .with_no_client_auth();

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
      "https://{}:{}/v1/tlsnotary?session_id={}",
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

  // notary_tls_socket.compat()

  // bind_client

  todo!("origo mode");
}
