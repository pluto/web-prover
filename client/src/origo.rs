use std::sync::Arc;

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::Full;
use hyper::{body::Bytes, Request, StatusCode};
use serde::Serialize;
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

  let origo_conn = Arc::new(std::sync::Mutex::new(tls_proxy2::OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
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

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await.unwrap();
  let connection_task = tokio::spawn(connection.without_shutdown());

  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/origo?session_id={}&target_host={}&target_port={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      session_id.clone(),
      config.target_host(),
      config.target_port(),
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

  let (client_tls_conn, tls_fut) =
    tls_client_async2::bind_client(notary_tls_socket.compat(), client);

  // TODO: What do with tls_fut? what do with tls_receiver?
  let (tls_sender, tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await;
    // Triggered when the server shuts the connection.
    // debug!("tls_sender.send({:?})", result);
    let _ = tls_sender.send(result);
  };
  tokio::spawn(handled_tls_fut);

  use tokio_util::compat::FuturesAsyncReadCompatExt;

  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await.unwrap();

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    // debug!("connection_sender.send({:?})", result);
    let _ = connection_sender.send(result);
  };
  tokio::spawn(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()).await.unwrap();

  assert_eq!(response.status(), StatusCode::OK);

  use http_body_util::BodyExt;

  let payload = response.into_body().collect().await.unwrap().to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server
  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner().into_inner();
  client_socket.close().await.unwrap();

  // call sign endpoint

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
  let _ = tokio::spawn(connection);

  #[derive(Serialize)]
  struct SignBody {
    server_aes_iv:  String,
    server_aes_key: String,
  }

  let server_aes_iv =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_key").unwrap().clone();

  let sb = SignBody {
    server_aes_iv:  String::from_utf8(server_aes_iv.to_vec()).unwrap(),
    server_aes_key: String::from_utf8(server_aes_key.to_vec()).unwrap(),
  };

  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/origo/sign?session_id={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      session_id.clone(),
    ))
    .method("POST")
    .header("Host", config.notary_host.clone())
    .header("Content-type", "application/json")
    .body(http_body_util::Full::from(serde_json::to_string(&sb).unwrap()))
    .unwrap();

  let response = request_sender.send_request(request).await.unwrap();
  assert!(response.status() == hyper::StatusCode::OK);

  let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
  println!("\n{}\n\n", String::from_utf8(body_bytes.to_vec()).unwrap());

  todo!("return origo TLS proof");
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
