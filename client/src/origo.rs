use std::sync::Arc;

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use serde::Serialize;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{config, errors, OrigoProof, Proof};

pub async fn prover_inner_origo(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();

  let (server_aes_key, server_aes_iv) =
    prover_inner_proxy(config.clone(), session_id.clone()).await;

  // return Ok(Proof::Origo(OrigoProof {}));
  prover_inner_sign(config.clone(), session_id.clone(), server_aes_key, server_aes_iv).await
}

async fn prover_inner_proxy(config: config::Config, session_id: String) -> (Vec<u8>, Vec<u8>) {
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

  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await.unwrap();

  // let (connection_sender, connection_receiver) = oneshot::channel();
  // let connection_fut = connection.without_shutdown();
  // let handled_connection_fut = async {
  //   let result = connection_fut.await;
  //   // debug!("connection_sender.send({:?})", result);
  //   let _ = connection_sender.send(result);
  // };
  // tokio::spawn(handled_connection_fut);
  tokio::spawn(connection);

  let response = request_sender.send_request(config.to_request()).await.unwrap();

  assert_eq!(response.status(), StatusCode::OK);

  let payload = response.into_body().collect().await.unwrap().to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server

  // let mut client_socket =
  // connection_receiver.await.unwrap().unwrap().io.into_inner().into_inner(); client_socket.
  // close().await.unwrap();

  let server_aes_iv =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_key").unwrap().clone();

  (server_aes_key, server_aes_iv)
}

async fn prover_inner_sign(
  config: config::Config,
  session_id: String,
  server_aes_key: Vec<u8>,
  server_aes_iv: Vec<u8>,
) -> Result<Proof, errors::ClientErrors> {
  // call sign endpoint
  debug!("call sign endpoint");

  // let client_notary_config = rustls::ClientConfig::builder()
  //   .with_safe_defaults()
  //   .with_root_certificates(crate::prover::default_root_store())
  //   .with_no_client_auth();

  // let notary_connector =
  //   tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  // let notary_socket =
  //   tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
  //     .await
  //     .unwrap();

  // debug!("1");

  // let notary_tls_socket = notary_connector
  //   .connect(rustls::ServerName::try_from(config.notary_host.as_str()).unwrap(), notary_socket)
  //   .await
  //   .unwrap();

  // debug!("2");
  // let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  // debug!("3");
  // let (mut request_sender, connection) =
  //   hyper::client::conn::http1::handshake(notary_tls_socket).await.unwrap();
  // let _ = tokio::spawn(connection);

  debug!("4");
  #[derive(Serialize)]
  struct SignBody {
    server_aes_iv:  String,
    server_aes_key: String,
  }

  debug!("5");

  let sb = SignBody {
    server_aes_iv:  String::from_utf8(server_aes_iv.to_vec()).unwrap(),
    server_aes_key: String::from_utf8(server_aes_key.to_vec()).unwrap(),
  };

  debug!("7");

  // let request: Request<Full<Bytes>> = hyper::Request::builder()
  //   .uri(format!(
  //     "https://{}:{}/v1/origo/sign?session_id={}",
  //     config.notary_host.clone(),
  //     config.notary_port.clone(),
  //     session_id.clone(),
  //   ))
  //   .method("POST")
  //   .header("Host", config.notary_host.clone())
  //   .header("Content-type", "application/json")
  //   .header("Connection", "close")
  //   .body(http_body_util::Full::from(serde_json::to_string(&sb).unwrap()))
  //   .unwrap();

  debug!("8");

  let url = format!(
    "https://{}:{}/v1/origo/sign?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let foo: Vec<u8> = Default::default();

  #[cfg(feature = "notary_ca_cert")]
  let foo = NOTARY_CA_CERT.to_vec();

  let cert = reqwest::tls::Certificate::from_der(&foo).unwrap();

  let client = reqwest::ClientBuilder::new().add_root_certificate(cert).build().unwrap();

  let response = client.post(url).json(&sb).send().await.unwrap();

  // let response = request_sender.send_request(request).await.unwrap();
  assert!(response.status() == hyper::StatusCode::OK);

  debug!("9");
  println!("\n{}\n\n", String::from_utf8(response.bytes().await.unwrap().to_vec()).unwrap());

  // let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
  // println!("\n{}\n\n", String::from_utf8(body_bytes.to_vec()).unwrap());

  debug!("10");

  Ok(Proof::Origo(OrigoProof {})) // TODO
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
