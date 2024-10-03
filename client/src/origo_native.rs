use std::sync::Arc;

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use tls_proxy2::WitnessData;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{config, errors, origo::SignBody, Proof};

pub async fn proxy_and_sign(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let (sb, witness) = proxy(config.clone(), session_id.clone()).await;
  crate::origo::sign(config.clone(), session_id.clone(), sb, witness).await
}

async fn proxy(config: config::Config, session_id: String) -> (SignBody, WitnessData) {
  println!("proxy:1");
  let root_store = crate::tls::tls_client2_default_root_store();

  println!("proxy:2");
  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  println!("proxy:3");
  let origo_conn = Arc::new(std::sync::Mutex::new(tls_proxy2::OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
    tls_client2::ServerName::try_from(config.target_host().as_str()).unwrap(),
  )
  .unwrap();
  println!("proxy:4");

  let client_notary_config = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(crate::tls::rustls_default_root_store())
    .with_no_client_auth();
  println!("proxy:5");

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));
  println!("proxy:6");

  // let notary_socket =
  //   tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
  //     .await
  //     .unwrap();

  // #[cfg(feature = "ios_app_clip")]
  use nw_connection;
  let notary_socket = nw_connection::NWConnection::connect(&config.notary_host.clone(), config.notary_port.clone());
  println!("proxy:7");

  let notary_tls_socket = notary_connector
    .connect(rustls::ServerName::try_from(config.notary_host.as_str()).unwrap(), notary_socket)
    .await
    .unwrap();
  println!("proxy:8");

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);
  println!("proxy:9");

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await.unwrap();
  println!("proxy:10");
  let connection_task = tokio::spawn(connection.without_shutdown());
  println!("proxy:11");

  // TODO build sanitized query
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
  println!("proxy:12");

  // Claim back the TLS socket after the HTTP to TCP upgrade is done
  let hyper::client::conn::http1::Parts { io: notary_tls_socket, .. } =
    connection_task.await.unwrap().unwrap();
  println!("proxy:13");

  // TODO notary_tls_socket needs to implement futures::AsyncRead/Write, find a better wrapper here
  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);
  println!("proxy:14");

  let (client_tls_conn, tls_fut) =
    tls_client_async2::bind_client(notary_tls_socket.compat(), client);
  println!("proxy:15");

  // TODO: What do with tls_fut? what do with tls_receiver?
  let (tls_sender, tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await;
    // Triggered when the server shuts the connection.
    // debug!("tls_sender.send({:?})", result);
    let _ = tls_sender.send(result);
  };
  tokio::spawn(handled_tls_fut);
  println!("proxy:16");

  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());
  println!("proxy:17");

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await.unwrap();
  println!("proxy:18");

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    // debug!("connection_sender.send({:?})", result);
    let _ = connection_sender.send(result);
  };
  println!("proxy:19");
  tokio::spawn(handled_connection_fut);
  println!("proxy:20");

  let response = request_sender.send_request(config.to_request()).await.unwrap();
  println!("proxy:21");

  assert_eq!(response.status(), StatusCode::OK);
  println!("proxy:22");

  let payload = response.into_body().collect().await.unwrap().to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server
  // TODO this closes the TLS Connection, do we want to maybe close the TCP stream instead?
  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner().into_inner();
  client_socket.close().await.unwrap();
  println!("proxy:23");

  let server_aes_iv =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_key").unwrap().clone();

  let witness = origo_conn.lock().unwrap().to_witness_data();
  let sb = SignBody {
    hs_server_aes_iv:  hex::encode(server_aes_iv.to_vec()),
    hs_server_aes_key: hex::encode(server_aes_key.to_vec()),
  };

  (sb, witness)
}
