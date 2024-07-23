// TODO combined binary which offers the following endpoints:
//
// GET /health
//
// GET /v1/origo/proxy (supports TCP or websocket connection) - focus on this one later, requires
// Thor's work.
//
// POST /v1/tlsnotary/session -> https://github.com/tlsnotary/tlsn/blob/3554db83e17b2e5fc98293b397a2907b7f023496/notary/server/src/service.rs#L114 (pub async fn initialize)
// GET /v1/tlsnotary/notarize (supports TCP or websocket connection)
//    a few possible entrypoints:
//       - https://github.com/tlsnotary/tlsn/blob/3554db83e17b2e5fc98293b397a2907b7f023496/notary/server/src/service.rs#L71
//         (pub async fn upgrade_protocol)
//       - https://github.com/tlsnotary/tlsn/blob/3554db83e17b2e5fc98293b397a2907b7f023496/notary/server/src/service.rs#L173
//         (pub async fn notary_service)
//
// GET /v1/tlsnotary/proxy (mostly this: https://github.com/pluto/web-prover/blob/30ba86a2d5887c2f7c4e2d7bb50b378998ccd297/bin/proxy.rs#L219)

use std::{
  fs, io,
  net::{IpAddr, SocketAddr},
  pin::Pin,
  sync::Arc,
};

use axum::{
  extract::Request,
  http::StatusCode,
  middleware::from_extractor_with_state,
  response::{Html, IntoResponse},
  routing::{get, post},
  Json, Router,
};
use futures_util::future::poll_fn;
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
// use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{debug, info};

#[tokio::main]
async fn main() {
  let certs = load_certs("./fixture/certs/server-cert.pem").unwrap();
  let key = load_private_key("./fixture/certs/server-key.pem").unwrap();

  let mut server_config =
    ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap();

  // Set the http protocols we support
  server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
  let tls_config = Arc::new(server_config);
  let tls_acceptor = TlsAcceptor::from(tls_config);

  let notary_address = SocketAddr::new(IpAddr::V4("0.0.0.0".parse().unwrap()), 7074);
  let mut listener = TcpListener::bind(notary_address).await.unwrap();

  info!("Listening for TCP traffic at {}", notary_address);

  let protocol = Arc::new(http1::Builder::new());

  let router =
    Router::new().route("/health", get(|| async move { (StatusCode::OK, "Ok").into_response() }));

  loop {
    // Poll and await for any incoming connection, ensure that all operations inside are infallible
    // to prevent bringing down the server
    let stream = match poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
      Ok((stream, _)) => stream,
      Err(err) => {
        panic!("todo");
        // error!("{}", NotaryServerError::Connection(err.to_string()));
        // continue;
      },
    };
    debug!("Received a TCP connection");

    let tower_service = router.clone();
    let tls_acceptor = tls_acceptor.clone();
    let protocol = protocol.clone();

    tokio::spawn(async move {
      match tls_acceptor.accept(stream).await {
        Ok(stream) => {
          info!("Accepted prover's TLS-secured TCP connection");
          // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
          let io = TokioIo::new(stream);
          let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
            tower_service.clone().call(request)
          });
          // Serve different requests using the same hyper protocol and axum router
          let _ = protocol
                  .serve_connection(io, hyper_service)
                  // use with_upgrades to upgrade connection to websocket for websocket clients
                  // and to extract tcp connection for tcp clients
                  .with_upgrades()
                  .await;
        },
        Err(err) => {
          panic!("todo");
          // error!("{}", NotaryServerError::Connection(err.to_string()));
        },
      }
    });
  }
}

fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
  let certfile =
    fs::File::open(filename).map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
  let mut reader = io::BufReader::new(certfile);
  rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
  let keyfile =
    fs::File::open(filename).map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
  let mut reader = io::BufReader::new(keyfile);
  rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

fn error(err: String) -> io::Error { io::Error::new(io::ErrorKind::Other, err) }
