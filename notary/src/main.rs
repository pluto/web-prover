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
  collections::HashMap,
  fs, io,
  sync::{Arc, Mutex},
};

use axum::{
  extract::Request,
  http::StatusCode,
  middleware::from_extractor_with_state,
  response::{Html, IntoResponse},
  routing::{get, post},
  Json, Router,
};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{debug, error, info};

mod axum_websocket;
mod tcp;
mod tlsn;
mod websockets;

#[tokio::main]
async fn main() {
  let subscriber = tracing_subscriber::FmtSubscriber::new();
  tracing::subscriber::set_global_default(subscriber).unwrap();

  let certs = load_certs("./fixture/certs/server-cert.pem").unwrap(); // TODO make CLI or ENV var
  let key = load_private_key("./fixture/certs/server-key.pem").unwrap(); // TODO make CLI or ENV var
  let addr = "0.0.0.0:7443"; // TODO make env var?

  let mut listener = TcpListener::bind(addr).await.unwrap();
  info!("Listening on https://{}", addr);

  let mut server_config =
    ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap();
  server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
  let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
  let protocol = Arc::new(http1::Builder::new());

  let router = Router::new()
    // .route_layer(from_extractor_with_state::<tlsn::NotaryGlobals>(notary_globals.clone()))
    .route("/health", get(|| async move { (StatusCode::OK, "Ok").into_response() }))
    .route("/v1/tlsnotary", get(tlsn::notarize))
    .layer(CorsLayer::permissive());
  // .route("/v1/tlsnotary/proxy", post(todo!("websocket proxy")))
  // .route("/v1/origo", post(todo!("call into origo")));

  // .route("/v1/tlsnotary/session", post(tlsn::initialize).with_state(notary_globals));

  use futures_util::future::poll_fn;

  loop {
    // let tcp_stream = match poll_fn(|cx| std::pin::Pin::new(&mut listener).poll_accept(cx)).await
    // {   Ok((stream, _)) => stream,
    //   Err(_) => {
    //     error!("error!");
    //     continue;
    //   },
    // };

    let (tcp_stream, _) = listener.accept().await.unwrap();
    let tls_acceptor = tls_acceptor.clone();
    let tower_service = router.clone();
    let protocol = protocol.clone();

    tokio::spawn(async move {
      // match tls_acceptor.accept(tcp_stream).await {
      //   Ok(stream) => {
      //     info!("Accepted prover's TLS-secured TCP connection");
      //     // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
      //     let io = TokioIo::new(stream);
      //     let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
      //       info!("tower_service.call");
      //       tower_service.clone().call(request)
      //     });
      //     // Serve different requests using the same hyper protocol and axum router
      //     protocol
      //                       .serve_connection(io, hyper_service)
      //                       // use with_upgrades to upgrade connection to websocket for websocket
      // clients                       // and to extract tcp connection for tcp clients
      //                       .with_upgrades()
      //                       .await.unwrap();
      //   },
      //   Err(err) => {
      //     error!("{}", err.to_string());
      //   },
      // }
      match tls_acceptor.accept(tcp_stream).await {
        Ok(tls_stream) => {
          let io = TokioIo::new(tls_stream);
          let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
            tower_service.clone().call(request)
          });
          // TODO should we check returned Result here?
          let _ = protocol.serve_connection(io, hyper_service).with_upgrades().await;
        },
        Err(err) => {
          error!("{err:#}"); // TODO format this better
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
