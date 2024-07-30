use std::{fs, io, sync::Arc};

use axum::{extract::Request, http::StatusCode, response::IntoResponse, routing::get, Router};
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use rustls_acme::{caches::DirCache, AcmeConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{error, info};

mod axum_websocket;
mod config;
mod tcp;
mod tlsn;
mod websocket_proxy;

#[derive(Debug, Clone)]
struct SharedState {
  notary_signing_key: SigningKey,
  tlsn_max_sent_data: usize,
  tlsn_max_recv_data: usize,
}

#[tokio::main]
async fn main() {
  let c = config::read_config();

  let subscriber = tracing_subscriber::FmtSubscriber::new();
  tracing::subscriber::set_global_default(subscriber).unwrap();

  let certs = load_certs(&c.server_cert).unwrap();
  let key = load_private_key(&c.server_key).unwrap();

  let listener = TcpListener::bind(&c.listen).await.unwrap();
  let tcp_incoming = TcpListenerStream::new(listener);
  info!("Listening on https://{}", &c.listen);

  let mut server_config =
    ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap();
  server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
  // let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
  let protocol = Arc::new(http1::Builder::new());

  let shared_state = Arc::new(SharedState {
    notary_signing_key: load_notary_signing_key(&c.notary_signing_key),
    tlsn_max_sent_data: c.tlsn_max_sent_data,
    tlsn_max_recv_data: c.tlsn_max_recv_data,
  });

  let router = Router::new()
    .route("/health", get(|| async move { (StatusCode::OK, "Ok").into_response() }))
    .route("/v1/tlsnotary", get(tlsn::notarize))
    .route("/v1/tlsnotary/websocket_proxy", get(websocket_proxy::proxy))
    .layer(CorsLayer::permissive())
    .with_state(shared_state);
  // .route("/v1/origo", post(todo!("call into origo")));

  let mut tls_incoming = AcmeConfig::new(["example.com"])
    .contact_push("mailto:admin@example.com")
    .cache(DirCache::new("./rustls_acme_cache"))
    .tokio_incoming(tcp_incoming, vec![b"http/1.1".to_vec()]);

  while let Some(tls) = tls_incoming.next().await {
    let tls = tls.unwrap(); // TODO

    let tower_service = router.clone();
    let protocol = protocol.clone();

    tokio::spawn(async move {
      let io = TokioIo::new(tls);
      let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
      });
      // TODO should we check returned Result here?
      let _ = protocol.serve_connection(io, hyper_service).with_upgrades().await;
    });
  }

  // loop {
  //   let (tcp_stream, _) = listener.accept().await.unwrap();
  //   let tls_acceptor = tls_acceptor.clone();
  //   let tower_service = router.clone();
  //   let protocol = protocol.clone();

  //   tokio::spawn(async move {
  //     match tls_incoming.next().await {
  //       Ok(tls_stream) => {
  //         let io = TokioIo::new(tls_stream);
  //         let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
  //           tower_service.clone().call(request)
  //         });
  //         // TODO should we check returned Result here?
  //         let _ = protocol.serve_connection(io, hyper_service).with_upgrades().await;
  //       },
  //       Err(err) => {
  //         error!("{err:#}"); // TODO format this better
  //       },
  //     }

  //     // match tls_acceptor.accept(tcp_stream).await {
  //     //   Ok(tls_stream) => {
  //     //     let io = TokioIo::new(tls_stream);
  //     //     let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
  //     //       tower_service.clone().call(request)
  //     //     });
  //     //     // TODO should we check returned Result here?
  //     //     let _ = protocol.serve_connection(io, hyper_service).with_upgrades().await;
  //     //   },
  //     //   Err(err) => {
  //     //     error!("{err:#}"); // TODO format this better
  //     //   },
  //     // }
  //   });
  // }
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

pub fn load_notary_signing_key(private_key_pem_path: &str) -> SigningKey {
  SigningKey::read_pkcs8_pem_file(private_key_pem_path).unwrap()
}
