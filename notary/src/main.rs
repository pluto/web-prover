use std::{
  collections::HashMap,
  fs,
  io::{self},
  sync::{Arc, Mutex},
};

use axum::{
  extract::Request,
  http::StatusCode,
  response::IntoResponse,
  routing::{get, post},
  Router,
};
use errors::NotaryServerError;
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use proofs::program::manifest::Manifest;
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  ServerConfig,
};
use rustls_acme::{caches::DirCache, AcmeConfig};
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod axum_websocket;
mod circuits;
mod config;
mod errors;
mod origo;
mod tcp;
mod tee;
mod tls_parser;
mod tlsn;
mod websocket_proxy;

struct SharedState {
  notary_signing_key: SigningKey,
  origo_signing_key:  Secp256k1SigningKey,
  tlsn_max_sent_data: usize,
  tlsn_max_recv_data: usize,
  origo_sessions:     Arc<Mutex<HashMap<String, tls_parser::Transcript<tls_parser::Raw>>>>,
  verifier_sessions:  Arc<Mutex<HashMap<String, origo::VerifierInputs>>>,
  manifest:           Manifest,
}

/// Main entry point for the notary server application.
///
/// This function:
/// 1. Initializes logging with line numbers and environment-based log levels
/// 2. Loads configuration from environment/files
/// 3. Sets up a TLS-enabled HTTP server with either:
///    - Static certificates provided in config, or
///    - Automatic certificate management via ACME/Let's Encrypt
/// 4. Configures routes for notary and proxy services
///
/// # Returns
///
/// Returns `Ok(())` if the server starts and runs successfully, or a `NotaryServerError` if:
/// - Configuration loading fails
/// - TCP listener binding fails
/// - TLS setup fails (either static or ACME)
///
/// # Environment Variables
///
/// * `RUST_LOG` - Controls log level (e.g. "info", "debug")
/// * `GIT_HASH` - Git commit hash (set at build time)
///
/// # Errors
///
/// This function will return an error if:
/// - TCP binding fails
/// - Configuration is invalid
/// - TLS certificate setup fails
///
/// Server startup errors are returned immediately, while runtime errors are logged
/// but don't terminate the server.
#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
  tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer().with_line_number(true))
    .with(tracing_subscriber::EnvFilter::from_default_env()) // set via RUST_LOG=INFO etc
    .init();

  info!("GIT_HASH: {}", env!("GIT_HASH"));

  let _ = rustls::crypto::ring::default_provider().install_default();

  let c = config::read_config();
  let manifest = config::read_manifest()?;

  let listener = TcpListener::bind(&c.listen).await?;
  info!("Listening on https://{}", &c.listen);

  let shared_state = Arc::new(SharedState {
    notary_signing_key: load_notary_signing_key(&c.notary_signing_key),
    origo_signing_key: load_origo_signing_key(&c.origo_signing_key),
    tlsn_max_sent_data: c.tlsn_max_sent_data,
    tlsn_max_recv_data: c.tlsn_max_recv_data,
    origo_sessions: Default::default(),
    verifier_sessions: Default::default(),
    // TODO: This is obviously not sufficient, we need richer logic
    // for informing the notary of a valid manifest.
    manifest,
  });

  let router = Router::new()
    .route("/health", get(|| async move { (StatusCode::OK, "Ok").into_response() }))
    .route("/v1/tlsnotary", get(tlsn::notarize))
    .route("/v1/tlsnotary/websocket_proxy", get(websocket_proxy::proxy))
    .route("/v1/origo", get(origo::proxy))
    .route("/v1/tee", get(tee::proxy))
    .route("/v1/origo/sign", post(origo::sign))
    .route("/v1/origo/verify", post(origo::verify))
    .layer(CorsLayer::permissive())
    .with_state(shared_state);

  if !c.server_cert.is_empty() || !c.server_key.is_empty() {
    let _ = listen(listener, router, &c.server_cert, &c.server_key).await;
  } else {
    let _ = acme_listen(listener, router, &c.acme_domain, &c.acme_email).await;
  }
  Ok(())
}

/// Starts an HTTPS server with automatic TLS certificate management via ACME protocol.
///
/// This function sets up an HTTPS server that:
/// 1. Configures automatic certificate provisioning using Let's Encrypt
/// 2. Handles ACME TLS-ALPN-01 challenges for domain validation
/// 3. Manages certificate renewal in the background
/// 4. Serves HTTPS traffic using the obtained certificates
///
/// # Arguments
///
/// * `listener` - TCP listener bound to the server's address
/// * `router` - Axum router containing the HTTP request handlers
/// * `domain` - Domain name for which to obtain certificates
/// * `email` - Contact email address for Let's Encrypt registration
///
/// # Returns
///
/// Returns `Ok(())` if the server starts successfully, or a `NotaryServerError` if:
/// - ACME configuration fails
/// - TLS configuration fails
/// - Server initialization fails
///
/// # Errors
///
/// This function will return an error if:
/// - ACME state initialization fails
/// - TLS configuration fails
/// - Server configuration is invalid
///
/// Connection-level errors and ACME events are logged but do not terminate the server.
/// Certificate renewal errors are handled automatically with exponential backoff.
async fn acme_listen(
  listener: TcpListener,
  router: Router,
  domain: &str,
  email: &str,
) -> Result<(), NotaryServerError> {
  let protocol = Arc::new(http1::Builder::new());

  let mut state = AcmeConfig::new([domain])
    .contact_push(format!("mailto:{}", email))
    .cache(DirCache::new("./rustls_acme_cache")) // TODO make this a config
    .directory_lets_encrypt(true)
    .state();
  let challenge_rustls_config = state.challenge_rustls_config();

  let mut rustls_config =
    ServerConfig::builder().with_no_client_auth().with_cert_resolver(state.resolver());
  rustls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

  tokio::spawn(async move {
    loop {
      match state.next().await {
        Some(result) => match result {
          Ok(ok) => info!("event: {:?}", ok),
          Err(err) => error!("error: {:?}", err),
        },
        None => {
          error!("ACME state stream ended unexpectedly");
        },
      }
    }
  });

  loop {
    let (tcp, _) = match listener.accept().await {
      Ok(connection) => connection,
      Err(e) => {
        error!("Failed to accept connection: {}", e);
        continue;
      },
    };
    let challenge_rustls_config = challenge_rustls_config.clone();
    let rustls_config = rustls_config.clone();
    let tower_service = router.clone();
    let protocol = protocol.clone();

    tokio::spawn(async move {
      let start_handshake = match LazyConfigAcceptor::new(Default::default(), tcp).await {
        Ok(handshake) => handshake,
        Err(e) => {
          error!("Failed to initialize TLS handshake: {}", e);
          return;
        },
      };

      if rustls_acme::is_tls_alpn_challenge(&start_handshake.client_hello()) {
        info!("received TLS-ALPN-01 validation request");
        let mut tls = match start_handshake.into_stream(challenge_rustls_config).await {
          Ok(stream) => stream,
          Err(e) => {
            error!("Failed to establish TLS-ALPN challenge stream: {}", e);
            return;
          },
        };
        if let Err(e) = tls.shutdown().await {
          error!("Failed to shutdown TLS-ALPN challenge connection: {}", e);
        }
      } else {
        let tls = match start_handshake.into_stream(Arc::new(rustls_config)).await {
          Ok(stream) => stream,
          Err(e) => {
            error!("Failed to establish TLS stream: {}", e);
            return;
          },
        };
        let io = TokioIo::new(tls);
        let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
          tower_service.clone().call(request)
        });
        if let Err(e) = protocol.serve_connection(io, hyper_service).with_upgrades().await {
          error!("Connection error: {}", e);
        }
      }
    });
  }
}

/// Starts a TLS-enabled HTTP server using provided certificates.
///
/// This function creates a TLS-enabled HTTP server that:
/// 1. Loads certificates and private key from the filesystem
/// 2. Configures TLS with HTTP/1.1 ALPN support
/// 3. Accepts incoming TLS connections in an infinite loop
/// 4. Spawns a new task for each connection to handle HTTP requests
///
/// # Arguments
///
/// * `listener` - TCP listener bound to the server's address
/// * `router` - Axum router containing the HTTP request handlers
/// * `server_cert_path` - Path to the TLS certificate file in PEM format
/// * `server_key_path` - Path to the private key file in PEM format
///
/// # Returns
///
/// Returns `Ok(())` if the server starts successfully, or a `NotaryServerError` if:
/// - Certificate files cannot be loaded
/// - Private key cannot be loaded
/// - TLS server configuration fails
///
/// # Errors
///
/// This function will return an error if:
/// - Certificate or private key files cannot be read
/// - TLS configuration fails
/// - Server configuration is invalid
///
/// Connection-level errors are logged but do not terminate the server.
async fn listen(
  listener: TcpListener,
  router: Router,
  server_cert_path: &str,
  server_key_path: &str,
) -> Result<(), NotaryServerError> {
  let protocol = Arc::new(http1::Builder::new());

  info!("Using {} and {}", server_cert_path, server_key_path);
  let certs = match load_certs(server_cert_path) {
    Ok(certs) => certs,
    Err(e) => {
      error!("Failed to load certificates: {}", e);
      return Err(NotaryServerError::CertificateError(e.to_string()));
    },
  };

  let key = match load_private_key(server_key_path) {
    Ok(key) => key,
    Err(e) => {
      error!("Failed to load private key: {}", e);
      return Err(NotaryServerError::CertificateError(e.to_string()));
    },
  };

  let server_config =
    match ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key) {
      Ok(config) => {
        let mut config = config;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
      },
      Err(e) => {
        error!("Failed to create server config: {}", e);
        return Err(NotaryServerError::ServerConfigError(e.to_string()));
      },
    };

  let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

  loop {
    let (tcp_stream, _) = match listener.accept().await {
      Ok(connection) => connection,
      Err(e) => {
        error!("Failed to accept connection: {}", e);
        continue;
      },
    };
    let tls_acceptor = tls_acceptor.clone();
    let tower_service = router.clone();
    let protocol = protocol.clone();

    tokio::spawn(async move {
      match tls_acceptor.accept(tcp_stream).await {
        Ok(tls_stream) => {
          let io = TokioIo::new(tls_stream);
          let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
            tower_service.clone().call(request)
          });
          if let Err(e) = protocol.serve_connection(io, hyper_service).with_upgrades().await {
            error!("Connection error: {}", e);
          }
        },
        Err(err) => {
          error!("TLS acceptance error: {}", err);
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

pub fn load_notary_signing_key(private_key_pem_path: &str) -> SigningKey {
  SigningKey::read_pkcs8_pem_file(private_key_pem_path).unwrap()
}

pub fn load_origo_signing_key(private_key_pem_path: &str) -> Secp256k1SigningKey {
  let raw = fs::read_to_string(private_key_pem_path).unwrap();
  Secp256k1SigningKey::from_pkcs8_pem(&raw).unwrap()
}
