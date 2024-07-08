pub mod notary;
pub mod routes;
pub mod errors;
pub mod client;
pub use errors::ClientErrors;

#[cfg(target_arch = "wasm32")] pub mod verify;
#[cfg(target_arch = "wasm32")] pub mod wasm_utils;
use std::{fs, io};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{debug, info, subscriber, trace, Level};

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
  /// Client that has access to the transport layer
  Tcp,
  /// Client that cannot directly access transport layer, e.g. browser extension
  Websocket,
}

// TODO: Note, this is currently bringing in some of the `RequestOptions` and renames to simplify
// things if possible.
// * `notary_host` is now `notary_url`
// The `target_headers` was previously `HashMap<String, Vec<String>>`
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub notary_host:                  String,
  pub notary_port:                  u16,
  pub target_method:                String,
  pub target_url:                   String,
  pub target_headers:               HashMap<String, String>,
  pub target_body:                  String,
  #[cfg(feature = "websocket")]
  _websocket_proxy_url:          String,
  pub notarization_session_request: NotarizationSessionRequest,
  pub notary_ca_cert_path:          String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
  pub client_type:   ClientType,
  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,
}

use anyhow::Result;
use pki_types::{CertificateDer, PrivateKeyDer};

pub fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
  let certfile =
    fs::File::open(filename).map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
  let mut reader = io::BufReader::new(certfile);
  rustls_pemfile::certs(&mut reader).collect()
}

pub fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
  let keyfile =
    fs::File::open(filename).map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
  let mut reader = io::BufReader::new(keyfile);
  rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

pub fn error(err: String) -> io::Error { io::Error::new(io::ErrorKind::Other, err) }

/// Read a PEM-formatted file and return its buffer reader
#[allow(dead_code)]
async fn read_pem_file(file_path: &str) -> Result<io::BufReader<std::fs::File>> {
  let key_file = tokio::fs::File::open(file_path).await?.into_std().await;
  Ok(io::BufReader::new(key_file))
}
