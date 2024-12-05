use std::{io, sync::Arc};

use axum::{
  extract::{self, State},
  Extension, Json,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_client_sockets::{unix::HyperUnixStream, Backend};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{errors::ProxyError, SharedState};

#[derive(Serialize)]
pub struct AttestationReply {
  token: String,
  error: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AttestationBody {
  handshake_server_aes_iv:    String,
  handshake_server_aes_key:   String,
  application_client_aes_iv:  String,
  application_client_aes_key: String,
  application_server_aes_iv:  String,
  application_server_aes_key: String,
}

pub async fn attestation(
  State(state): State<Arc<SharedState>>,
  Extension(key_material): Extension<Vec<u8>>,
  extract::Json(payload): extract::Json<AttestationBody>,
) -> Result<Json<AttestationReply>, ProxyError> {
  let mut response = AttestationReply { token: Default::default(), error: Default::default() };

  match get_tee_token("https://notary.pluto.xyz".to_string(), "OIDC".to_string(), vec![
    hex::encode(key_material),
  ])
  .await
  {
    Ok(token) => response.token = token,
    Err(e) => response.error = format!("{:?}", e),
  }

  Ok(Json(response))
}

#[derive(Error, Debug)]
pub enum TEETokenError {
  #[error("I/O error: {0}")]
  IoError(#[from] io::Error),

  #[error("UTF-8 error: {0}")]
  Utf8Error(#[from] std::string::FromUtf8Error),

  #[error("JSON parsing error: {0}")]
  JsonError(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct CustomTokenRequest {
  audience:   String,
  token_type: String,
  nonces:     Vec<String>,
}

pub async fn get_tee_token(
  audience: String,
  token_type: String,
  nonces: Vec<String>,
) -> Result<String, TEETokenError> {
  let stream = HyperUnixStream::connect("/run/container_launcher/teeserver.sock", Backend::Tokio)
    .await
    .unwrap(); // TODO unwrap

  let token_request = CustomTokenRequest { audience, token_type, nonces };
  let token_request = serde_json::to_string(&token_request)?;

  let (mut client, conn) =
    hyper::client::conn::http1::Builder::new().handshake::<_, Full<Bytes>>(stream).await.unwrap(); // TODO unwrap

  tokio::task::spawn(conn);

  let request = Request::builder()
    .uri("http://localhost/v1/token")
    .method("POST")
    .header("Host", "localhost")
    .header("Content-Type", "application/json")
    .body(Full::new(Bytes::from(token_request)))
    .unwrap(); // TODO unwrap

  let response = client.send_request(request).await.unwrap(); // TODO unwrap
  assert!(response.status().is_success()); // TODO return Err instead

  let body = response.collect().await.unwrap().to_bytes();
  let body = String::from_utf8_lossy(&body).to_string();
  Ok(body)
}
