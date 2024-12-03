use std::{
  io,
  process::{Command, Output, Stdio},
  sync::Arc,
};

use axum::{
  extract::{self, Query, State},
  response::Response,
  Extension, Json,
};
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

  match get_token(vec![hex::encode(key_material)], None) {
    Ok(token) => response.token = token,
    Err(e) => response.error = format!("{:?}", e),
  }

  Ok(Json(response))
}

#[derive(Error, Debug)]
pub enum TEETokenError {
  #[error("Command execution failed with exit code {exit_code:?}: {stderr}")]
  CommandFailed { exit_code: Option<i32>, stderr: String },

  #[error("I/O error: {0}")]
  IoError(#[from] io::Error),

  #[error("UTF-8 error: {0}")]
  Utf8Error(#[from] std::string::FromUtf8Error),

  #[error("JSON parsing error: {0}")]
  JsonError(#[from] serde_json::Error),
}

#[derive(serde::Deserialize)]
struct TokenResponse {
  jwt: String,
}

pub fn get_token(nonces: Vec<String>, audience: Option<String>) -> Result<String, TEETokenError> {
  let mut command = Command::new("/app/tee-util");

  if let Some(aud) = audience {
    command.arg("-audience").arg(aud);
  }

  for nonce in nonces {
    command.arg("-nonce").arg(nonce);
  }

  let output: Output = command.stderr(Stdio::piped()).stdout(Stdio::piped()).output()?;

  if !output.status.success() {
    let stderr = String::from_utf8(output.stderr)?;
    return Err(TEETokenError::CommandFailed { exit_code: output.status.code(), stderr });
  }

  let stdout = String::from_utf8(output.stdout)?;
  let token: TokenResponse = serde_json::from_str(&stdout)?;
  Ok(token.jwt)
}
