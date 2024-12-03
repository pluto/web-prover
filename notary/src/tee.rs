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
  key_material: String,
  token:        String,
  error:        String,
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
  let mut response = AttestationReply {
    key_material: Default::default(),
    token:        Default::default(),
    error:        Default::default(),
  };

  response.key_material = hex::encode(key_material.clone());

  match run_tee_util(vec![hex::encode(key_material)], None) {
    Ok(stdout) => response.token = stdout,
    Err(e) => response.error = format!("{:?}", e),
  }

  Ok(Json(response))
}

#[derive(Error, Debug)]
pub enum TeeUtilError {
  #[error("Command execution failed with exit code {exit_code:?}: {stderr}")]
  CommandFailed { exit_code: Option<i32>, stderr: String },

  #[error("I/O error: {0}")]
  IoError(#[from] io::Error),

  #[error("UTF-8 error: {0}")]
  Utf8Error(#[from] std::string::FromUtf8Error),
}

pub fn run_tee_util(nonces: Vec<String>, audience: Option<String>) -> Result<String, TeeUtilError> {
  // return Ok("dummy string".to_string()); // TODO

  let mut command = Command::new("/app/tee-util");

  if let Some(aud) = audience {
    command.arg("-audience").arg(aud);
  }

  for nonce in nonces {
    command.arg("-nonce").arg(nonce);
  }

  let output: Output = command.stderr(Stdio::piped()).stdout(Stdio::piped()).output().unwrap();

  if !output.status.success() {
    let stderr = String::from_utf8(output.stderr).unwrap();
    return Err(TeeUtilError::CommandFailed { exit_code: output.status.code(), stderr });
  }

  let stdout = String::from_utf8(output.stdout).unwrap();
  Ok(stdout)
}
