use std::{
  io,
  process::{Command, Output, Stdio},
  sync::Arc,
};

use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{errors::ProxyError, SharedState};

#[derive(Serialize)]
pub struct AttestationReply {
  token: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AttestationBody {}

pub async fn attestation(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<AttestationBody>,
) -> Result<Json<AttestationReply>, ProxyError> {
  let mut response = AttestationReply { token: "".to_string() };

  match run_tee_util() {
    Ok(stdout) => {
		response.token = stdout
	},
    Err(e) => {
      println!("{:}", e)
    },
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

fn run_tee_util() -> Result<String, TeeUtilError> {
  let output: Output =
    Command::new("/app/tee-util").stderr(Stdio::piped()).stdout(Stdio::piped()).output()?;

  if !output.status.success() {
    let stderr = String::from_utf8(output.stderr)?;
    return Err(TeeUtilError::CommandFailed { exit_code: output.status.code(), stderr });
  }

  let stdout = String::from_utf8(output.stdout)?;
  Ok(stdout)
}
