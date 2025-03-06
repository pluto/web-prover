use axum::{
  http::StatusCode,
  response::{IntoResponse, Response},
};
use eyre::Report;
use thiserror::Error;
use tracing::error;
use web_prover_core::errors::ManifestError;

#[derive(Debug, Error)]
pub enum ProxyError {
  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  TryIntoError(#[from] std::array::TryFromSliceError),

  #[error(transparent)]
  Base64Decode(#[from] base64::DecodeError),

  #[error(transparent)]
  SerdeJsonError(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
  #[error(transparent)]
  Unexpected(#[from] Report),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),

  #[error("Error occurred from reading certificates: {0}")]
  CertificateError(String),

  #[error("Error occurred from reasing server config: {0}")]
  ServerConfigError(String),

  // TODO: Update to contain feedback
  #[error("Manifest-request mismatch")]
  ManifestRequestMismatch,

  // TODO: Update to contain feedback
  #[error("Manifest-response mismatch")]
  ManifestResponseMismatch,

  #[error(transparent)]
  ProxyError(#[from] ProxyError),

  #[error(transparent)]
  ManifestError(#[from] ManifestError),
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
  fn into_response(self) -> Response {
    error!("notary error: {:?}", self);
    (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response()
  }
}
