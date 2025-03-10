use axum::{
  http::StatusCode,
  response::{IntoResponse, Response},
};
use eyre::Report;
use thiserror::Error;
use tracing::error;
use web_prover_core::error::WebProverCoreError;

// TODO (autoparallel): I think these error enums should be combined into `WebProverNotaryError`.
// Combining enums is a good practice. They could also all be moved to the `web-prover-core` crate
// so there is one spot for all the errors. This makes error handling more consistent and easier to
// manage.

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

  #[error("Manifest-request mismatch")]
  ManifestRequestMismatch,

  #[error(transparent)]
  ProxyError(#[from] ProxyError),

  #[error(transparent)]
  WebProverCoreError(#[from] WebProverCoreError),
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
  fn into_response(self) -> Response {
    error!("notary error: {:?}", self);
    (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response()
  }
}
