use axum::{
  http::StatusCode,
  response::{IntoResponse, Response},
};
use eyre::Report;
use thiserror::Error;
use tlsn_verifier::tls::{VerifierConfigBuilderError, VerifierError};

#[derive(Debug, Error)]
pub enum ProxyError {
  #[error(transparent)]
  Base64Decode(#[from] base64::DecodeError),

  #[error(transparent)]
  TlsBackend(#[from] tls_backend::BackendError),

  #[error("unable to parse record! position={position:?}, remaining={remaining:?}, e={e:?}")]
  TlsParser { position: u64, remaining: usize, e: String },

  #[error("{0}")]
  TlsHandshakeExtract(String),

  #[error("Error occurred during Sign: {0}")]
  Sign(Box<dyn std::error::Error + Send + 'static>),
}

impl IntoResponse for ProxyError {
  fn into_response(self) -> Response {
    match self {
      sign @ ProxyError::Sign(_) =>
        (StatusCode::INTERNAL_SERVER_ERROR, sign.to_string()).into_response(),
      ProxyError::TlsHandshakeExtract(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
      _ => (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response(),
    }
  }
}

#[derive(Debug, Error)]
pub enum TeeError {}

impl IntoResponse for TeeError {
  fn into_response(self) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response()
  }
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
  #[error(transparent)]
  Unexpected(#[from] Report),
  #[error("Failed to connect to prover: {0}")]
  Connection(String),
  #[error("Error occurred during notarization: {0}")]
  Notarization(Box<dyn std::error::Error + Send + 'static>),
  #[error("Invalid request from prover: {0}")]
  BadProverRequest(String),
  #[error("Unauthorized request from prover: {0}")]
  UnauthorizedProverRequest(String),
}

impl From<VerifierError> for NotaryServerError {
  fn from(error: VerifierError) -> Self { Self::Notarization(Box::new(error)) }
}

impl From<VerifierConfigBuilderError> for NotaryServerError {
  fn from(error: VerifierConfigBuilderError) -> Self { Self::Notarization(Box::new(error)) }
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
  fn into_response(self) -> Response {
    match self {
      bad_request_error @ NotaryServerError::BadProverRequest(_) =>
        (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response(),
      unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) =>
        (StatusCode::UNAUTHORIZED, unauthorized_request_error.to_string()).into_response(),
      _ => (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response(),
    }
  }
}
