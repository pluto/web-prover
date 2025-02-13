use axum::{
  http::StatusCode,
  response::{IntoResponse, Response},
};
use eyre::Report;
use thiserror::Error;
use tlsn_verifier::tls::{VerifierConfigBuilderError, VerifierError};
use tracing::error;

#[derive(Debug, Error)]
pub enum ProxyError {
  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  TryIntoError(#[from] std::array::TryFromSliceError),

  #[error(transparent)]
  Base64Decode(#[from] base64::DecodeError),

  #[error(transparent)]
  TlsBackend(#[from] tls_client2::BackendError),

  #[error("unable to parse record! position={position:?}, remaining={remaining:?}, e={e:?}")]
  TlsParser { position: u64, remaining: usize, e: String },

  #[error("{0}")]
  TlsHandshakeExtract(String),

  #[error("{0}")]
  TlsHandshakeVerify(String),

  #[error("Error occurred during Sign: {0}")]
  Sign(Box<dyn std::error::Error + Send + 'static>),

  #[error("transparent")]
  SuperNovaError(#[from] client_side_prover::supernova::error::SuperNovaError),

  #[error("Session ID Error: {0}")]
  InvalidSessionId(String),

  #[error(transparent)]
  ProofError(#[from] proofs::errors::ProofError),

  #[error(transparent)]
  SerdeJsonError(#[from] serde_json::Error),
}

impl IntoResponse for ProxyError {
  fn into_response(self) -> Response {
    error!("proxy error: {}", self);

    match self {
      sign @ ProxyError::Sign(_) =>
        (StatusCode::INTERNAL_SERVER_ERROR, sign.to_string()).into_response(),
      ProxyError::TlsHandshakeExtract(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
      _ => (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response(),
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
  #[error(transparent)]
  Unexpected(#[from] Report),

  #[error("Error occurred during notarization: {0}")]
  Notarization(Box<dyn std::error::Error + Send + 'static>),

  #[error("Invalid request from prover: {0}")]
  BadProverRequest(String),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  TeeTlsAcceptorError(#[from] caratls_ekm_server::TeeTlsAcceptorError),

  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),

  #[error("Error occurred from reading certificates: {0}")]
  CertificateError(String),

  #[error("Error occurred from reasing server config: {0}")]
  ServerConfigError(String),
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
    error!("notary error: {:?}", self);

    match self {
      bad_request_error @ NotaryServerError::BadProverRequest(_) =>
        (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response(),
      _ => (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response(),
    }
  }
}
