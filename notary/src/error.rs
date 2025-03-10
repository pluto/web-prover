//! Error types for the web-prover-notary crate.
//! - `ProxyError`: Errors that occur during proxy operations
//! - `NotaryServerError`: Errors that occur in the notary server
//!
//! It also provides conversion to HTTP responses for integration with the web framework.

use axum::{
  http::StatusCode,
  response::{IntoResponse, Response},
};
use eyre::Report;
use thiserror::Error;
use tracing::error;
use web_prover_core::error::WebProverCoreError;

/// Errors related to the proxy functionality.
///
/// These errors occur during proxy operations, such as forwarding requests
/// and handling responses between the client and the target server.
#[derive(Debug, Error)]
pub enum ProxyError {
  /// IO error during proxy operations
  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  /// Error when converting a slice to an array
  #[error("Array conversion error: {0}")]
  TryIntoError(#[from] std::array::TryFromSliceError),

  /// Base64 decoding error
  #[error("Base64 decoding error: {0}")]
  Base64Decode(#[from] base64::DecodeError),

  /// JSON serialization/deserialization error
  #[error("JSON error: {0}")]
  SerdeJsonError(#[from] serde_json::Error),
}

/// Errors related to the notary server.
///
/// These errors represent all possible failures that can occur in the notary server,
/// including configuration errors, certificate errors, and proxy errors.
#[derive(Debug, Error)]
pub enum NotaryServerError {
  /// Unexpected error with full context
  #[error("Unexpected error: {0}")]
  Unexpected(#[from] Report),

  /// IO error
  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  /// JSON serialization/deserialization error
  #[error("JSON error: {0}")]
  SerdeJson(#[from] serde_json::Error),

  /// Error occurred from reading certificates
  #[error("Certificate error: {0}")]
  CertificateError(String),

  /// Error occurred from reading server config
  #[error("Server configuration error: {0}")]
  ServerConfigError(String),

  /// Manifest-request mismatch
  #[error("Manifest-request mismatch")]
  ManifestRequestMismatch,

  /// Proxy error
  #[error("Proxy error: {0}")]
  ProxyError(#[from] ProxyError),

  /// Web prover core error
  #[error("Core error: {0}")]
  WebProverCoreError(#[from] WebProverCoreError),
}

/// Trait implementation to convert this error into an axum http response.
///
/// This allows the error to be returned directly from axum handlers,
/// automatically converting it to an appropriate HTTP response.
impl IntoResponse for NotaryServerError {
  fn into_response(self) -> Response {
    error!("notary error: {:?}", self);
    (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response()
  }
}
