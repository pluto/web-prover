//! Error types for the web-prover-client crate.
//!
//! This module defines the `WebProverClientError` enum, which represents
//! all possible errors that can occur within the client crate. It includes
//! errors from external dependencies as well as client-specific errors.

use thiserror::Error;

/// Errors related to the web prover client.
///
/// This enum represents all possible errors that can occur within the client crate.
/// It includes errors from external dependencies (like network errors, parsing errors)
/// as well as client-specific errors (like missing manifest or TEE proof).
#[derive(Debug, Error)]
pub enum WebProverClientError {
  /// Rustls TLS error
  #[cfg(not(target_arch = "wasm32"))]
  #[error("TLS error: {0}")]
  RustTls(#[from] rustls::Error),

  /// UTF-8 conversion error
  #[error("UTF-8 conversion error: {0}")]
  FromUtf8(#[from] std::string::FromUtf8Error),

  /// Reqwest HTTP client error
  #[error("HTTP client error: {0}")]
  Reqwest(#[from] reqwest::Error),

  /// IO error
  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  /// JSON serialization/deserialization error
  #[error("JSON error: {0}")]
  SerdeJson(#[from] serde_json::Error),

  /// Hyper HTTP error
  #[error("HTTP error: {0}")]
  Hyper(#[from] hyper::Error),

  /// HTTP protocol error
  #[error("HTTP protocol error: {0}")]
  Http(#[from] hyper::http::Error),

  /// Async task join error
  #[error("Async task error: {0}")]
  Join(#[from] tokio::task::JoinError),

  /// UTF-8 error
  #[error("UTF-8 error: {0}")]
  Utf8(#[from] std::str::Utf8Error),

  /// URL parsing error
  #[error("URL parsing error: {0}")]
  UrlParse(#[from] url::ParseError),

  /// Invalid HTTP header name
  #[error("Invalid HTTP header name: {0}")]
  InvalidHeaderName(#[from] hyper::header::InvalidHeaderName),

  /// Invalid HTTP header value
  #[error("Invalid HTTP header value: {0}")]
  InvalidHeaderValue(#[from] hyper::header::InvalidHeaderValue),

  /// Base64 decoding error
  #[error("Base64 decoding error: {0}")]
  Base64Decode(#[from] base64::DecodeError),

  /// Hex decoding error
  #[error("Hex decoding error: {0}")]
  HexDecode(#[from] hex::FromHexError),

  /// Invalid DNS name error
  #[error("Invalid DNS name: {0}")]
  InvalidDnsNameError(#[from] rustls::pki_types::InvalidDnsNameError),

  /// Async operation canceled
  #[error("Async operation canceled: {0}")]
  Canceled(#[from] futures::channel::oneshot::Canceled),

  /// Manifest missing error
  #[error("Manifest missing")]
  ManifestMissingError,

  /// Other error
  #[error("Other error: {0}")]
  Other(String),

  /// TEE proof missing
  #[error("TEE proof missing")]
  TeeProofMissing,

  /// Core error
  #[error("Core error: {0}")]
  CoreError(#[from] web_prover_core::error::WebProverCoreError),
}
