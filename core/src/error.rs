//! # Error Types
//!
//! This module defines the error types used throughout the `web-prover-core` crate.
//!
//! The primary error type is [`WebProverCoreError`], which encompasses all possible
//! error conditions that can occur within the crate.

use thiserror::Error;

/// Represents the various error conditions that can occur within the `web-prover-core` crate.
///
/// This enum provides specific error variants for different failure scenarios, making
/// error handling more precise and informative.
#[derive(Debug, Error)]
pub enum WebProverCoreError {
  /// The error is an invalid manifest
  ///
  /// This error occurs when a manifest fails validation checks. The string
  /// parameter provides details about the specific validation failure.
  #[error("Invalid manifest: {0}")]
  InvalidManifest(String),

  /// Serde operation failed
  ///
  /// This error occurs when serialization or deserialization operations fail.
  #[error("Serde error occurred: {0}")]
  SerdeError(#[from] serde_json::Error),
}
