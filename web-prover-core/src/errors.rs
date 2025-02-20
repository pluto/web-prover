//! Error type for the `web-prover-core` crate.

use thiserror::Error;

/// Represents the various error conditions that can occur within the `proofs` crate.
#[derive(Debug, Error)]
pub enum ManifestError {
  /// The error is an invalid manifest
  #[error("Invalid manifest: {0}")]
  InvalidManifest(String),

  /// Serde operation failed
  #[error("Serde error occurred: {0}")]
  SerdeError(#[from] serde_json::Error),
}
