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

  /// Extractor error
  #[error("Extractor error: {0}")]
  ExtractorError(#[from] crate::parser::ExtractorError),

  /// Template-specific errors
  #[error("Template error: {0}")]
  Template(#[from] TemplateError),
}

/// Represents specific error conditions related to template handling
#[derive(Debug, Error)]
pub enum TemplateError {
  /// Required template variable is not used in the template
  #[error("Required variable `{0}` is not used in the template")]
  UnusedRequiredVariable(String),

  /// Non-required variable is missing a default value
  #[error("Non-required variable `{0}` must have a default value")]
  MissingDefaultValue(String),

  /// Invalid regex pattern
  #[error("Invalid regex pattern for `{0}`")]
  InvalidRegexPattern(String),

  /// Default value doesn't match the specified pattern
  #[error("Default value for `{0}` does not match the specified pattern")]
  DefaultValuePatternMismatch(String),

  /// Empty regex pattern
  #[error("Empty regex pattern for `{0}`")]
  EmptyRegexPattern(String),
}
