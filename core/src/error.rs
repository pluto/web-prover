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

  /// The error is a manifest HTTP error
  #[error("Manifest HTTP error: {0}")]
  ManifestHttpError(#[from] ManifestHttpError),

  /// Serde operation failed
  ///
  /// This error occurs when serialization or deserialization operations fail.
  #[error("Serde error occurred: {0}")]
  SerdeError(#[from] serde_json::Error),

  /// Extractor error
  #[error("Extractor error: {0}")]
  ExtractorError(#[from] crate::parser::ExtractorError),

  /// Template-specific errors
  #[error("Template error: {0}")]
  Template(#[from] TemplateError),

  /// Indicates that extraction failed
  #[error("Extraction failed: {0}")]
  ExtractionFailed(String),
}

#[derive(Debug, Error)]
pub enum ManifestHttpError {
  /// HTTP status mismatch between expected and actual status
  #[error("HTTP status mismatch: expected {expected}, actual {actual}")]
  StatusMismatch { expected: String, actual: String },

  /// HTTP version mismatch between expected and actual version
  #[error("HTTP version mismatch: expected {expected}, actual {actual}")]
  VersionMismatch { expected: String, actual: String },

  /// HTTP message mismatch between expected and actual message
  #[error("HTTP message mismatch: expected {expected}, actual {actual}")]
  MessageMismatch { expected: String, actual: String },

  /// HTTP header value mismatch between expected and actual value
  #[error("HTTP header mismatch: expected {expected}, actual {actual}")]
  HeaderMismatch { expected: String, actual: String },

  /// Expected HTTP header is missing
  #[error("HTTP header missing: expected {expected}, actual {actual}")]
  HeaderMissing { expected: String, actual: String },

  /// HTTP method mismatch between expected and actual method
  #[error("HTTP method mismatch: expected {expected}, actual {actual}")]
  MethodMismatch { expected: String, actual: String },

  /// HTTP URL mismatch between expected and actual URL
  #[error("HTTP URL mismatch: expected {expected}, actual {actual}")]
  UrlMismatch { expected: String, actual: String },
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

  /// Variable is missing
  #[error("Variable missing for key: {key}")]
  VariableMissing { key: String },

  /// Variable doesn't match
  #[error("Variable mismatch for key: {key}")]
  VariableMismatch { key: String },
}
