//! # Extractor Types
//!
//! This module defines the common types used by extractors.

use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

use crate::{
  hash::keccak_digest,
  parser::{
    errors::ExtractorErrorWithId, extractors::get_value_type, predicate, predicate::Predicate,
    DataFormat, ExtractorConfig, ExtractorError,
  },
};

/// Trait for extracting data from a document
pub trait DocumentExtractor {
  fn validate_input(&self, data: &[u8]) -> Result<(), ExtractorError>;
  fn extract(
    &self,
    data: &[u8],
    config: &ExtractorConfig,
  ) -> Result<ExtractionResult, ExtractorError>;
}

/// The type of data being extracted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExtractorType {
  /// String type
  String,
  /// Number type
  Number,
  /// Boolean type
  Boolean,
  /// Array type
  Array,
  /// Object type
  Object,
}

impl ExtractorType {
  pub fn is_valid_type(&self, value: &Value) -> Result<(), ExtractorError> {
    let actual_type = get_value_type(value);
    let expected_type_str = self.to_string();

    if actual_type != expected_type_str {
      return Err(ExtractorError::TypeMismatch {
        expected: expected_type_str,
        actual:   actual_type.to_string(),
      });
    }

    Ok(())
  }
}

impl TryFrom<&str> for ExtractorType {
  type Error = ExtractorError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value.to_lowercase().as_str() {
      "string" => Ok(ExtractorType::String),
      "number" => Ok(ExtractorType::Number),
      "boolean" => Ok(ExtractorType::Boolean),
      "array" => Ok(ExtractorType::Array),
      "object" => Ok(ExtractorType::Object),
      _ => Err(ExtractorError::UnsupportedExtractorType(value.to_string())),
    }
  }
}

impl Display for ExtractorType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let str = match self {
      ExtractorType::String => "string",
      ExtractorType::Number => "number",
      ExtractorType::Boolean => "boolean",
      ExtractorType::Array => "array",
      ExtractorType::Object => "object",
    }
    .to_string();
    write!(f, "{}", str)
  }
}

/// Function to provide the default value `true` for `required`
fn default_true() -> bool { true }

/// A data extractor configuration
// TODO: Consider introducing a generic type parameter for the extractor https://github.com/pluto/web-prover/pull/547#discussion_r1986080565
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Extractor {
  /// Unique identifier for the extractor
  pub id:             String,
  /// Human-readable description
  pub description:    String,
  /// Path to the data (e.g., JSON path)
  pub selector:       Vec<String>,
  /// Expected data type
  #[serde(rename = "type")]
  pub extractor_type: ExtractorType,
  /// Whether this extraction is required
  #[serde(default = "default_true")]
  pub required:       bool,
  /// Predicates to validate the extracted data
  #[serde(default)]
  pub predicates:     Vec<Predicate>,
  /// HTML attribute to extract
  #[serde(skip_serializing_if = "Option::is_none")]
  pub attribute:      Option<String>,
}

/// The extracted values, keyed by extractor ID
// TODO: Consider supporting lazy evaluation https://github.com/pluto/web-prover/pull/547#discussion_r1986223169
pub type ExtractionValues = HashMap<String, Value>;

/// The result of an extraction operation
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExtractionResult {
  /// The extracted values, keyed by extractor ID
  pub values: ExtractionValues,
  /// Any errors that occurred during extraction
  pub errors: Vec<String>,
}

impl ExtractionResult {
  /// Processes the extracted value based on the extractor configuration.
  /// If the extraction is required and fails, the error is added to the result.
  /// If the extraction is not required, the error is ignored.
  /// If the extraction is successful, the value is added to the result.
  pub fn process_extraction(
    &mut self,
    value: Result<ExtractedValue, ExtractorError>,
    extractor: &Extractor,
  ) {
    match value {
      Ok(extracted) => {
        let value = extracted.into_value();
        if let Err(type_err) = extractor.extractor_type.is_valid_type(&value) {
          if extractor.required {
            self.add_extractor_error(extractor, type_err);
          }
          return;
        }

        let mut predicate_valid = true;
        for predicate in &extractor.predicates {
          if let Err(pred_err) = predicate::validate_predicate(&value, predicate) {
            if extractor.required {
              self.add_extractor_error(extractor, ExtractorError::PredicateError(pred_err));
            }
            predicate_valid = false;
            break;
          }
        }

        if predicate_valid {
          debug!("Predicate {} valid for extractor {}", predicate_valid, extractor.id);
          self.values.insert(extractor.id.clone(), value);
        } else {
          debug!("Predicate {} invalid for extractor {}", predicate_valid, extractor.id);
        }
      },
      Err(err) if extractor.required => {
        self.add_extractor_error(extractor, err);
      },
      _ => {},
    }
  }

  /// Adds an error to the result and logs it
  pub fn report_error(&mut self, error: ExtractorErrorWithId) {
    tracing::debug!(
      error_type = "extraction",
      error_msg = %error,
      "Extraction error occurred"
    );
    self.errors.push(error.to_string());
  }

  /// Adds an extractor error to the result and logs it
  fn add_extractor_error(&mut self, extractor: &Extractor, error: ExtractorError) {
    tracing::debug!(
      error_type = "extractor",
      extractor_id = %extractor.id,
      error_msg = %error,
      extractor_description = %extractor.description,
      "Extractor validation failed"
    );

    self.report_error((extractor.id.clone(), error).into());
  }

  /// Merges another extraction result into this one
  pub fn merge(&mut self, other: &ExtractionResult) {
    self.values.extend(other.clone().values);
    self.errors.extend(other.clone().errors);
  }

  /// Returns `true` if no errors were encountered during extraction
  pub fn is_success(&self) -> bool { self.errors.is_empty() }

  /// Compute a `Keccak256` hash of the serialized ExtractionResult
  pub fn to_keccak_digest(&self) -> Result<[u8; 32], ExtractorError> {
    let as_bytes: Vec<u8> = serde_json::to_vec(self)?;
    Ok(keccak_digest(&as_bytes))
  }
}

/// The value extracted from the raw document
pub enum ExtractedValue {
  Json(Value),
  Html(Value),
}

impl ExtractedValue {
  pub fn into_value(self) -> Value {
    match self {
      ExtractedValue::Json(v) | ExtractedValue::Html(v) => v,
    }
  }
}

/// Trait for raw document, providing methods to extract values and validate format
pub trait RawDocument {
  fn extract_value(&self, extractor: &Extractor) -> Result<ExtractedValue, ExtractorError>;
  fn validate_format(&self, format: &DataFormat) -> Result<(), ExtractorError>;
}
