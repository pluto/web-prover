//! # Extractor Types
//!
//! This module defines the common types used by extractors.

use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::parser::{
  extractors::get_value_type, predicate, predicate::Predicate, DataFormat, ExtractorError,
};

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
    match value {
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

impl Extractor {}

/// The extracted values, keyed by extractor ID
pub type ExtractionValues = HashMap<String, Value>;

/// The result of an extraction operation
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ExtractionResult {
  /// The extracted values, keyed by extractor ID
  pub values: ExtractionValues,
  /// Any errors that occurred during extraction
  pub errors: Vec<String>,
}

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

pub trait RawDocument {
  fn extract_value(&self, extractor: &Extractor) -> Result<ExtractedValue, ExtractorError>;
  fn validate_format(&self, format: &DataFormat) -> Result<(), ExtractorError>;
}

impl ExtractionResult {
  pub fn process_value(
    &mut self,
    value: Result<ExtractedValue, ExtractorError>,
    extractor: &Extractor,
  ) {
    match value {
      Ok(extracted) => {
        let value = extracted.into_value();
        if let Err(type_err) = extractor.extractor_type.is_valid_type(&value) {
          if extractor.required {
            self.add_error(extractor, type_err);
          }
          return;
        }

        let mut predicate_valid = true;
        for predicate in &extractor.predicates {
          if let Err(pred_err) = predicate::validate_predicate(&value, predicate) {
            if extractor.required {
              self.add_error(extractor, ExtractorError::PredicateError(pred_err));
            }
            predicate_valid = false;
            break;
          }
        }

        if predicate_valid {
          self.values.insert(extractor.id.clone(), value);
        }
      },
      Err(err) if extractor.required => {
        self.add_error(extractor, err);
      },
      _ => {},
    }
  }

  fn add_error(&mut self, extractor: &Extractor, error: ExtractorError) {
    self.errors.push(format!("Extractor '{}': {}", extractor.id, error));
  }
}
