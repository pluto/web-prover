//! # Extractor Utilities
//!
//! This module provides utility functions for extractors.

use serde_json::Value;

use crate::parser::{
  common::get_value_type, errors::ExtractorError, extractors::types::ExtractorType,
};

/// Validates that a value matches the expected type
pub fn validate_type(value: &Value, expected_type: &ExtractorType) -> Result<(), ExtractorError> {
  let actual_type = get_value_type(value);
  let expected_type_str = expected_type.to_string();

  if actual_type != expected_type_str {
    return Err(ExtractorError::TypeMismatch {
      expected: expected_type_str,
      actual:   actual_type.to_string(),
    });
  }

  Ok(())
}
