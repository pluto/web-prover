//! # Extractor Module
//!
//! The `extractor` module provides functionality for extracting and validating data
//! from different formats (JSON, HTML) based on a configuration file.

use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::parser::{
  common::get_value_type,
  config::{DataFormat, ExtractorConfig},
  errors::ExtractorError,
  predicate,
  predicate::Predicate,
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
}

/// The extracted values, keyed by extractor ID
pub type ExtractionValues = HashMap<String, Value>;

/// The result of an extraction operation
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ExtractionResult {
  /// The extracted values, keyed by extractor ID
  pub values: ExtractionValues,
  /// Any errors that occurred during extraction
  pub errors: Vec<String>,
}

/// Validates that a value matches the expected type
fn validate_type(value: &Value, expected_type: &ExtractorType) -> Result<(), ExtractorError> {
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

/// Extracts data from a JSON value using the provided extractor configuration
pub fn extract_json(
  json: &Value,
  config: &ExtractorConfig,
) -> Result<ExtractionResult, ExtractorError> {
  if config.format != DataFormat::Json {
    return Err(ExtractorError::InvalidFormat("JSON".to_string()));
  }

  let mut result = ExtractionResult { values: HashMap::new(), errors: Vec::new() };

  for extractor in &config.extractors {
    match extract_json_value(json, &extractor.selector) {
      Ok(value) => {
        // Validate the type
        if let Err(type_err) = validate_type(&value, &extractor.extractor_type) {
          if extractor.required {
            match &type_err {
              ExtractorError::TypeMismatch { expected, actual } => {
                result.errors.push(format!(
                  "Extractor '{}': Expected {}, got {}",
                  extractor.id, expected, actual
                ));
              },
              _ => result.errors.push(format!("Extractor '{}': {}", extractor.id, type_err)),
            }
          }
          continue;
        }

        // Validate predicates
        let mut predicate_valid = true;
        for predicate in &extractor.predicates {
          if let Err(pred_err) = predicate::validate_predicate(&value, predicate) {
            if extractor.required {
              result.errors.push(format!("Extractor '{}': {}", extractor.id, pred_err));
            }
            predicate_valid = false;
            break;
          }
        }

        if predicate_valid {
          result.values.insert(extractor.id.clone(), value);
        }
      },
      Err(err) =>
        if extractor.required {
          result.errors.push(format!("Extractor '{}': {}", extractor.id, err));
        },
    }
  }

  Ok(result)
}

/// Extracts a value from a JSON object using a path selector
fn extract_json_value(json: &Value, path: &[String]) -> Result<Value, ExtractorError> {
  // Special case: if the path is empty, we should not extract anything
  if path.is_empty() {
    return Err(ExtractorError::MissingField("Empty selector path".to_string()));
  }

  let mut current = json;

  for (i, segment) in path.iter().enumerate() {
    match current {
      Value::Object(map) =>
        if let Some(value) = map.get(segment) {
          current = value;
        } else {
          return Err(ExtractorError::MissingField(format!("Key '{}' not found", segment)));
        },
      Value::Array(arr) =>
        if let Ok(index) = segment.parse::<usize>() {
          if index < arr.len() {
            current = &arr[index];
          } else {
            return Err(ExtractorError::ArrayIndexOutOfBounds { index, segment: i });
          }
        } else {
          return Err(ExtractorError::InvalidArrayIndex { index: segment.clone(), segment: i });
        },
      _ => {
        return Err(ExtractorError::NonNavigableValue {
          value_type: get_value_type(current).to_string(),
          segment:    i,
        });
      },
    }
  }

  Ok(current.clone())
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use crate::{
    extractor,
    parser::{
      predicate::{Comparison, PredicateType},
      test_utils::{
        assert_extraction_error, assert_extraction_success, create_extractor, create_json_config,
      },
      ExtractorType,
    },
    predicate,
  };

  mod basic_extraction {
    use super::*;

    #[test]
    fn simple_object_extraction() {
      let json_data = json!({
        "key1": {
          "key2": "value"
        }
      });

      let config = create_json_config(vec![extractor!(
        id: "simple".to_string(),
        selector: vec!["key1".to_string(), "key2".to_string()],
        extractor_type: ExtractorType::String
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_success(&result, &[("simple", &json!("value"))]);
    }

    #[test]
    fn array_extraction() {
      let json_data = json!({
        "key1": [
          {
            "key2": "value1"
          },
          {
            "key3": "value2"
          }
        ]
      });

      let config = create_json_config(vec![extractor!(
        id: "array_value".to_string(),
        selector: vec!["key1".to_string(), "1".to_string(), "key3".to_string()],
        extractor_type: ExtractorType::String
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_success(&result, &[("array_value", &json!("value2"))]);
    }
  }

  mod error_handling {
    use super::*;

    #[test]
    fn invalid_key() {
      let json_data = json!({
        "key1": {
          "key2": "value"
        }
      });

      let config = create_json_config(vec![create_extractor(
        "invalid_key",
        vec!["key1".to_string(), "invalid_key".to_string()],
        ExtractorType::String,
        vec![],
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_error(&result, 1, &["Key 'invalid_key' not found"]);
    }

    #[test]
    fn invalid_array_index() {
      let json_data = json!({
        "key1": [
          "value1",
          "value2"
        ]
      });

      let config = create_json_config(vec![create_extractor(
        "out_of_bounds",
        vec!["key1".to_string(), "3".to_string()],
        ExtractorType::String,
        vec![],
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_error(&result, 1, &["Array index 3 out of bounds"]);
    }

    #[test]
    fn index_on_non_array() {
      let json_data = json!({
        "key1": {
          "key2": "value"
        }
      });

      let config = create_json_config(vec![create_extractor(
        "non_array_index",
        vec!["key1".to_string(), "0".to_string()],
        ExtractorType::String,
        vec![],
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_error(&result, 1, &["Key '0' not found"]);
    }

    #[test]
    fn empty_path() {
      let json_data = json!({
        "key1": {
          "key2": {
            "key3": "value"
          }
        }
      });

      let config = create_json_config(vec![extractor!(
        id: "empty_path".to_string(),
        selector: vec![],
        extractor_type: ExtractorType::Object
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_error(&result, 1, &["Empty selector path"]);
    }

    #[test]
    fn empty_body() {
      let json_data = json!({});
      let config = create_json_config(vec![extractor!(
        id: "empty_body".to_string(),
        selector: vec!["key1".to_string()],
        extractor_type: ExtractorType::String
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_error(&result, 1, &["Key 'key1' not found"]);
    }
  }

  mod complex_structures {
    use super::*;

    #[test]
    fn nested_arrays() {
      let json_data = json!({
        "data": [
          [1, 2, 3],
          [4, 5, 6]
        ]
      });

      let config = create_json_config(vec![extractor!(
        id: "nested_array_value".to_string(),
        selector: vec!["data".to_string(), "1".to_string(), "1".to_string()],
        extractor_type: ExtractorType::Number,
        predicates: vec![predicate!(
          predicate_type: PredicateType::Value,
          comparison: Comparison::Equal,
          value: json!(5)
        )]
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_success(&result, &[("nested_array_value", &json!(5))]);
    }

    #[test]
    fn mixed_types_in_array() {
      let json_data = json!({
        "mixed": [
          42,
          "string",
          { "key": "value" },
          [1, 2, 3]
        ]
      });

      let config = create_json_config(vec![
        extractor!(
          id: "number_value".to_string(),
          selector: vec!["mixed".to_string(), "0".to_string()],
          extractor_type: ExtractorType::Number
        ),
        extractor!(
          id: "string_value".to_string(),
          selector: vec!["mixed".to_string(), "1".to_string()],
          extractor_type: ExtractorType::String
        ),
        extractor!(
          id: "object_value".to_string(),
          selector: vec!["mixed".to_string(), "2".to_string(), "key".to_string()],
          extractor_type: ExtractorType::String
        ),
      ]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_success(&result, &[
        ("number_value", &json!(42)),
        ("string_value", &json!("string")),
        ("object_value", &json!("value")),
      ]);
    }
  }

  mod edge_cases {
    use super::*;

    #[test]
    fn empty_string_keys_and_values() {
      let json_data = json!({
        "": {
          "empty": ""
        }
      });

      let config = create_json_config(vec![extractor!(
        id: "empty_key_value".to_string(),
        selector: vec!["".to_string(), "empty".to_string()],
        extractor_type: ExtractorType::String,
        predicates: vec![predicate!(
          predicate_type: PredicateType::Value,
          comparison: Comparison::Equal,
          value: json!("")
        )]
      )]);

      let result = config.extract_and_validate(&json_data).unwrap();
      assert_extraction_success(&result, &[("empty_key_value", &json!(""))]);
    }

    #[test]
    fn null_values() {
      let json_data = json!({
        "nullable_field": null,
        "valid_field": "value"
      });

      let config = create_json_config(vec![
        extractor!(
          id: "null_value".to_string(),
          selector: vec!["nullable_field".to_string()],
          extractor_type: ExtractorType::String
        ),
        extractor!(
          id: "valid_value".to_string(),
          selector: vec!["valid_field".to_string()],
          extractor_type: ExtractorType::String
        ),
      ]);

      let result = config.extract_and_validate(&json_data).unwrap();
      // The null value should cause an error, but the valid value should be extracted
      assert_eq!(result.errors.len(), 1);
      assert_eq!(result.values.len(), 1);
      assert!(result.values.contains_key("valid_value"));
    }
  }

  #[test]
  fn test_nesting_depth() {
    // Test different nesting depths
    for depth in [5, 25, 100] {
      // Build nested JSON structure
      let mut json_value = json!("deep_value");
      for i in (0..depth).rev() {
        json_value = json!({
            format!("level{}", i): json_value
        });
      }

      // Build the selector path
      let mut selector = Vec::new();
      for i in 0..depth {
        selector.push(format!("level{}", i));
      }

      // Create extractor config
      let config = create_json_config(vec![extractor!(
        id: "deep_value".to_string(),
        selector: selector,
        extractor_type: ExtractorType::String,
        predicates: vec![predicate!(
          predicate_type: PredicateType::Value,
          comparison: Comparison::Equal,
          value: json!("deep_value")
        )]
      )]);

      // Test extraction
      let result = config.extract_and_validate(&json_value).unwrap();
      assert_extraction_success(&result, &[("deep_value", &json!("deep_value"))]);
    }
  }
}
