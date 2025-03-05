use serde_json::Value;

use super::types::{DocumentExtractor, ExtractedValue, ExtractionResult, RawDocument};
use crate::parser::{errors::ExtractorError, DataFormat, Extractor, ExtractorConfig};

/// Helper function to get the type of serde_json::Value as a string
pub fn get_value_type(value: &Value) -> &'static str {
  match value {
    Value::Null => "null",
    Value::Bool(_) => "boolean",
    Value::Number(_) => "number",
    Value::String(_) => "string",
    Value::Array(_) => "array",
    Value::Object(_) => "object",
  }
}

pub struct RawJsonHandle {
  json: Value,
}

impl RawDocument for RawJsonHandle {
  fn extract_value(&self, extractor: &Extractor) -> Result<ExtractedValue, ExtractorError> {
    extract_json_value(&self.json, &extractor.selector).map(ExtractedValue::Json)
  }

  fn validate_format(&self, format: &DataFormat) -> Result<(), ExtractorError> {
    if *format != DataFormat::Json {
      return Err(ExtractorError::InvalidFormat(format!("Expected JSON format, got {}", format)));
    }
    Ok(())
  }
}

pub struct JsonDocumentExtractor;

impl DocumentExtractor for JsonDocumentExtractor {
  fn validate_input(&self, data: &Value) -> Result<(), ExtractorError> {
    if !matches!(data, Value::Object(_) | Value::Array(_)) {
      return Err(ExtractorError::TypeMismatch {
        expected: "object or array".to_string(),
        actual:   get_value_type(data).to_string(),
      });
    }
    Ok(())
  }

  fn extract(
    &self,
    data: &Value,
    config: &ExtractorConfig,
  ) -> Result<ExtractionResult, ExtractorError> {
    extract_json(data, config)
  }
}

/// Extracts data from a JSON value using the provided extractor configuration
pub fn extract_json(
  json: &Value,
  config: &ExtractorConfig,
) -> Result<ExtractionResult, ExtractorError> {
  let handle = RawJsonHandle { json: json.clone() };
  handle.validate_format(&config.format)?;

  let mut result = ExtractionResult::default();
  for extractor in &config.extractors {
    let value = handle.extract_value(&extractor);
    result.process_extraction(value, extractor);
  }

  Ok(result)
}

/// Extracts a value from a JSON object using a path selector
fn extract_json_value(json: &Value, path: &[String]) -> Result<Value, ExtractorError> {
  if path.is_empty() {
    return Err(ExtractorError::EmptySelector);
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
      test_utils::{assert_extraction_error, assert_extraction_success, create_json_config},
      ExtractorType,
    },
    predicate,
  };

  mod basic_extraction {
    use super::*;
    use crate::parser::ExtractorType;

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
    use crate::parser::ExtractorType;

    #[test]
    fn invalid_key() {
      let json_data = json!({
        "key1": {
          "key2": "value"
        }
      });

      let config = create_json_config(vec![extractor!(
        id: "invalid_key".to_string(),
        selector: vec!["key1".to_string(), "invalid_key".to_string()],
        extractor_type: ExtractorType::String,
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

      let config = create_json_config(vec![extractor!(
        id: "out_of_bounds".to_string(),
        selector: vec!["key1".to_string(), "3".to_string()],
        extractor_type: ExtractorType::String,
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

      let config = create_json_config(vec![extractor!(
        id: "non_array_index".to_string(),
        selector: vec!["key1".to_string(), "0".to_string()],
        extractor_type: ExtractorType::String,
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
      assert_extraction_error(&result, 1, &["Empty selector"]);
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
    use crate::parser::ExtractorType;

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
