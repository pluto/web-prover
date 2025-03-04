//! # Extractor Module
//!
//! The `extractor` module provides functionality for extracting and validating data
//! from different formats (JSON, HTML) based on a configuration file.

use std::{collections::HashMap, fmt::Display};

use derive_more::TryFrom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tl::{ParserOptions, VDom};

use crate::parser::{
  common::get_value_type,
  config::{DataFormat, ExtractorConfig},
  errors::ExtractorError,
  predicate,
  predicate::Predicate,
};

/// The type of data being extracted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TryFrom)]
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
  /// HTML attribute to extract
  #[serde(skip_serializing_if = "Option::is_none")]
  pub attribute:      Option<String>,
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

/// Extracts data from HTML using CSS selectors
pub fn extract_html(
  html_str: &str,
  config: &ExtractorConfig,
) -> Result<ExtractionResult, ExtractorError> {
  if config.format != DataFormat::Html {
    return Err(ExtractorError::InvalidFormat("HTML".to_string()));
  }

  let mut result = ExtractionResult { values: HashMap::new(), errors: Vec::new() };

  // Parse the HTML document
  let dom = tl::parse(html_str, ParserOptions::default())
    .map_err(|_| ExtractorError::InvalidFormat("Failed to parse HTML".to_string()))?;

  for extractor in &config.extractors {
    match extract_html_value(&dom, &extractor.selector, extractor) {
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

/// Extracts a value from an HTML document using CSS selectors
pub fn extract_html_value(
  dom: &VDom,
  selector_path: &[String],
  extractor: &Extractor,
) -> Result<Value, ExtractorError> {
  if selector_path.is_empty() {
    return Err(ExtractorError::MissingField("Empty selector path".to_string()));
  }

  // If there's only one selector, use the existing approach
  if selector_path.len() == 1 {
    return extract_with_single_selector(dom, &selector_path[0], extractor);
  }

  // For multiple selectors, we need to traverse the DOM
  // First, apply the first selector to get initial elements
  let first_selector = &selector_path[0];
  let initial_elements = match dom.query_selector(first_selector) {
    Some(matches) => {
      let elements = matches.collect::<Vec<_>>();
      if elements.is_empty() {
        return Err(ExtractorError::MissingField(format!(
          "No elements found for selector '{}'",
          first_selector
        )));
      }
      elements
    }
    None => {
      return Err(ExtractorError::InvalidPath(format!(
        "Invalid selector '{}'",
        first_selector
      )));
    }
  };

  // For each subsequent selector, apply it to the results of the previous selector
  let mut current_elements = initial_elements;
  let parser = dom.parser();

  for (i, selector) in selector_path.iter().enumerate().skip(1) {
    let mut next_elements = Vec::new();

    for element in &current_elements {
      if let Some(node) = element.get(parser) {
        if let Some(tag) = node.as_tag() {
          // Apply the next selector to this element
          if let Some(matches) = tag.query_selector(parser, selector) {
            let matches = matches.collect::<Vec<_>>();
            if !matches.is_empty() {
              next_elements.extend(matches);
              continue;
            }
          }
        }
      }
    }

    if next_elements.is_empty() {
      return Err(ExtractorError::MissingField(format!(
        "No elements found for selector '{}' at position {} in selector path",
        selector, i + 1
      )));
    }

    current_elements = next_elements;
  }

  // Now we have the final set of elements, process them based on extractor type
  if extractor.extractor_type == ExtractorType::Array {
    let values: Vec<Value> = current_elements
      .iter()
      .filter_map(|el| {
        el.get(parser).map(|node| {
          if let Some(attr) = &extractor.attribute {
            if let Some(tag) = node.as_tag() {
              if let Some(attr_value) = tag.attributes().get(attr.as_str()) {
                if let Some(value) = attr_value {
                  return Value::String(value.as_utf8_str().to_string());
                }
              }
            }
            Value::String("".to_string()) // Return empty string if attribute not found
          } else {
            Value::String(node.inner_text(parser).to_string())
          }
        })
      })
      .collect();
    return Ok(Value::Array(values));
  }

  // For non-array types, use the first element
  let element = &current_elements[0];

  // Extract the raw value (either attribute or text content)
  let raw_value = if let Some(attr) = &extractor.attribute {
    if let Some(node) = element.get(parser) {
      if let Some(tag) = node.as_tag() {
        if let Some(attr_value) = tag.attributes().get(attr.as_str()) {
          if let Some(value) = attr_value {
            value.as_utf8_str().to_string()
          } else {
            "".to_string()
          }
        } else {
          "".to_string()
        }
      } else {
        "".to_string()
      }
    } else {
      "".to_string()
    }
  } else if let Some(node) = element.get(parser) {
    node.inner_text(parser).to_string()
  } else {
    "".to_string()
  };

  // Convert the raw value to the appropriate type
  match extractor.extractor_type {
    ExtractorType::String => Ok(Value::String(raw_value)),
    ExtractorType::Number =>
      if let Ok(num) = raw_value.parse::<f64>() {
        Ok(Value::Number(serde_json::Number::from_f64(num).unwrap_or(serde_json::Number::from(0))))
      } else {
        Err(ExtractorError::TypeMismatch {
          expected: "number".to_string(),
          actual:   "string".to_string(),
        })
      },
    ExtractorType::Boolean =>
      if let Ok(b) = raw_value.parse::<bool>() {
        Ok(Value::Bool(b))
      } else {
        Err(ExtractorError::TypeMismatch {
          expected: "boolean".to_string(),
          actual:   "string".to_string(),
        })
      },
    _ => Err(ExtractorError::TypeMismatch {
      expected: format!("{}", extractor.extractor_type),
      actual:   "string".to_string(),
    }),
  }
}

/// Helper function to extract values using a single selector
fn extract_with_single_selector(
  dom: &VDom,
  selector: &str,
  extractor: &Extractor,
) -> Result<Value, ExtractorError> {
  // Query with the single selector
  let elements = match dom.query_selector(selector) {
    Some(matches) => {
      let elements = matches.collect::<Vec<_>>();
      if elements.is_empty() {
        return Err(ExtractorError::MissingField(format!(
          "No elements found for selector '{}'",
          selector
        )));
      }
      elements
    }
    None => {
      return Err(ExtractorError::InvalidPath(format!(
        "Invalid selector '{}'",
        selector
      )));
    }
  };

  // Handle array type specially
  if extractor.extractor_type == ExtractorType::Array {
    let values: Vec<Value> = elements
      .iter()
      .filter_map(|el| {
        el.get(dom.parser()).map(|node| {
          if let Some(attr) = &extractor.attribute {
            if let Some(tag) = node.as_tag() {
              if let Some(attr_value) = tag.attributes().get(attr.as_str()) {
                if let Some(value) = attr_value {
                  return Value::String(value.as_utf8_str().to_string());
                }
              }
            }
            Value::String("".to_string()) // Return empty string if attribute not found
          } else {
            Value::String(node.inner_text(dom.parser()).to_string())
          }
        })
      })
      .collect();
    return Ok(Value::Array(values));
  }

  // For non-array types, use the first element
  let element = &elements[0];

  // Extract the raw value (either attribute or text content)
  let raw_value = if let Some(attr) = &extractor.attribute {
    if let Some(node) = element.get(dom.parser()) {
      if let Some(tag) = node.as_tag() {
        if let Some(attr_value) = tag.attributes().get(attr.as_str()) {
          if let Some(value) = attr_value {
            value.as_utf8_str().to_string()
          } else {
            "".to_string()
          }
        } else {
          "".to_string()
        }
      } else {
        "".to_string()
      }
    } else {
      "".to_string()
    }
  } else if let Some(node) = element.get(dom.parser()) {
    node.inner_text(dom.parser()).to_string()
  } else {
    "".to_string()
  };

  // Convert the raw value to the appropriate type
  match extractor.extractor_type {
    ExtractorType::String => Ok(Value::String(raw_value)),
    ExtractorType::Number =>
      if let Ok(num) = raw_value.parse::<f64>() {
        Ok(Value::Number(serde_json::Number::from_f64(num).unwrap_or(serde_json::Number::from(0))))
      } else {
        Err(ExtractorError::TypeMismatch {
          expected: "number".to_string(),
          actual:   "string".to_string(),
        })
      },
    ExtractorType::Boolean =>
      if let Ok(b) = raw_value.parse::<bool>() {
        Ok(Value::Bool(b))
      } else {
        Err(ExtractorError::TypeMismatch {
          expected: "boolean".to_string(),
          actual:   "string".to_string(),
        })
      },
    _ => Err(ExtractorError::TypeMismatch {
      expected: format!("{}", extractor.extractor_type),
      actual:   "string".to_string(),
    }),
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use crate::{
    extractor,
    parser::{
      predicate::{Comparison, PredicateType},
      test_utils::{assert_extraction_success, create_json_config},
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
    use crate::parser::test_utils::assert_extraction_error;

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

  mod html_extraction {
    use serde_json::json;
    use tl::{ParserOptions, VDom};

    use super::*;
    use crate::parser::{
      extractor::{extract_html, extract_html_value},
      DataFormat, ExtractorConfig, ExtractorError,
    };

    fn create_test_html() -> String {
      r#"
        <!DOCTYPE html>
        <html>
        <head>
          <title>Test Page</title>
          <meta name="description" content="A test page for HTML extraction">
        </head>
        <body>
          <div class="container">
            <header>
              <h1 id="main-title">Hello, World!</h1>
              <nav>
                <ul>
                  <li><a href="/">Home</a></li>
                  <li><a href="/about">About</a></li>
                  <li><a href="/contact">Contact</a></li>
                </ul>
              </nav>
            </header>
            <main>
              <section class="content">
                <article>
                  <h2>Article Title</h2>
                  <p class="summary">This is a summary of the article.</p>
                  <div class="tags">
                    <span>tag1</span>
                    <span>tag2</span>
                    <span>tag3</span>
                  </div>
                </article>
              </section>
              <aside>
                <div class="widget">
                  <h3>Related Links</h3>
                  <ul>
                    <li><a href="/link1">Link 1</a></li>
                    <li><a href="/link2">Link 2</a></li>
                  </ul>
                </div>
              </aside>
            </main>
            <footer>
              <p>&copy; 2023 Test Company</p>
            </footer>
          </div>
        </body>
        </html>
      "#
      .to_string()
    }

    fn parse_test_html(html: &str) -> VDom {
      tl::parse(html, ParserOptions::default()).expect("Failed to parse HTML")
    }

    #[test]
    fn test_html_extract_basic_text() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      let extractor = extractor!(
          id: "title".to_string(),
          description: "Main title".to_string(),
          selector: vec!["#main-title".to_string()],
          extractor_type: ExtractorType::String
      );
      let result = extract_html_value(&dom, &["#main-title".to_string()], &extractor).unwrap();
      assert_eq!(result, json!("Hello, World!"));
    }

    #[test]
    fn test_html_extraction_errors() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      let basic_extractor = extractor!(
        id: "test".to_string(),
        description: "Test extractor".to_string(),
        extractor_type: ExtractorType::String
      );

      // Test invalid CSS selector
      let result = extract_html_value(&dom, &["#[invalid".to_string()], &basic_extractor);
      assert!(result.is_err());
      assert!(matches!(result, Err(ExtractorError::InvalidPath(_))));

      // Test non-existent element
      let result = extract_html_value(&dom, &["#non-existent".to_string()], &basic_extractor);
      assert!(result.is_err());
      assert!(matches!(result, Err(ExtractorError::MissingField(_))));

      // Test empty selector path
      let result = extract_html_value(&dom, &[], &basic_extractor);
      assert!(result.is_err());
      assert!(matches!(result, Err(ExtractorError::MissingField(_))));

      // Test attribute extraction error
      let attr_extractor = extractor!(
        id: "test".to_string(),
        description: "Test extractor".to_string(),
        selector: vec!["#main-title".to_string()],
        extractor_type: ExtractorType::String,
        attribute: Some("non-existent".to_string())
      );
      let result = extract_html_value(&dom, &["#main-title".to_string()], &attr_extractor);
      // With our new implementation, missing attributes return an empty string instead of an error
      assert!(result.is_ok());
      assert_eq!(result.unwrap(), json!(""));
    }

    #[test]
    fn test_extract_html_function() {
      let html = create_test_html();

      let config = ExtractorConfig {
        format:     DataFormat::Html,
        extractors: vec![
          extractor!(
            id: "title".to_string(),
            description: "Main title".to_string(),
            selector: vec!["#main-title".to_string()],
            extractor_type: ExtractorType::String
          ),
          extractor!(
            id: "nav_links".to_string(),
            description: "Navigation links".to_string(),
            selector: vec!["a".to_string()],
            extractor_type: ExtractorType::Array
          ),
          extractor!(
            id: "missing".to_string(),
            description: "Missing element".to_string(),
            selector: vec!["#non-existent".to_string()],
            extractor_type: ExtractorType::String,
            required: false
          ),
        ],
      };

      let result = extract_html(&html, &config).unwrap();

      assert_eq!(result.errors.len(), 0);
      assert_eq!(result.values.len(), 2);

      assert_eq!(result.values["title"], json!("Hello, World!"));
      // Check that nav_links contains the expected values
      let nav_links = result.values["nav_links"].as_array().unwrap();
      assert!(nav_links.contains(&json!("Home")));
      assert!(nav_links.contains(&json!("About")));
      assert!(nav_links.contains(&json!("Contact")));
      assert!(!result.values.contains_key("missing"));
    }

    #[test]
    fn test_html_extract_meta_attribute() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      let extractor = extractor!(
          id: "description".to_string(),
          description: "Meta description".to_string(),
          selector: vec!["meta[name=description]".to_string()],
          extractor_type: ExtractorType::String,
          attribute: Some("content".to_string())
      );
      let result =
        extract_html_value(&dom, &["meta[name=description]".to_string()], &extractor).unwrap();
      assert_eq!(result, json!("A test page for HTML extraction"));
    }

    #[test]
    fn test_html_extract_tags_array() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      let extractor = extractor!(
          id: "tags".to_string(),
          description: "Tag list".to_string(),
          selector: vec!["span".to_string()],
          extractor_type: ExtractorType::Array
      );
      let result = extract_html_value(&dom, &["span".to_string()], &extractor).unwrap();
      assert_eq!(result, json!(["tag1", "tag2", "tag3"]));
    }

    #[test]
    fn test_html_extract_nav_links() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      let extractor = extractor!(
          id: "nav_links".to_string(),
          description: "Navigation links".to_string(),
          selector: vec!["a".to_string()],
          extractor_type: ExtractorType::Array
      );

      let result = extract_html_value(&dom, &["a".to_string()], &extractor).unwrap();
      // Since we're selecting all 'a' elements, we'll get all links in the document
      assert!(result.as_array().unwrap().contains(&json!("Home")));
      assert!(result.as_array().unwrap().contains(&json!("About")));
      assert!(result.as_array().unwrap().contains(&json!("Contact")));
    }

    #[test]
    fn test_html_extract_href_attributes() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      // Test with a selector that targets all links
      let extractor = extractor!(
          id: "all_links".to_string(),
          description: "All link href attributes".to_string(),
          selector: vec!["a".to_string()],
          extractor_type: ExtractorType::Array,
          attribute: Some("href".to_string())
      );
      
      let result = extract_html_value(&dom, &["a".to_string()], &extractor).unwrap();
      
      // Since we're getting all href attributes, we should verify that our expected values are included
      let hrefs = result.as_array().unwrap();
      assert!(hrefs.contains(&json!("/")));
      assert!(hrefs.contains(&json!("/about")));
      assert!(hrefs.contains(&json!("/contact")));

      // Test with nested selectors to get links in the nav
      let extractor = extractor!(
          id: "nav_links".to_string(),
          description: "Navigation link href attributes".to_string(),
          selector: vec!["nav".to_string(), "a".to_string()],
          extractor_type: ExtractorType::Array,
          attribute: Some("href".to_string())
      );
      
      let result = extract_html_value(
        &dom,
        &["nav".to_string(), "a".to_string()],
        &extractor,
      ).unwrap();
      
      // Verify we get the same links
      let hrefs = result.as_array().unwrap();
      assert!(hrefs.contains(&json!("/")));
      assert!(hrefs.contains(&json!("/about")));
      assert!(hrefs.contains(&json!("/contact")));
    }

    #[test]
    fn test_html_extract_nested_structure() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      // Test with a string type instead of object type
      let extractor = extractor!(
          id: "article_content".to_string(),
          description: "Article content structure".to_string(),
          selector: vec!["article".to_string()],
          extractor_type: ExtractorType::String
      );
      let result = extract_html_value(&dom, &["article".to_string()], &extractor).unwrap();

      // Verify the content contains both the title and summary
      let content = result.as_str().unwrap();
      assert!(content.contains("Article Title"));
      assert!(content.contains("This is a summary of the article"));
    }

    #[test]
    fn test_html_extract_with_multiple_selectors() {
      let html = create_test_html();

      // Test with multiple extractors, including one with multiple selectors in the path
      let config = ExtractorConfig {
        format:     DataFormat::Html,
        extractors: vec![
          extractor!(
              id: "page_info".to_string(),
              description: "Page title and description".to_string(),
              selector: vec!["title".to_string()],
              extractor_type: ExtractorType::Array
          ),
          extractor!(
              id: "all_headings".to_string(),
              description: "All heading elements".to_string(),
              selector: vec!["h1, h2, h3".to_string()],
              extractor_type: ExtractorType::Array
          ),
          extractor!(
              id: "article_summary".to_string(),
              description: "Article summary using nested selectors".to_string(),
              selector: vec!["article".to_string(), "p.summary".to_string()],
              extractor_type: ExtractorType::String
          ),
          extractor!(
              id: "tags".to_string(),
              description: "Article tags using nested selectors".to_string(),
              selector: vec!["article".to_string(), "div.tags".to_string(), "span".to_string()],
              extractor_type: ExtractorType::Array
          ),
        ],
      };

      let result = extract_html(&html, &config).unwrap();

      // Check page info contains title
      let page_info = result.values["page_info"].as_array().unwrap();
      assert!(page_info.contains(&json!("Test Page")));

      // Check all headings are extracted
      let headings = result.values["all_headings"].as_array().unwrap();
      assert!(headings.contains(&json!("Hello, World!")));
      assert!(headings.contains(&json!("Article Title")));
      assert!(headings.contains(&json!("Related Links")));

      // Check article summary is extracted using nested selectors
      assert_eq!(result.values["article_summary"], json!("This is a summary of the article."));

      // Check tags are extracted using nested selectors
      let tags = result.values["tags"].as_array().unwrap();
      assert_eq!(tags.len(), 3);
      assert!(tags.contains(&json!("tag1")));
      assert!(tags.contains(&json!("tag2")));
      assert!(tags.contains(&json!("tag3")));
    }

    #[test]
    fn test_html_extract_with_complex_selectors() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      // Test with multiple selectors instead of a complex single selector
      let extractor = extractor!(
          id: "multi_part_select".to_string(),
          description: "Multi-part selector test".to_string(),
          selector: vec!["main".to_string(), "section.content".to_string(), "article".to_string(), "p.summary".to_string()],
          extractor_type: ExtractorType::String
      );
      
      let result = extract_html_value(
        &dom,
        &["main".to_string(), "section.content".to_string(), "article".to_string(), "p.summary".to_string()],
        &extractor,
      );
      
      assert!(result.is_ok());
      assert_eq!(result.unwrap(), json!("This is a summary of the article."));
    }

    #[test]
    fn test_html_extract_with_numeric_conversion() {
      let html = r#"
            <!DOCTYPE html>
            <html>
            <body>
                <div class="stats">
                    <span class="count">42</span>
                    <span class="price">99.99</span>
                    <span class="invalid">not a number</span>
                </div>
            </body>
            </html>
        "#;
      let dom = parse_test_html(html);

      // Test integer extraction
      let extractor = extractor!(
          id: "count".to_string(),
          description: "Numeric count".to_string(),
          selector: vec![".count".to_string()],
          extractor_type: ExtractorType::Number
      );
      let result = extract_html_value(&dom, &[".count".to_string()], &extractor).unwrap();
      assert_eq!(result, json!(42.0));

      // Test float extraction
      let price_extractor = extractor!(
          id: "price".to_string(),
          description: "Price value".to_string(),
          selector: vec![".price".to_string()],
          extractor_type: ExtractorType::Number
      );
      let result = extract_html_value(&dom, &[".price".to_string()], &price_extractor).unwrap();
      assert_eq!(result, json!(99.99));

      // Test invalid number conversion
      let invalid_extractor = extractor!(
          id: "invalid".to_string(),
          description: "Invalid number".to_string(),
          selector: vec![".invalid".to_string()],
          extractor_type: ExtractorType::Number
      );
      let result = extract_html_value(&dom, &[".invalid".to_string()], &invalid_extractor);
      assert!(result.is_err());
    }

    #[test]
    fn test_html_extract_boolean_conversion() {
      let html = r#"
            <!DOCTYPE html>
            <html>
            <body>
                <div class="flags">
                    <span class="true-value">true</span>
                    <span class="false-value">false</span>
                    <span class="invalid-bool">not a boolean</span>
                </div>
            </body>
            </html>
        "#;
      let dom = parse_test_html(html);

      let true_extractor = extractor!(
          id: "true_flag".to_string(),
          description: "True boolean value".to_string(),
          selector: vec![".true-value".to_string()],
          extractor_type: ExtractorType::Boolean
      );
      let result = extract_html_value(&dom, &[".true-value".to_string()], &true_extractor).unwrap();
      assert_eq!(result, json!(true));

      let false_extractor = extractor!(
          id: "false_flag".to_string(),
          description: "False boolean value".to_string(),
          selector: vec![".false-value".to_string()],
          extractor_type: ExtractorType::Boolean
      );
      let result =
        extract_html_value(&dom, &[".false-value".to_string()], &false_extractor).unwrap();
      assert_eq!(result, json!(false));

      let invalid_extractor = extractor!(
          id: "invalid_bool".to_string(),
          description: "Invalid boolean".to_string(),
          selector: vec![".invalid-bool".to_string()],
          extractor_type: ExtractorType::Boolean
      );
      let result = extract_html_value(&dom, &[".invalid-bool".to_string()], &invalid_extractor);
      assert!(result.is_err());
    }

    #[test]
    fn test_html_extract_with_nested_selectors() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      // Test with two selectors: first select the article, then select the summary paragraph within it
      let extractor = extractor!(
          id: "nested_select".to_string(),
          description: "Nested selector test".to_string(),
          selector: vec!["article".to_string(), "p.summary".to_string()],
          extractor_type: ExtractorType::String
      );
      
      let result = extract_html_value(
        &dom,
        &["article".to_string(), "p.summary".to_string()],
        &extractor,
      )
      .unwrap();
      
      assert_eq!(result, json!("This is a summary of the article."));

      // Test with three selectors: navigate down the DOM tree
      let extractor = extractor!(
          id: "deep_nested_select".to_string(),
          description: "Deep nested selector test".to_string(),
          selector: vec!["main".to_string(), "section.content".to_string(), "article".to_string()],
          extractor_type: ExtractorType::String
      );
      
      let result = extract_html_value(
        &dom,
        &["main".to_string(), "section.content".to_string(), "article".to_string()],
        &extractor,
      )
      .unwrap();
      
      // The article contains both the heading and summary
      assert!(result.as_str().unwrap().contains("Article Title"));
      assert!(result.as_str().unwrap().contains("This is a summary of the article"));

      // Test with array type to get all spans in the tags div
      let extractor = extractor!(
          id: "nested_array_select".to_string(),
          description: "Nested array selector test".to_string(),
          selector: vec!["article".to_string(), "div.tags".to_string(), "span".to_string()],
          extractor_type: ExtractorType::Array
      );
      
      let result = extract_html_value(
        &dom,
        &["article".to_string(), "div.tags".to_string(), "span".to_string()],
        &extractor,
      )
      .unwrap();
      
      let tags = result.as_array().unwrap();
      assert_eq!(tags.len(), 3);
      assert!(tags.contains(&json!("tag1")));
      assert!(tags.contains(&json!("tag2")));
      assert!(tags.contains(&json!("tag3")));
    }

    #[test]
    fn test_html_extract_with_invalid_nested_selector() {
      let html = create_test_html();
      let dom = parse_test_html(&html);

      // Test with a valid first selector but an invalid second selector
      let extractor = extractor!(
          id: "invalid_nested_select".to_string(),
          description: "Invalid nested selector test".to_string(),
          selector: vec!["article".to_string(), "non-existent-element".to_string()],
          extractor_type: ExtractorType::String
      );
      
      let result = extract_html_value(
        &dom,
        &["article".to_string(), "non-existent-element".to_string()],
        &extractor,
      );
      
      assert!(result.is_err());
      if let Err(err) = result {
        match err {
          ExtractorError::MissingField(msg) => {
            assert!(msg.contains("No elements found for selector 'non-existent-element'"));
            assert!(msg.contains("position 2"));
          },
          _ => panic!("Expected MissingField error, got: {:?}", err),
        }
      }

      // Test with an invalid first selector
      let extractor = extractor!(
          id: "invalid_first_selector".to_string(),
          description: "Invalid first selector test".to_string(),
          selector: vec!["non-existent-element".to_string(), "p".to_string()],
          extractor_type: ExtractorType::String
      );
      
      let result = extract_html_value(
        &dom,
        &["non-existent-element".to_string(), "p".to_string()],
        &extractor,
      );
      
      assert!(result.is_err());
      if let Err(err) = result {
        match err {
          ExtractorError::MissingField(msg) => {
            assert!(msg.contains("No elements found for selector 'non-existent-element'"));
          },
          _ => panic!("Expected MissingField error, got: {:?}", err),
        }
      }
    }
  }
}
