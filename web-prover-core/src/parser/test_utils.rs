use serde_json::{json, Value};

use crate::parser::{
  extractor::ExtractionResult,
  predicate::{Comparison, PredicateType},
  DataFormat, Extractor, ExtractorConfig, ExtractorType,
};

pub fn create_json_config(extractors: Vec<Extractor>) -> ExtractorConfig {
  ExtractorConfig { format: DataFormat::Json, extractors }
}

#[macro_export]
/// Creates a new Extractor with optional parameters.
macro_rules! extractor {
    // Match with optional parameters
    ($($key:ident: $value:expr),* $(,)?) => {{
        let mut extractor = crate::parser::Extractor {
            id: String::new(),
            description: String::new(),
            selector: Vec::new(),
            extractor_type: crate::parser::ExtractorType::String,
            required: true,
            predicates: Vec::new(),
            attribute: None,
        };

        // Override default fields with provided arguments
        $(
            extractor.$key = $value;
        )*

        // If description is not provided but id is, generate a default description
        if extractor.description.is_empty() && !extractor.id.is_empty() {
            extractor.description = format!("Extract {}", extractor.id);
        }

        extractor
    }};
}

pub fn assert_extraction_success(result: &ExtractionResult, expected_values: &[(&str, &Value)]) {
  assert_eq!(result.errors.len(), 0, "Unexpected errors: {:?}", result.errors);
  for (key, value) in expected_values.iter().cloned() {
    assert_eq!(result.values.get(key), Some(value), "Value mismatch for key {}", key);
  }
}

pub fn assert_extraction_error(
  result: &ExtractionResult,
  expected_error_count: usize,
  error_substrings: &[&str],
) {
  assert_eq!(result.errors.len(), expected_error_count, "Error count mismatch");
  for substring in error_substrings {
    assert!(
      result.errors.iter().any(|e| e.contains(substring)),
      "Expected error containing '{}', got: {:?}",
      substring,
      result.errors
    );
  }
}

#[macro_export]
/// Creates a new Predicate with optional parameters.
macro_rules! predicate {
        // Match with optional parameters
        ($($key:ident: $value:expr),* $(,)?) => {{
            let mut predicate = crate::parser::predicate::Predicate {
                predicate_type: crate::parser::predicate::PredicateType::Value,
                comparison: crate::parser::predicate::Comparison::Equal,
                value: serde_json::Value::Null,
                case_sensitive: true,
                flags: None,
                nested_predicate: None,
                description: None,
            };

            // Override default fields with provided arguments
            $(
                predicate.$key = $value;
            )*

            predicate
        }};
    }

pub fn active_extractor() -> Extractor {
  extractor!(
    id: "userActive".to_string(),
    description: "Extract user's active status".to_string(),
    selector: vec!["user".to_string(), "active".to_string()],
    extractor_type: ExtractorType::Boolean,
    predicates: vec![predicate!(
      predicate_type: PredicateType::Value,
      comparison: Comparison::Equal,
      value: json!(true)
    )]
  )
}

pub fn age_extractor() -> Extractor {
  extractor!(
    id: "userAge".to_string(),
    description: "Extract user's age".to_string(),
    selector: vec!["user".to_string(), "age".to_string()],
    extractor_type: ExtractorType::Number,
    predicates: vec![predicate!(
      predicate_type: PredicateType::Value,
      comparison: Comparison::GreaterThanOrEqual,
      value: json!(18)
    )]
  )
}

pub fn name_extractor() -> Extractor {
  extractor!(
    id: "userName".to_string(),
    description: "Extract user's name".to_string(),
    selector: vec!["user".to_string(), "name".to_string()],
    extractor_type: ExtractorType::String,
    predicates: vec![predicate!(
      predicate_type: PredicateType::Length,
      comparison: Comparison::GreaterThan,
      value: json!(3)
    )]
  )
}

pub fn tags_extractor() -> Extractor {
  extractor!(
    id: "userTags".to_string(),
    description: "Extract user's tags".to_string(),
    selector: vec!["user".to_string(), "tags".to_string()],
    extractor_type: ExtractorType::Array,
    predicates: vec![predicate!(
      predicate_type: PredicateType::Length,
      comparison: Comparison::GreaterThanOrEqual,
      value: json!(1)
    )]
  )
}
