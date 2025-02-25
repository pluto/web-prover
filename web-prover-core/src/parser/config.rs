use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::parser::{errors::ExtractorError, extractor, extractor::ExtractionResult, Extractor};

/// The format of the data to extract from
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DataFormat {
  /// JSON format
  #[default]
  Json,
}

/// The root configuration for data extractors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ExtractorConfig {
  /// The format of the data to extract from
  pub format:     DataFormat,
  /// The list of extractors
  pub extractors: Vec<Extractor>,
}

impl ExtractorConfig {
  /// Extracts and validates data using this extractor configuration
  pub fn extract_and_validate(&self, data: &Value) -> Result<ExtractionResult, ExtractorError> {
    match self.format {
      DataFormat::Json => extractor::extract_json(data, self),
    }
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::parser::{
    extractor::{Extractor, ExtractorType},
    predicate::{Comparison, PredicateType},
    test_utils::{active_extractor, age_extractor, name_extractor, tags_extractor},
  };

  #[test]
  fn test_extract_and_validate_json() {
    let json_data = json!({
        "user": {
            "name": "John Doe",
            "age": 30,
            "active": true,
            "tags": ["developer", "rust"]
        }
    });
    let config = ExtractorConfig {
      format:     DataFormat::Json,
      extractors: vec![name_extractor(), age_extractor(), active_extractor(), tags_extractor()],
    };

    let result = config.extract_and_validate(&json_data).unwrap();
    assert_eq!(result.errors.len(), 0);
    assert_eq!(result.values.len(), 4);
    assert_eq!(result.values.get("userName"), Some(&json!("John Doe")));
    assert_eq!(result.values.get("userAge"), Some(&json!(30)));
    assert_eq!(result.values.get("userActive"), Some(&json!(true)));
    assert_eq!(result.values.get("userTags"), Some(&json!(["developer", "rust"])));
  }

  #[test]
  fn test_extract_and_validate_with_failures() {
    let json_data = json!({
        "user": {
            "name": "Jo", // Too short
            "age": 15,    // Too young
            "active": false,
            "tags": []    // Empty array
        }
    });
    let config = ExtractorConfig {
      format:     DataFormat::Json,
      extractors: vec![name_extractor(), age_extractor(), active_extractor(), tags_extractor()],
    };

    let result = config.extract_and_validate(&json_data).unwrap();
    assert_eq!(result.errors.len(), 4);

    // Check that each error message contains the expected information
    assert!(result.errors.iter().any(|e| e.contains("userName") && e.contains("Length")));
    assert!(result.errors.iter().any(|e| e.contains("userAge") && e.contains("18")));
    assert!(result.errors.iter().any(|e| e.contains("userActive") && e.contains("true")));
    assert!(result.errors.iter().any(|e| e.contains("userTags") && e.contains("Length")));

    // No values should be extracted due to validation failures
    assert_eq!(result.values.len(), 0);
  }

  #[test]
  fn test_extract_and_validate_with_optional_fields() {
    let json_data = json!({
        "user": {
            "name": "John Doe"
            // Missing age and active fields
        }
    });
    let config = ExtractorConfig {
      format:     DataFormat::Json,
      extractors: vec![
        name_extractor(),
        Extractor {
          id:             "userAge".to_string(),
          description:    "Extract user's age".to_string(),
          selector:       vec!["user".to_string(), "age".to_string()],
          extractor_type: ExtractorType::Number,
          required:       false, // Optional
          predicates:     vec![],
        },
        Extractor {
          id:             "userActive".to_string(),
          description:    "Extract user's active status".to_string(),
          selector:       vec!["user".to_string(), "active".to_string()],
          extractor_type: ExtractorType::Boolean,
          required:       false, // Optional
          predicates:     vec![],
        },
      ],
    };

    let result = config.extract_and_validate(&json_data).unwrap();
    assert_eq!(result.errors.len(), 0);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values.get("userName"), Some(&json!("John Doe")));
    assert_eq!(result.values.get("userAge"), None);
    assert_eq!(result.values.get("userActive"), None);
  }

  #[test]
  fn test_extractor_config_serialization() {
    let config = ExtractorConfig {
      format:     DataFormat::Json,
      extractors: vec![name_extractor(), age_extractor()],
    };

    // Serialize and deserialize the config
    let serialized_str = serde_json::to_string(&config).unwrap();
    let deserialized: ExtractorConfig = serde_json::from_str(&serialized_str).unwrap();
    assert_eq!(config, deserialized);

    // Verify basic properties
    assert_eq!(deserialized.format, DataFormat::Json);
    assert_eq!(deserialized.extractors.len(), 2);

    let extractor1 = &deserialized.extractors[0];
    assert_eq!(extractor1.id, "userName");
    assert_eq!(extractor1.description, "Extract user's name");
    assert_eq!(extractor1.selector, vec!["user", "name"]);
    assert_eq!(extractor1.extractor_type, ExtractorType::String);
    assert_eq!(extractor1.required, true);
    assert_eq!(extractor1.predicates.len(), 1);

    let predicate1 = &extractor1.predicates[0];
    assert_eq!(predicate1.predicate_type, PredicateType::Length);
    assert_eq!(predicate1.comparison, Comparison::GreaterThan);
    assert_eq!(predicate1.value, json!(3));

    let extractor2 = &deserialized.extractors[1];
    assert_eq!(extractor2.id, "userAge");
    assert_eq!(extractor2.description, "Extract user's age");
    assert_eq!(extractor2.selector, vec!["user", "age"]);
    assert_eq!(extractor2.extractor_type, ExtractorType::Number);
    assert_eq!(extractor2.required, true);
    assert_eq!(extractor2.predicates.len(), 1);

    let predicate2 = &extractor2.predicates[0];
    assert_eq!(predicate2.predicate_type, PredicateType::Value);
    assert_eq!(predicate2.comparison, Comparison::GreaterThanOrEqual);
    assert_eq!(predicate2.value, json!(18));
  }

  #[test]
  fn test_extractor_config_serialization_from_string() {
    let config =
      ExtractorConfig { format: DataFormat::Json, extractors: vec![age_extractor()] };

    // Serialize to JSON and then deserialize back
    let json_str = serde_json::to_string_pretty(&config).unwrap();
    let deserialized: ExtractorConfig = serde_json::from_str(&json_str).unwrap();
    assert_eq!(config, deserialized);

    // Deserialize from a JSON string
    let str_config = r#"
    {
        "format": "json",
        "extractors": [
            {
                "id": "userAge",
                "description": "Extract user's age",
                "selector": ["user", "age"],
                "type": "number",
                "required": true,
                "predicates": [
                    {
                        "type": "value",
                        "comparison": "greaterThanOrEqual",
                        "value": 18
                    }
                ]
            }
        ]
    }
    "#;
    let deserialized: ExtractorConfig = serde_json::from_str(str_config).unwrap();
    assert_eq!(deserialized.format, DataFormat::Json);
    assert_eq!(deserialized.extractors.len(), 1);

    let extractor = &deserialized.extractors[0];
    assert_eq!(extractor.id, "userAge");
    assert_eq!(extractor.selector, vec!["user", "age"]);
    assert_eq!(extractor.extractor_type, ExtractorType::Number);

    let predicate = &extractor.predicates[0];
    assert_eq!(predicate.predicate_type, PredicateType::Value);
    assert_eq!(predicate.comparison, Comparison::GreaterThanOrEqual);
    assert_eq!(predicate.value, json!(18));
  }
}
