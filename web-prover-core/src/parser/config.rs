use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::parser::{
  errors::ExtractorError,
  extractors::{ExtractionResult, Extractor},
  format::{FormatExtractor, HtmlExtractor, JsonExtractor},
};

/// The format of the data to extract from
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DataFormat {
  /// JSON format
  #[default]
  Json,
  /// HTML format
  Html,
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
  pub fn extract_and_validate(&self, data: &Value) -> Result<ExtractionResult, ExtractorError> {
    let extractor: Box<dyn FormatExtractor> = match self.format {
      DataFormat::Json => Box::new(JsonExtractor),
      DataFormat::Html => Box::new(HtmlExtractor),
    };

    extractor.validate_input(data)?;
    extractor.extract(data, self)
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::{
    extractor,
    parser::{
      predicate::{Comparison, PredicateType},
      test_utils::{active_extractor, age_extractor, name_extractor, tags_extractor},
      ExtractorType,
    },
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
        extractor!(
            id: "userAge".to_string(),
            description: "Extract user's age".to_string(),
            selector: vec!["user".to_string(), "age".to_string()],
            extractor_type: ExtractorType::Number,
            required: false
        ),
        extractor!(
            id: "userActive".to_string(),
            description: "Extract user's active status".to_string(),
            selector: vec!["user".to_string(), "active".to_string()],
            extractor_type: ExtractorType::Boolean,
            required: false
        ),
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
    assert_eq!(extractor.required, true);

    let predicate = &extractor.predicates[0];
    assert_eq!(predicate.predicate_type, PredicateType::Value);
    assert_eq!(predicate.comparison, Comparison::GreaterThanOrEqual);
    assert_eq!(predicate.value, json!(18));
  }

  #[test]
  fn test_extract_and_validate_html() {
    let html = r#"
      <!DOCTYPE html>
      <html>
      <head>
        <title>Test Page</title>
      </head>
      <body>
        <div class="user-info">
          <h1 id="username">John Doe</h1>
          <p class="age">30</p>
          <p class="active">true</p>
          <ul class="tags">
            <li>developer</li>
            <li>rust</li>
            <li>web</li>
          </ul>
        </div>
        <a href="https://example.com" class="link">Visit Website</a>
      </body>
      </html>
    "#;

    let config = ExtractorConfig {
      format:     DataFormat::Html,
      extractors: vec![
        extractor!(
            id: "username".to_string(),
            description: "User's name".to_string(),
            selector: vec!["#username".to_string()],
            extractor_type: ExtractorType::String
        ),
        extractor!(
            id: "age".to_string(),
            description: "User's age".to_string(),
            selector: vec![".age".to_string()],
            extractor_type: ExtractorType::String
        ),
        extractor!(
            id: "active".to_string(),
            description: "User's active status".to_string(),
            selector: vec![".active".to_string()],
            extractor_type: ExtractorType::String
        ),
        extractor!(
            id: "tags".to_string(),
            description: "User's tags".to_string(),
            selector: vec!["li".to_string()],
            extractor_type: ExtractorType::Array
        ),
        extractor!(
            id: "link_href".to_string(),
            description: "Link URL".to_string(),
            selector: vec![".link".to_string()],
            attribute: Some("href".to_string()),
            extractor_type: ExtractorType::String
        ),
      ],
    };

    let result = config.extract_and_validate(&json!(html)).unwrap();

    assert_eq!(result.errors.len(), 0);
    assert_eq!(result.values.len(), 5);

    assert_eq!(result.values["username"], json!("John Doe"));
    assert_eq!(result.values["age"], json!("30"));
    assert_eq!(result.values["active"], json!("true"));
    let tags = result.values["tags"].as_array().unwrap();
    assert!(tags.contains(&json!("developer")));
    assert!(tags.contains(&json!("rust")));
    assert!(tags.contains(&json!("web")));
    assert_eq!(result.values["link_href"], json!("https://example.com"));
  }

  #[test]
  fn test_extract_and_validate_html_with_failures() {
    let html = r#"
      <!DOCTYPE html>
      <html>
      <body>
        <div class="user-info">
          <h1 id="username">John Doe</h1>
        </div>
      </body>
      </html>
    "#;

    let config = ExtractorConfig {
      format:     DataFormat::Html,
      extractors: vec![
        extractor!(
            id: "username".to_string(),
            description: "User's name".to_string(),
            selector: vec!["#username".to_string()],
            extractor_type: ExtractorType::String
        ),
        extractor!(
            id: "missing_element".to_string(),
            description: "Missing element".to_string(),
            selector: vec![".non-existent".to_string()],
            extractor_type: ExtractorType::String
        ),
        extractor!(
            id: "optional_missing".to_string(),
            description: "Optional missing element".to_string(),
            selector: vec![".optional".to_string()],
            extractor_type: ExtractorType::String,
            required: false
        ),
      ],
    };

    let result = config.extract_and_validate(&json!(html)).unwrap();

    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.values.len(), 1);

    assert_eq!(result.values["username"], json!("John Doe"));
    assert!(result.errors[0].contains("No elements found for selector"));
  }

  #[test]
  fn test_extract_and_validate_html_with_invalid_input() {
    let config = ExtractorConfig {
      format:     DataFormat::Html,
      extractors: vec![extractor! {
        id:             "username".to_string(),
        description:    "User's name".to_string(),
        selector:       vec!["#username".to_string()],
        extractor_type: ExtractorType::String,
      }],
    };

    // Test with non-string input
    let result = config.extract_and_validate(&json!(42));
    assert!(result.is_err());

    if let Err(ExtractorError::TypeMismatch { expected, actual }) = result {
      assert_eq!(expected, "string");
      assert_eq!(actual, "number");
    } else {
      panic!("Expected TypeMismatch error");
    }
  }

  #[test]
  fn test_json_format_type_validation() {
    let config =
      ExtractorConfig { format: DataFormat::Json, extractors: vec![name_extractor()] };

    // Test with string instead of JSON object
    let invalid_data = Value::String("not a json object".to_string());
    let result = config.extract_and_validate(&invalid_data);
    assert!(matches!(
        result,
        Err(ExtractorError::TypeMismatch { expected, actual })
        if expected == "object or array" && actual == "string"
    ));

    // Test with valid JSON object
    let valid_data = json!({
        "user": {
            "name": "John Doe"
        }
    });
    assert!(config.extract_and_validate(&valid_data).is_ok());

    // Test with valid JSON array
    let valid_array = json!([{"user": {"name": "John Doe"}}]);
    assert!(config.extract_and_validate(&valid_array).is_ok());
  }
}
