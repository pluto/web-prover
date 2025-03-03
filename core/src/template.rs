//! Template handling for manifest variables.
//!
//! This module provides functionality for handling template variables in manifests.
//! Template variables are used to parameterize manifest fields and are identified
//! by the pattern `<% variable_name %>`.

use serde::{Deserialize, Serialize};

use crate::error::TemplateError;

/// Regular expression for matching template variables in text.
///
/// Matches patterns like `<% variable_name %>` where variable_name
/// consists of word characters.
const TEMPLATE_VAR_PATTERN: &str = r"<%\s*(\w+)\s*%>";

/// Default value for the required field is true
const DEFAULT_REQUIRED: bool = true;
fn default_required() -> bool { DEFAULT_REQUIRED }

/// Template variables are identified in `Manifest` fields using the syntax `<% variable_name %>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateVar {
  /// Optional description explaining the purpose of this variable
  pub description: Option<String>,
  /// Whether this variable must be provided (defaults to true)
  #[serde(default = "default_required")]
  pub required:    bool,
  /// Default value for optional variables
  pub default:     Option<String>,
  /// Regular expression pattern for validating values
  pub pattern:     Option<String>,
}

impl TemplateVar {
  /// Validates the template variable
  pub fn validate(&self, key: &str, is_used: bool) -> Result<(), TemplateError> {
    // Check required variable usage
    if self.required && !is_used {
      return Err(TemplateError::UnusedRequiredVariable(key.to_string()));
    }

    // Check non-required variable default value
    if !self.required && self.default.is_none() {
      return Err(TemplateError::MissingDefaultValue(key.to_string()));
    }

    // Validate pattern if present
    if let Some(pattern) = self.pattern.as_ref() {
      // Check for empty pattern
      if pattern.is_empty() {
        return Err(TemplateError::EmptyRegexPattern(key.to_string()));
      }

      // Using `regress` crate for compatibility with ECMAScript regular expressions
      let _regex = regress::Regex::new(pattern)
        .map_err(|_| TemplateError::InvalidRegexPattern(key.to_string()))?;

      // Validate default value against pattern if present
      if let Some(default_value) = self.default.as_ref() {
        let regex = regex::Regex::new(pattern)
          .map_err(|_| TemplateError::InvalidRegexPattern(key.to_string()))?;

        if !regex.is_match(default_value) {
          return Err(TemplateError::DefaultValuePatternMismatch(key.to_string()));
        }
      }
    }
    Ok(())
  }
}

/// Extracts template variable tokens from a JSON value.
pub fn extract_tokens(value: &serde_json::Value) -> Vec<String> {
  let mut tokens = Vec::new();
  let token_regex = regex::Regex::new(TEMPLATE_VAR_PATTERN).unwrap();

  match value {
    serde_json::Value::String(s) =>
      for capture in token_regex.captures_iter(s) {
        if let Some(token) = capture.get(1) {
          // Extract token name
          tokens.push(token.as_str().to_string());
        }
      },
    serde_json::Value::Object(map) =>
    // Recursively extract tokens from nested objects
      for v in map.values() {
        tokens.extend(extract_tokens(v));
      },
    serde_json::Value::Array(arr) =>
    // Recursively extract tokens from nested arrays
      for v in arr {
        tokens.extend(extract_tokens(v));
      },
    _ => {},
  }

  tokens
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  impl TemplateVar {
    /// Creates a new template variable with the specified parameters.
    pub fn new(
      description: Option<&str>,
      required: bool,
      default: Option<&str>,
      pattern: Option<&str>,
    ) -> Self {
      TemplateVar {
        description: description.map(String::from),
        required,
        default: default.map(String::from),
        pattern: pattern.map(String::from),
      }
    }

    /// Creates a new required template variable.
    pub fn required(description: &str, pattern: Option<&str>) -> Self {
      Self::new(Some(description), true, None, pattern)
    }

    /// Creates a new optional template variable with a default value.
    pub fn optional(description: &str, default: &str, pattern: Option<&str>) -> Self {
      Self::new(Some(description), false, Some(default), pattern)
    }

    /// Creates a new optional template variable without a default value.
    pub fn optional_without_default(description: &str, pattern: Option<&str>) -> Self {
      Self::new(Some(description), false, None, pattern)
    }

    /// Creates a new required template variable with a default value.
    pub fn required_with_default(description: &str, default: &str, pattern: Option<&str>) -> Self {
      Self::new(Some(description), true, Some(default), pattern)
    }
  }

  #[test]
  fn test_validate_vars_with_missing_token() {
    let var = TemplateVar::required("Test var", None);

    let result = var.validate("missing_token", false);
    assert!(result.is_err());
    assert!(matches!(
      result,
      Err(TemplateError::UnusedRequiredVariable(token))
      if token == "missing_token"
    ));
  }

  #[test]
  fn test_validate_vars_required_not_used() {
    let var = TemplateVar::required("This is a required variable", None);

    let result = var.validate("unused_var", false);
    assert!(result.is_err());
    assert!(matches!(
      result,
      Err(TemplateError::UnusedRequiredVariable(var))
      if var == "unused_var"
    ));
  }

  #[test]
  fn test_validate_vars_non_required_without_default() {
    let var = TemplateVar::optional_without_default("This is an optional variable", None);

    let result = var.validate("optional_var", true);
    assert!(result.is_err());
    assert!(matches!(
      result,
      Err(TemplateError::MissingDefaultValue(var))
      if var == "optional_var"
    ));
  }

  #[test]
  fn test_validate_vars_default_not_matching_pattern() {
    let var = TemplateVar::optional("Variable with pattern", "abc123", Some("^[0-9]+$"));

    let result = var.validate("pattern_var", true);
    assert!(result.is_err());
    assert!(matches!(
      result,
      Err(TemplateError::DefaultValuePatternMismatch(var))
      if var == "pattern_var"
    ));
  }

  #[test]
  fn test_validate_vars_valid() {
    let var1 = TemplateVar::required("This is a header variable", Some("^[A-Za-z0-9]+$"));
    let var2 =
      TemplateVar::optional("This is a body variable", "default123", Some("^[A-Za-z0-9]+$"));

    assert!(var1.validate("header_var", true).is_ok());
    assert!(var2.validate("body_var", true).is_ok());
  }

  #[test]
  fn test_extract_tokens() {
    let json = json!({
        "string": "Hello <% token1 %> World <% token2 %>",
        "nested": {
            "array": ["<% token3 %>", "plain text"],
            "object": {"key": "<% token4 %>"}
        }
    });

    let tokens = extract_tokens(&json);
    assert_eq!(tokens.len(), 4);
    assert!(tokens.contains(&"token1".to_string()));
    assert!(tokens.contains(&"token2".to_string()));
    assert!(tokens.contains(&"token3".to_string()));
    assert!(tokens.contains(&"token4".to_string()));
  }

  #[test]
  fn test_validate_vars_invalid_regex_pattern() {
    let var = TemplateVar {
      description: Some("Variable with invalid regex".to_string()),
      required:    false,
      default:     Some("test".to_string()),
      pattern:     Some("[invalid regex(".to_string()),
    };

    let result = var.validate("invalid_pattern", true);
    assert!(result.is_err());
    assert!(matches!(
      result,
      Err(TemplateError::InvalidRegexPattern(var))
      if var == "invalid_pattern"
    ));
  }

  #[test]
  fn test_extract_tokens_empty_values() {
    let json = json!({
        "empty_string": "",
        "null": null,
        "number": 42,
        "boolean": true
    });

    let tokens = extract_tokens(&json);
    assert!(tokens.is_empty());
  }

  #[test]
  fn test_validate_vars_empty_pattern() {
    let var = TemplateVar {
      description: None,
      required:    false,
      default:     Some("test".to_string()),
      pattern:     Some("".to_string()),
    };

    let result = var.validate("empty_pattern", true);
    assert!(result.is_err());
    assert!(matches!(
      result,
      Err(TemplateError::EmptyRegexPattern(var))
      if var == "empty_pattern"
    ));
  }

  #[test]
  fn test_extract_tokens_nested_structure() {
    let json = json!({
        "object": {
            "nested": {
                "value": "Hello <% user %>"
            },
            "array": [
                "First <% index %>",
                {"deep": "<% token %>"}
            ]
        }
    });

    let tokens = extract_tokens(&json);
    assert_eq!(tokens.len(), 3);
    assert!(tokens.contains(&"user".to_string()));
    assert!(tokens.contains(&"index".to_string()));
    assert!(tokens.contains(&"token".to_string()));
  }

  #[test]
  fn test_template_var_defaults() {
    let var = TemplateVar::new(None, DEFAULT_REQUIRED, None, None);
    assert!(var.required);
    assert!(var.description.is_none());
    assert!(var.default.is_none());
    assert!(var.pattern.is_none());
  }
}
