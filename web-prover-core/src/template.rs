use serde::{Deserialize, Serialize};

use crate::errors::ManifestError;

/// Default value for the required field is true
fn default_required() -> bool { true }

/// Template variable type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateVar {
  /// Optional description for the end user
  pub description: Option<String>,
  /// Indicates if the value is required
  #[serde(default = "default_required")]
  pub required:    bool,
  /// A default value, must be set when `required` is false
  pub default:     Option<String>,
  /// Regex pattern for validation of user input
  pub pattern:     Option<String>,
}

impl TemplateVar {
  pub fn validate(&self, key: &str, is_used: bool) -> Result<(), ManifestError> {
    // Check required variable usage
    if self.required && !is_used {
      return Err(ManifestError::InvalidManifest(format!(
        "Required variable `{}` is not used in the template",
        key
      )));
    }

    // Check non-required variable default value
    if !self.required && self.default.is_none() {
      return Err(ManifestError::InvalidManifest(format!(
        "Non-required variable `{}` must have a default value",
        key
      )));
    }

    // Validate pattern if present
    if let Some(pattern) = self.pattern.as_ref() {
      // Using `regress` crate for compatibility with ECMAScript regular expressions
      let _regex = regress::Regex::new(pattern).map_err(|_| {
        ManifestError::InvalidManifest(format!("Invalid regex pattern for `{}`", key))
      })?;

      // Validate default value against pattern if present
      if let Some(default_value) = self.default.as_ref() {
        let regex = regex::Regex::new(pattern).map_err(|_| {
          ManifestError::InvalidManifest(format!("Invalid regex pattern for `{}`", key))
        })?;

        if !regex.is_match(default_value) {
          return Err(ManifestError::InvalidManifest(format!(
            "Default value for `{}` does not match the specified pattern",
            key
          )));
        }
      }
    }

    Ok(())
  }
}

/// Extract tokens from a JSON value
pub fn extract_tokens(value: &serde_json::Value) -> Vec<String> {
  let mut tokens = vec![];

  match value {
    serde_json::Value::String(s) => {
      let token_regex = regex::Regex::new(r"<%\s*(\w+)\s*%>").unwrap();
      for capture in token_regex.captures_iter(s) {
        if let Some(token) = capture.get(1) {
          // Extract token name
          tokens.push(token.as_str().to_string());
        }
      }
    },
    serde_json::Value::Object(map) => {
      // Recursively parse nested objects
      for (_, v) in map {
        tokens.extend(extract_tokens(v));
      }
    },
    serde_json::Value::Array(arr) => {
      // Recursively parse arrays
      for v in arr {
        tokens.extend(extract_tokens(v));
      }
    },
    _ => {},
  }

  tokens
}
