use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::parser::{errors::PredicateError, extractors::get_value_type};

/// The type of predicate to apply
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
#[serde(rename_all = "camelCase")]
pub enum PredicateType {
  /// Value-based predicate
  Value,
  /// Length-based predicate
  Length,
  /// Regex-based predicate
  Regex,
  /// String-specific operations
  String,
  /// Array-specific operations
  Array,
}

/// The comparison operation to use in a predicate
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
// TODO: Consider splitting this into multiple enums
pub enum Comparison {
  /// Equal comparison
  Equal,
  /// Not equal comparison
  NotEqual,
  /// Greater than comparison
  GreaterThan,
  /// Less than comparison
  LessThan,
  /// Greater than or equal comparison
  GreaterThanOrEqual,
  /// Less than or equal comparison
  LessThanOrEqual,
  /// Contains comparison
  Contains,
  /// Not contains comparison
  NotContains,
  /// Starts with comparison (for strings)
  StartsWith,
  /// Ends with comparison (for strings)
  EndsWith,
  /// Includes comparison (for arrays)
  Includes,
  /// Every comparison (for arrays)
  Every,
  /// Some comparison (for arrays)
  Some,
}

/// Function to provide the default value `true` for `case_sensitive`
fn default_case_sensitive() -> bool { true }

/// A predicate for validating extracted data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Predicate {
  /// The type of predicate
  #[serde(rename = "type")]
  pub predicate_type:   PredicateType,
  /// The comparison operation
  pub comparison:       Comparison,
  /// The value to compare against
  pub value:            Value,
  /// Case sensitivity for string operations
  #[serde(default = "default_case_sensitive")]
  pub case_sensitive:   bool,
  /// Regex flags
  pub flags:            Option<String>,
  /// Optional description
  pub description:      Option<String>,
  /// Nested predicate for array operations
  pub nested_predicate: Option<Box<Predicate>>,
}

/// Validates a value-based predicate
pub fn validate_value_predicate(
  value: &Value,
  predicate: &Predicate,
) -> Result<(), PredicateError> {
  match predicate.comparison {
    Comparison::Equal => {
      // Special handling for numeric comparisons
      match (value, &predicate.value) {
        (Value::Number(_), Value::Number(_)) => {
          if !compare_values(
            value,
            &predicate.value,
            |a, b| (a - b).abs() < f64::EPSILON,
            |a, b| a == b,
          ) {
            return Err(PredicateError::NotEqual {
              actual:   value.clone(),
              expected: predicate.value.clone(),
            });
          }
        },
        _ =>
          if value != &predicate.value {
            return Err(PredicateError::NotEqual {
              actual:   value.clone(),
              expected: predicate.value.clone(),
            });
          },
      }
    },
    Comparison::NotEqual => {
      // Special handling for numeric comparisons
      match (value, &predicate.value) {
        (Value::Number(_), Value::Number(_)) => {
          if compare_values(
            value,
            &predicate.value,
            |a, b| (a - b).abs() < f64::EPSILON,
            |a, b| a == b,
          ) {
            return Err(PredicateError::Equal {
              actual:   value.clone(),
              expected: predicate.value.clone(),
            });
          }
        },
        _ =>
          if value == &predicate.value {
            return Err(PredicateError::Equal {
              actual:   value.clone(),
              expected: predicate.value.clone(),
            });
          },
      }
    },
    Comparison::GreaterThan =>
      if !is_greater_than(value, &predicate.value) {
        return Err(PredicateError::NotGreaterThan {
          actual:   value.clone(),
          expected: predicate.value.clone(),
        });
      },
    Comparison::LessThan =>
      if !is_less_than(value, &predicate.value) {
        return Err(PredicateError::NotLessThan {
          actual:   value.clone(),
          expected: predicate.value.clone(),
        });
      },
    Comparison::GreaterThanOrEqual =>
      if is_less_than(value, &predicate.value) {
        return Err(PredicateError::LessThan {
          actual:   value.clone(),
          expected: predicate.value.clone(),
        });
      },
    Comparison::LessThanOrEqual =>
      if is_greater_than(value, &predicate.value) {
        return Err(PredicateError::GreaterThan {
          actual:   value.clone(),
          expected: predicate.value.clone(),
        });
      },
    Comparison::Contains => match (value, &predicate.value) {
      (Value::String(s), Value::String(pattern)) =>
        if !s.contains(pattern) {
          return Err(PredicateError::StringNotContains {
            string:  s.clone(),
            pattern: pattern.clone(),
          });
        },
      (Value::Array(arr), val) =>
        if !arr.contains(val) {
          return Err(PredicateError::ArrayNotIncludes { array: arr.clone(), value: val.clone() });
        },
      _ => {
        return Err(PredicateError::InvalidComparison {
          comparison:    predicate.comparison,
          actual_type:   get_value_type(value).to_string(),
          expected_type: get_value_type(&predicate.value).to_string(),
        });
      },
    },
    Comparison::NotContains => match (value, &predicate.value) {
      (Value::String(s), Value::String(pattern)) =>
        if s.contains(pattern) {
          return Err(PredicateError::StringContains {
            string:  s.clone(),
            pattern: pattern.clone(),
          });
        },
      (Value::Array(arr), val) =>
        if arr.contains(val) {
          return Err(PredicateError::ArrayContains { array: arr.clone(), value: val.clone() });
        },
      _ => {
        return Err(PredicateError::InvalidComparison {
          comparison:    predicate.comparison,
          actual_type:   get_value_type(value).to_string(),
          expected_type: get_value_type(&predicate.value).to_string(),
        });
      },
    },
    Comparison::StartsWith => match (value, &predicate.value) {
      (Value::String(s), Value::String(prefix)) => {
        let case_sensitive = predicate.case_sensitive;

        if case_sensitive {
          if !s.starts_with(prefix) {
            return Err(PredicateError::StringNotStartsWith {
              string: s.clone(),
              prefix: prefix.clone(),
              case_sensitive,
            });
          }
        } else {
          let s_lower = s.to_lowercase();
          let prefix_lower = prefix.to_lowercase();
          if !s_lower.starts_with(&prefix_lower) {
            return Err(PredicateError::StringNotStartsWith {
              string: s.clone(),
              prefix: prefix.clone(),
              case_sensitive,
            });
          }
        }
      },
      _ => {
        return Err(PredicateError::InvalidComparison {
          comparison:    predicate.comparison,
          actual_type:   get_value_type(value).to_string(),
          expected_type: get_value_type(&predicate.value).to_string(),
        });
      },
    },
    Comparison::EndsWith => match (value, &predicate.value) {
      (Value::String(s), Value::String(suffix)) => {
        let case_sensitive = predicate.case_sensitive;

        if case_sensitive {
          if !s.ends_with(suffix) {
            return Err(PredicateError::StringNotEndsWith {
              string: s.clone(),
              suffix: suffix.clone(),
              case_sensitive,
            });
          }
        } else {
          let s_lower = s.to_lowercase();
          let suffix_lower = suffix.to_lowercase();
          if !s_lower.ends_with(&suffix_lower) {
            return Err(PredicateError::StringNotEndsWith {
              string: s.clone(),
              suffix: suffix.clone(),
              case_sensitive,
            });
          }
        }
      },
      _ => {
        return Err(PredicateError::InvalidComparison {
          comparison:    predicate.comparison,
          actual_type:   get_value_type(value).to_string(),
          expected_type: get_value_type(&predicate.value).to_string(),
        });
      },
    },
    Comparison::Includes | Comparison::Every | Comparison::Some => {
      return Err(PredicateError::ShouldBeHandledByArrayValidator(predicate.comparison));
    },
  }
  Ok(())
}

/// Validates a length-based predicate
pub fn validate_length_predicate(
  value: &Value,
  predicate: &Predicate,
) -> Result<(), PredicateError> {
  let length = match value {
    Value::String(s) => s.len(),
    Value::Array(arr) => arr.len(),
    Value::Object(obj) => obj.len(),
    _ => {
      return Err(PredicateError::InvalidPredicateForType {
        predicate_type: predicate.predicate_type,
        value_type:     get_value_type(value).to_string(),
      });
    },
  };

  let expected_length = match predicate.value.as_u64() {
    Some(n) => n as usize,
    None => {
      return Err(PredicateError::InvalidLengthValue(predicate.value.clone()));
    },
  };

  match predicate.comparison {
    Comparison::Equal =>
      if length != expected_length {
        return Err(PredicateError::LengthNotEqual { actual: length, expected: expected_length });
      },
    Comparison::NotEqual =>
      if length == expected_length {
        return Err(PredicateError::LengthEqual { actual: length, expected: expected_length });
      },
    Comparison::GreaterThan =>
      if length <= expected_length {
        return Err(PredicateError::LengthNotGreaterThan {
          actual:   length,
          expected: expected_length,
        });
      },
    Comparison::LessThan =>
      if length >= expected_length {
        return Err(PredicateError::LengthNotLessThan {
          actual:   length,
          expected: expected_length,
        });
      },
    Comparison::GreaterThanOrEqual =>
      if length < expected_length {
        return Err(PredicateError::LengthLessThan { actual: length, expected: expected_length });
      },
    Comparison::LessThanOrEqual =>
      if length > expected_length {
        return Err(PredicateError::LengthGreaterThan {
          actual:   length,
          expected: expected_length,
        });
      },
    _ => {
      return Err(PredicateError::InvalidLengthComparison {
        comparison:     predicate.comparison,
        predicate_type: predicate.predicate_type,
      });
    },
  }
  Ok(())
}

/// Validates a regex-based predicate
pub fn validate_regex_predicate(
  value: &Value,
  predicate: &Predicate,
) -> Result<(), PredicateError> {
  let string_value = match value {
    Value::String(s) => s,
    _ => {
      return Err(PredicateError::RegexNotApplicable(get_value_type(value).to_string()));
    },
  };

  let pattern = match predicate.value.as_str() {
    Some(p) => p,
    None => {
      return Err(PredicateError::InvalidRegexPattern(predicate.value.clone()));
    },
  };

  // Build regex with flags if provided
  let regex_result = if let Some(flags) = &predicate.flags {
    let mut builder = regex::RegexBuilder::new(pattern);

    if flags.contains('i') {
      builder.case_insensitive(true);
    }
    if flags.contains('m') {
      builder.multi_line(true);
    }
    if flags.contains('s') {
      builder.dot_matches_new_line(true);
    }

    builder.build()
  } else {
    regex::Regex::new(pattern)
  };

  let regex = match regex_result {
    Ok(r) => r,
    Err(e) => {
      return Err(PredicateError::RegexError(e.to_string()));
    },
  };

  let matches = regex.is_match(string_value);

  match predicate.comparison {
    Comparison::Equal | Comparison::Contains =>
      if !matches {
        return Err(PredicateError::RegexNoMatch {
          string:  string_value.to_string(),
          pattern: pattern.to_string(),
        });
      },
    Comparison::NotEqual | Comparison::NotContains =>
      if matches {
        return Err(PredicateError::RegexMatch {
          string:  string_value.to_string(),
          pattern: pattern.to_string(),
        });
      },
    _ => {
      return Err(PredicateError::InvalidRegexComparison(predicate.comparison));
    },
  }
  Ok(())
}

/// Validates a string-specific predicate
pub fn validate_string_predicate(
  value: &Value,
  predicate: &Predicate,
) -> Result<(), PredicateError> {
  let string_value = match value {
    Value::String(s) => s,
    _ => {
      return Err(PredicateError::StringPredicateNotApplicable(get_value_type(value).to_string()));
    },
  };

  match predicate.comparison {
    Comparison::StartsWith => {
      let prefix = match predicate.value.as_str() {
        Some(p) => p,
        None => {
          return Err(PredicateError::InvalidPrefixValue(predicate.value.clone()));
        },
      };

      if predicate.case_sensitive {
        if !string_value.starts_with(prefix) {
          return Err(PredicateError::StringNotStartsWith {
            string:         string_value.to_string(),
            prefix:         prefix.to_string(),
            case_sensitive: true,
          });
        }
      } else {
        let s_lower = string_value.to_lowercase();
        let prefix_lower = prefix.to_lowercase();
        if !s_lower.starts_with(&prefix_lower) {
          return Err(PredicateError::StringNotStartsWith {
            string:         string_value.to_string(),
            prefix:         prefix.to_string(),
            case_sensitive: false,
          });
        }
      }
    },
    Comparison::EndsWith => {
      let suffix = match predicate.value.as_str() {
        Some(s) => s,
        None => {
          return Err(PredicateError::InvalidSuffixValue(predicate.value.clone()));
        },
      };

      if predicate.case_sensitive {
        if !string_value.ends_with(suffix) {
          return Err(PredicateError::StringNotEndsWith {
            string:         string_value.to_string(),
            suffix:         suffix.to_string(),
            case_sensitive: true,
          });
        }
      } else {
        let s_lower = string_value.to_lowercase();
        let suffix_lower = suffix.to_lowercase();
        if !s_lower.ends_with(&suffix_lower) {
          return Err(PredicateError::StringNotEndsWith {
            string:         string_value.to_string(),
            suffix:         suffix.to_string(),
            case_sensitive: false,
          });
        }
      }
    },
    _ => {
      return Err(PredicateError::InvalidStringComparison(predicate.comparison));
    },
  }
  Ok(())
}

/// Validates an array-specific predicate
pub fn validate_array_predicate(
  value: &Value,
  predicate: &Predicate,
) -> Result<(), PredicateError> {
  let array_value = match value {
    Value::Array(arr) => arr,
    _ => {
      return Err(PredicateError::ArrayPredicateNotApplicable(get_value_type(value).to_string()));
    },
  };

  match predicate.comparison {
    Comparison::Includes =>
      if !array_value.contains(&predicate.value) {
        return Err(PredicateError::ArrayNotIncludes {
          array: array_value.clone(),
          value: predicate.value.clone(),
        });
      },
    Comparison::Every => {
      if !array_value.iter().any(|_| true) {
        // Handle empty array case
        return Ok(());
      }

      for item in array_value {
        if let Err(err) = validate_value_predicate(item, predicate) {
          return Err(PredicateError::NotAllElementsSatisfyPredicate(err.to_string()));
        }
      }
    },
    Comparison::Some => {
      if array_value.is_empty() {
        return Err(PredicateError::SomePredicateEmptyArray);
      }

      if !array_value.iter().any(|item| validate_value_predicate(item, predicate).is_ok()) {
        return Err(PredicateError::NoElementsSatisfyPredicate(array_value.clone()));
      }
    },
    _ => {
      return Err(PredicateError::InvalidComparison {
        comparison:    predicate.comparison,
        actual_type:   get_value_type(value).to_string(),
        expected_type: get_value_type(&predicate.value).to_string(),
      });
    },
  }
  Ok(())
}

/// Validates a `predicate` against a `value`
pub fn validate_predicate(value: &Value, predicate: &Predicate) -> Result<(), PredicateError> {
  match predicate.predicate_type {
    PredicateType::Value => validate_value_predicate(value, predicate),
    PredicateType::Length => validate_length_predicate(value, predicate),
    PredicateType::Regex => validate_regex_predicate(value, predicate),
    PredicateType::String => validate_string_predicate(value, predicate),
    PredicateType::Array => validate_array_predicate(value, predicate),
  }
}

/// Helper function to compare two `Value` objects with given numeric and string comparators
fn compare_values<FNum, FStr>(
  a: &Value,
  b: &Value,
  num_comparator: FNum,
  str_comparator: FStr,
) -> bool
where
  FNum: Fn(f64, f64) -> bool,
  FStr: Fn(&str, &str) -> bool,
{
  match (a, b) {
    (Value::Number(a_num), Value::Number(b_num)) => {
      if let (Some(a_f), Some(b_f)) = (a_num.as_f64(), b_num.as_f64()) {
        return num_comparator(a_f, b_f);
      }
    },
    (Value::String(a_str), Value::String(b_str)) => {
      return str_comparator(a_str, b_str);
    },
    _ => {},
  }
  false
}

/// Helper function to check if a value is greater than another
fn is_greater_than(a: &Value, b: &Value) -> bool {
  compare_values(a, b, |x, y| x > y, |x, y| x > y)
}

/// Helper function to check if a value is less than another
fn is_less_than(a: &Value, b: &Value) -> bool { compare_values(a, b, |x, y| x < y, |x, y| x < y) }

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::predicate;

  #[test]
  fn test_value_predicates() {
    let json_data = json!({
        "number": 42,
        "string": "hello world",
        "boolean": true,
        "array": [1, 2, 3, 42],
        "email": "user@example.com",
        "phone": "+1-555-123-4567",
        "username": "johndoe123"
    });

    // Equal
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(42)
    );
    assert!(validate_value_predicate(&json_data["number"], &predicate).is_ok());

    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(100)
    );
    assert!(validate_value_predicate(&json_data["number"], &predicate).is_err());

    // NotEqual
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::NotEqual,
        value: json!(100)
    );
    assert!(validate_value_predicate(&json_data["number"], &predicate).is_ok());

    // String operations - StartsWith
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::StartsWith,
        value: json!("hello")
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_ok());

    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::StartsWith,
        value: json!("world")
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_err());

    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::StartsWith,
        value: json!("HELLO"),
        case_sensitive: false
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_ok());

    // String operations - EndsWith
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::EndsWith,
        value: json!("world")
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_ok());

    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::EndsWith,
        value: json!("hello")
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_err());

    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::EndsWith,
        value: json!("WORLD"),
        case_sensitive: false
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_ok());

    // Contains
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Contains,
        value: json!("llo wor")
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_ok());

    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Contains,
        value: json!("goodbye")
    );
    assert!(validate_value_predicate(&json_data["string"], &predicate).is_err());
  }

  #[test]
  fn test_regex_predicates() {
    let json_data = json!({
        "email": "user@example.com",
        "invalid_email": "not-an-email"
    });

    // Email regex - pass
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    );
    assert!(validate_regex_predicate(&json_data["email"], &predicate).is_ok());

    // Email regex - fail
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    );
    assert!(validate_regex_predicate(&json_data["invalid_email"], &predicate).is_err());

    // Email regex with flags - pass
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"),
        flags: Some("i".to_string())
    );
    assert!(validate_regex_predicate(&json_data["email"], &predicate).is_ok());
  }

  #[test]
  fn test_length_predicates() {
    let json_data = json!({
        "string": "hello world",
        "array": [1, 2, 3, 42],
        "empty_array": []
    });

    // Length equal
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::Equal,
        value: json!(11)
    );
    assert!(validate_length_predicate(&json_data["string"], &predicate).is_ok());

    // Length equal - array
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::Equal,
        value: json!(4)
    );
    assert!(validate_length_predicate(&json_data["array"], &predicate).is_ok());

    // Length greater than
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::GreaterThan,
        value: json!(10)
    );
    assert!(validate_length_predicate(&json_data["string"], &predicate).is_ok());

    // Length less than
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::LessThan,
        value: json!(12)
    );
    assert!(validate_length_predicate(&json_data["string"], &predicate).is_ok());

    // Length greater than or equal
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::GreaterThanOrEqual,
        value: json!(11)
    );
    assert!(validate_length_predicate(&json_data["string"], &predicate).is_ok());

    // Length less than or equal
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::LessThanOrEqual,
        value: json!(11)
    );
    assert!(validate_length_predicate(&json_data["string"], &predicate).is_ok());

    // Length not equal
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::NotEqual,
        value: json!(10)
    );
    assert!(validate_length_predicate(&json_data["string"], &predicate).is_ok());

    // Empty array
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::Equal,
        value: json!(0)
    );
    assert!(validate_length_predicate(&json_data["empty_array"], &predicate).is_ok());
  }

  #[test]
  fn test_numeric_comparisons() {
    let test_cases = vec![
      // Unsigned integers
      (json!({"val": 42u64}), 42, true),
      // Signed integers
      (json!({"val": -42}), -42, true),
      // Floating point
      (json!({"val": 42.0}), 42, true),
      // Mismatched types
      (json!({"val": "42"}), 42, false),
      // Edge cases
      (json!({"val": 42.000001}), 42, false),
    ];

    for (json_data, expected, should_match) in test_cases {
      let predicate = predicate!(
          predicate_type: PredicateType::Value,
          comparison: Comparison::Equal,
          value: json!(expected)
      );

      let result = validate_value_predicate(&json_data["val"], &predicate);
      assert_eq!(
        result.is_ok(),
        should_match,
        "Failed for value {:?} and expected {:?}",
        json_data["val"],
        expected
      );
    }
  }

  #[test]
  fn test_unicode_and_special_characters() {
    let json_data = json!({
        "unicode": "こんにちは世界",
        "emoji": "Hello 😊 World 🌍",
        "mixed": "Special chars: !@#$%^&*()"
    });

    // Unicode string length (counts UTF-8 bytes, not visual characters)
    // "こんにちは世界" has 7 visual characters but 21 bytes in UTF-8
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::Equal,
        value: json!(21)
    );
    assert!(validate_length_predicate(&json_data["unicode"], &predicate).is_ok());

    // Contains with emoji
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Contains,
        value: json!("😊")
    );
    assert!(validate_value_predicate(&json_data["emoji"], &predicate).is_ok());

    // StartsWith with special characters
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::StartsWith,
        value: json!("Special")
    );
    assert!(validate_value_predicate(&json_data["mixed"], &predicate).is_ok());
  }

  #[test]
  fn test_edge_cases() {
    let json_data = json!({
        "empty_string": "",
        "whitespace_only": "   \t\n",
        "very_large_number": 9007199254740991i64,
        "very_small_number": 0.0000000000001,
        "null_value": null
    });

    // Empty string length
    let predicate = predicate!(
        predicate_type: PredicateType::Length,
        comparison: Comparison::Equal,
        value: json!(0)
    );
    assert!(validate_length_predicate(&json_data["empty_string"], &predicate).is_ok());

    // Whitespace string contains
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Contains,
        value: json!("\t")
    );
    assert!(validate_value_predicate(&json_data["whitespace_only"], &predicate).is_ok());

    // Large number comparison
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::GreaterThan,
        value: json!(9007199254740990i64)
    );
    assert!(validate_value_predicate(&json_data["very_large_number"], &predicate).is_ok());

    // Small number comparison
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::LessThan,
        value: json!(0.00000000001)
    );
    assert!(validate_value_predicate(&json_data["very_small_number"], &predicate).is_ok());
  }

  #[test]
  fn test_boolean_predicates() {
    let json_data = json!({
        "true_value": true,
        "false_value": false,
        "string_true": "true",
        "number_one": 1
    });

    // Boolean equality
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(true)
    );
    assert!(validate_value_predicate(&json_data["true_value"], &predicate).is_ok());

    // Boolean inequality
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::NotEqual,
        value: json!(true)
    );
    assert!(validate_value_predicate(&json_data["false_value"], &predicate).is_ok());

    // String "true" is not boolean true
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(true)
    );
    assert!(validate_value_predicate(&json_data["string_true"], &predicate).is_err());

    // Number 1 is not boolean true
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(true)
    );
    assert!(validate_value_predicate(&json_data["number_one"], &predicate).is_err());
  }

  #[test]
  fn test_complex_regex_patterns() {
    let json_data = json!({
        "email": "user.name+tag@example.co.uk",
        "phone": "+1 (555) 123-4567",
        "date": "2023-10-15",
        "url": "https://www.example.com/path?query=value#fragment"
    });

    // Complex email regex
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    );
    assert!(validate_regex_predicate(&json_data["email"], &predicate).is_ok());

    // Phone number with formatting
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^\+\d+\s*\(\d+\)\s*\d+\-\d+$")
    );
    assert!(validate_regex_predicate(&json_data["phone"], &predicate).is_ok());

    // ISO date format
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^\d{4}-\d{2}-\d{2}$")
    );
    assert!(validate_regex_predicate(&json_data["date"], &predicate).is_ok());

    // URL with capture groups
    let predicate = predicate!(
        predicate_type: PredicateType::Regex,
        comparison: Comparison::Equal,
        value: json!(r"^(https?):\/\/([^\/]+)\/(.*)$")
    );
    assert!(validate_regex_predicate(&json_data["url"], &predicate).is_ok());
  }

  #[test]
  fn test_numeric_precision() {
    let json_data = json!({
        "integer": 42,
        "float": 42.0,
        "almost_same": 42.0000001,
        "scientific": 4.2e1
    });

    // Integer and float equality
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(42)
    );
    assert!(validate_value_predicate(&json_data["float"], &predicate).is_ok());

    // Scientific notation
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(42)
    );
    assert!(validate_value_predicate(&json_data["scientific"], &predicate).is_ok());

    // Very close but not equal
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::Equal,
        value: json!(42)
    );
    assert!(validate_value_predicate(&json_data["almost_same"], &predicate).is_err());

    // Very close with greater than
    let predicate = predicate!(
        predicate_type: PredicateType::Value,
        comparison: Comparison::GreaterThan,
        value: json!(42)
    );
    assert!(validate_value_predicate(&json_data["almost_same"], &predicate).is_ok());
  }
}
