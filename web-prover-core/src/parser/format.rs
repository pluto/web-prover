use serde_json::Value;

use crate::parser::{
  extractors::{extract_html, extract_json, get_value_type},
  ExtractionResult, ExtractorConfig, ExtractorError,
};

/// Trait for data format extractors
pub trait FormatExtractor {
  fn validate_input(&self, data: &Value) -> Result<(), ExtractorError>;
  fn extract(
    &self,
    data: &Value,
    config: &ExtractorConfig,
  ) -> Result<ExtractionResult, ExtractorError>;
}

pub struct JsonExtractor;
pub struct HtmlExtractor;

impl FormatExtractor for JsonExtractor {
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

impl FormatExtractor for HtmlExtractor {
  fn validate_input(&self, data: &Value) -> Result<(), ExtractorError> {
    if !matches!(data, Value::String(_)) {
      return Err(ExtractorError::TypeMismatch {
        expected: "string".to_string(),
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
    data.as_str().map(|s| extract_html(s, config)).unwrap_or_else(|| unreachable!())
  }
}
