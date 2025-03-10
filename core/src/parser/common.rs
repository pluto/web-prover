use serde_json::Value;

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
