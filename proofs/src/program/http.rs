use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;
use web_proof_circuits_witness_generator::json::JsonKey;

use crate::{errors::ProofError, program::manifest::MAX_HTTP_HEADERS};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseBody {
  pub json: Vec<JsonKey>,
}

/// Default HTTP version
pub fn default_version() -> String { "HTTP/1.1".to_string() }
/// Default HTTP message
pub fn default_message() -> String { "OK".to_string() }

/// HTTP Response items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Response {
  /// HTTP response status
  pub status:  String,
  /// HTTP version
  #[serde(default = "default_version")]
  pub version: String,
  /// HTTP response message
  #[serde(default = "default_message")]
  pub message: String,
  /// HTTP headers to lock
  pub headers: HashMap<String, String>,
  /// HTTP body keys
  pub body:    ResponseBody,
}

impl Response {
  pub fn validate(&self) -> Result<(), ProofError> {
    // TODO: What are legal statuses?
    const VALID_STATUSES: [&str; 2] = ["200", "201"];
    if !VALID_STATUSES.contains(&self.status.as_str()) {
      return Err(ProofError::InvalidManifest("Unsupported HTTP status".to_string()));
    }

    // TODO: What HTTP versions are supported?
    if self.version != "HTTP/1.1" {
      return Err(ProofError::InvalidManifest(
        "Invalid HTTP version: ".to_string() + &self.version,
      ));
    }

    // TODO: What is the max supported message length?
    // TODO: Not covered by serde's #default annotation. Is '""' a valid message?
    if self.message.len() > 1024 || self.message.is_empty() {
      return Err(ProofError::InvalidManifest(
        "Invalid message length: ".to_string() + &self.message,
      ));
    }

    // We always expect at least one header, "Content-Type"
    if self.headers.len() > MAX_HTTP_HEADERS || self.headers.is_empty() {
      return Err(ProofError::InvalidManifest(
        "Invalid headers length: ".to_string() + &self.headers.len().to_string(),
      ));
    }

    let content_type = self.headers.get("Content-Type");
    if content_type.is_none() {
      return Err(ProofError::InvalidManifest("Missing 'Content-Type' header".to_string()));
    }
    let content_type = content_type.unwrap();

    const VALID_CONTENT_TYPES: [&str; 2] = ["application/json", "text/plain"];
    let is_valid_content_type = VALID_CONTENT_TYPES.iter().any(|&legal_type| {
      content_type == legal_type || content_type.starts_with(&format!("{};", legal_type))
    });
    if !is_valid_content_type {
      return Err(ProofError::InvalidManifest(
        "Invalid Content-Type header: ".to_string() + content_type,
      ));
    }

    // When Content-Type is application/json, we expect at least one JSON item
    if content_type == "application/json" && self.body.json.is_empty() {
      return Err(ProofError::InvalidManifest("Expected at least one JSON item".to_string()));
    }

    Ok(())
  }

  /// Recovers all `Response` fields from the given payloads and creates a `Response` struct.
  ///
  /// - `header_bytes`: The bytes representing the HTTP response headers and metadata.
  /// - `body_bytes`: The bytes representing the HTTP response body.
  pub fn from_payload(header_bytes: &[u8], body_bytes: &[u8]) -> Result<Self, ProofError> {
    let (headers, status, version, message) = Self::parse_header(header_bytes)?;
    let body = Self::parse_body(body_bytes)?;
    Ok(Self { status, version, message, headers, body })
  }

  fn parse_body(body_bytes: &[u8]) -> Result<ResponseBody, ProofError> {
    if body_bytes.is_empty() {
      return Ok(ResponseBody { json: Vec::new() });
    }

    let body_json: Value = serde_json::from_slice(body_bytes)
      .map_err(|_| ProofError::InvalidManifest("Failed to parse body as valid JSON".to_string()))?;

    let body = ResponseBody {
      json: match body_json {
        Value::Object(map) => map.keys().cloned().map(JsonKey::String).collect(),
        _ =>
          return Err(ProofError::InvalidManifest("Body is not a valid JSON object".to_string())),
      },
    };
    Ok(body)
  }

  fn parse_header(
    header_bytes: &[u8],
  ) -> Result<(HashMap<String, String>, String, String, String), ProofError> {
    let headers_str = std::str::from_utf8(header_bytes).map_err(|_| {
      ProofError::InvalidManifest("Failed to interpret headers as valid UTF-8".to_string())
    })?;
    let mut headers = HashMap::new();
    let mut status = String::new();
    let mut version = String::new();
    let mut message = String::new();

    for (i, line) in headers_str.lines().enumerate() {
      if line.trim().is_empty() {
        continue; // Skip empty lines
      }
      if i == 0 {
        // Process the first line as the HTTP response start-line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
          return Err(ProofError::InvalidManifest("Invalid HTTP response start-line".to_string()));
        }
        version = parts[0].to_string();
        status = parts[1].to_string();
        message = parts[2..].join(" ");
      } else {
        // Process subsequent lines as headers
        if let Some((key, value)) = line.split_once(": ") {
          headers.insert(key.to_string(), value.to_string());
        } else {
          return Err(ProofError::InvalidManifest(format!("Invalid header line: {}", line)));
        }
      }
    }
    Ok((headers, status, version, message))
  }

  /// Performs a test between two response structures. Returns true if `other` contains
  /// at least all the values also present in `self`.
  pub fn is_subset_of(&self, other: &Response) -> bool {
    if self.status != other.status || self.version != other.version || self.message != other.message
    {
      debug!("Exact matches don't match");
      return false;
    }

    // Check if all headers in `self` are present in `other`
    for (key, value) in &self.headers {
      if let Some(other_value) = other.headers.get(key) {
        if other_value != value {
          debug!("other_value={} doesnt match value={}", other_value, value);
          return false;
        }
      } else {
        debug!("missing key {}", key);
        return false;
      }
    }

    // Check if all JSON keys in `self.body` are present in `other.body`
    for self_key in &self.body.json {
      if !other.body.json.iter().any(|other_key| self_key == other_key) {
        debug!("missing self_key {:?}", self_key);
        return false;
      }
    }

    // TODO: We are NOT checking the body contents yet! So this "DSL" is not supported:
    // 			"body": {
    // 					"json": [
    // 						"hello"
    // 					],
    // 					"contains": "world"
    // 				}

    // All checks passed
    debug!("All checks passed");
    true
  }
}

fn extract_tokens(value: &serde_json::Value) -> Vec<String> {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateVar {
  /// Regex for validation (if applicable)
  pub regex:  Option<String>,
  /// Length constraint (if applicable)
  pub length: Option<usize>,
  /// Type constraint (e.g., base64, hex)
  pub r#type: Option<String>,
}

/// HTTP Request items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
  /// HTTP method (GET or POST)
  pub method:  String,
  /// HTTP request URL
  pub url:     String,
  /// HTTP version
  #[serde(default = "default_version")]
  pub version: String,
  /// Request headers to lock
  pub headers: HashMap<String, String>,
  /// Request JSON body
  pub body:    Option<serde_json::Value>,
  /// Request JSON vars to be used in templates
  pub vars:    HashMap<String, TemplateVar>,
}

impl Request {
  pub fn validate(&self) -> Result<(), ProofError> {
    // TODO: What HTTP methods are supported?
    const ALLOWED_METHODS: [&str; 2] = ["GET", "POST"];
    if !ALLOWED_METHODS.contains(&self.method.as_str()) {
      return Err(ProofError::InvalidManifest("Invalid HTTP method".to_string()));
    }

    // Not a valid URL
    if url::Url::parse(&self.url).is_err() {
      return Err(ProofError::InvalidManifest("Invalid URL: ".to_string() + &self.url));
    }

    if !self.url.starts_with("https://") {
      return Err(ProofError::InvalidManifest("Only HTTPS URLs are allowed".to_string()));
    }

    // TODO: What HTTP versions are supported?
    if self.version != "HTTP/1.1" {
      return Err(ProofError::InvalidManifest(
        "Invalid HTTP version: ".to_string() + &self.version,
      ));
    }

    Ok(())
  }

  fn validate_vars(&self) -> Result<(), ProofError> {
    let mut all_tokens = vec![];

    // Parse and validate tokens in the body
    if let Some(body_tokens) = self.body.as_ref().map(extract_tokens) {
      for token in &body_tokens {
        if !self.vars.contains_key(token) {
          return Err(ProofError::InvalidManifest(format!(
            "Token `<% {} %>` not declared in `vars`",
            token
          )));
        }
      }
      all_tokens.extend(body_tokens);
    }

    // Parse and validate tokens in headers
    for value in self.headers.values() {
      let header_tokens = extract_tokens(&serde_json::Value::String(value.clone()));
      for token in &header_tokens {
        if !self.vars.contains_key(token) {
          return Err(ProofError::InvalidManifest(format!(
            "Token `<% {} %>` not declared in `vars`",
            token
          )));
        }
      }
      all_tokens.extend(header_tokens);
    }

    for var_key in self.vars.keys() {
      if !all_tokens.contains(var_key) {
        return Err(ProofError::InvalidManifest(format!(
          "Token `<% {} %>` not declared in `body` or `headers`",
          var_key
        )));
      }
    }

    // Validate each `vars` entry
    for (key, var_def) in &self.vars {
      // Validate regex (if defined)
      if let Some(regex_pattern) = var_def.regex.as_ref() {
        // Using `regress` crate for compatibility with ECMAScript regular expressions
        let _regex = regress::Regex::new(regex_pattern).map_err(|_| {
          ProofError::InvalidManifest(format!("Invalid regex pattern for `{}`", key))
        })?;
        // TODO: It will definitely not match it here because it's a template variable, not an
        // actual variable
        // TODO: How does the Manifest receiver (notary) verifies this?
        // if let Some(value) = self.body.as_ref().and_then(|b| b.get(key)) {
        //   if regex.find(value.as_str().unwrap_or("")).is_none() {
        //     return Err(ProofError::InvalidManifest(format!(
        //       "Value for token `<% {} %>` does not match regex",
        //       key
        //     )));
        //   }
        // }
      }

      // Validate length (if applicable)
      if let Some(length) = var_def.length {
        if let Some(value) = self.body.as_ref().and_then(|b| b.get(key)) {
          if value.as_str().unwrap_or("").len() != length {
            return Err(ProofError::InvalidManifest(format!(
              "Value for token `<% {} %>` does not meet length constraint",
              key
            )));
          }
        }
      }

      // TODO: Validate the token "type" constraint
    }
    Ok(())
  }

  pub fn from_payload(header_bytes: &[u8], body_bytes: Option<&[u8]>) -> Result<Self, ProofError> {
    let (method, url, version, headers) = Self::parse_header(header_bytes)?;
    // TODO: Do we expect requests to have bodies?
    let body = if let Some(bytes) = body_bytes {
      Some(
        serde_json::from_slice(bytes)
          .map_err(|_| ProofError::InvalidManifest("Invalid body bytes".to_string()))?,
      )
    } else {
      None
    };
    Ok(Self { method, url, version, headers, body, vars: HashMap::new() })
  }

  /// Parses the HTTP request start-line and headers from the given bytes.
  fn parse_header(
    header_bytes: &[u8],
  ) -> Result<(String, String, String, HashMap<String, String>), ProofError> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
      ProofError::InvalidManifest("Failed to interpret headers as valid UTF-8".to_string())
    })?;
    let mut lines = header_str.lines();

    let start_line = lines.next().ok_or_else(|| {
      ProofError::InvalidManifest("Missing start-line in the HTTP request.".to_string())
    })?;

    let parts: Vec<&str> = start_line.split_whitespace().collect();
    if parts.len() < 3 {
      return Err(ProofError::InvalidManifest("Invalid HTTP request start-line.".to_string()));
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let version = parts[2].to_string();

    let mut headers = HashMap::new();
    for line in lines {
      if line.trim().is_empty() {
        continue; // Skip empty lines
      }
      if let Some((key, value)) = line.split_once(": ") {
        headers.insert(key.to_string(), value.to_string());
      } else {
        return Err(ProofError::InvalidManifest(format!("Invalid header line: {}", line)));
      }
    }

    Ok((method, path, version, headers))
  }

  /// Checks if the current request is a subset of the given `other` request.
  /// For the request to be a subset:
  /// - All headers in `self` must exist in `other` with matching values.
  /// - All vars in `self` must exist in `other` with matching constraints.
  /// - All remaining fields like `method`, `url`, and `body` must also match.
  pub fn is_subset_of(&self, other: &Request) -> bool {
    // Check if all headers in `self` exist in `other` with the same value
    for (key, value) in &self.headers {
      if other.headers.get(key) != Some(value) {
        return false;
      }
    }

    // TODO: Not sure how to handle `vars` now, so disabling this
    // Check if all vars in `self` exist in `other` with the same or compatible constraints
    // for (key, var) in &self.vars {
    //   match other.vars.get(key) {
    //     Some(other_var) =>
    //       if var != other_var {
    //         return false;
    //       },
    //     None => {
    //       return false;
    //     },
    //   }
    // }

    // TODO: Notice that we match body exactly below
    // TODO: What to do with the body? Ominous
    // self.method == other.method && self.url == other.url && self.body == other.body
    self.method == other.method && self.url == other.url
  }
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;

  #[macro_export]
  macro_rules! create_request {
    // Match with optional parameters
    ($($key:ident: $value:expr),* $(,)?) => {{
        let mut request = Request {
            method: "GET".to_string(),
            url: "https://example.com".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: std::collections::HashMap::from([
                ("Authorization".to_string(), "Bearer <TOKEN>".to_string()),
                ("User-Agent".to_string(), "test-agent".to_string()),
            ]),
            body: None,
            vars: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                TemplateVar {
                    regex: Some("^[A-Za-z0-9]+$".to_string()),
                    length: Some(20),
                    r#type: Some("base64".to_string()),
                },
            )]),
        };

        // Override default fields with provided arguments
        $(
            request.$key = $value;
        )*

        request
    }};
  }

  #[macro_export]
  macro_rules! create_response {
    // Match with optional parameters
    ($($key:ident: $value:expr),* $(,)?) => {{
        let mut response = Response {
            status: "200".to_string(),
            version: "HTTP/1.1".to_string(),
            message: "OK".to_string(),
            headers: std::collections::HashMap::from([
                ("Content-Type".to_string(), "application/json".to_string())
            ]),
            body: ResponseBody {
                json: vec![JsonKey::String("key1".to_string()), JsonKey::String("key2".to_string())],
            },
        };

        // Override default fields with provided arguments
        $(
            response.$key = $value;
        )*

        response
    }};
  }

  #[test]
  fn test_parse_response() {
    let header_bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let body_bytes = br#"{"key1": "value1", "key2": "value2"}"#;
    let response = Response::from_payload(header_bytes, body_bytes).unwrap();
    assert_eq!(response.status, "200");
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(response.message, "OK");
    assert_eq!(response.headers.len(), 1);
    assert_eq!(response.headers.get("Content-Type").unwrap(), "application/json");
    assert_eq!(response.body.json.len(), 2);
    assert_eq!(response.body.json[0], JsonKey::String("key1".to_string()));
    assert_eq!(response.body.json[1], JsonKey::String("key2".to_string()));
  }

  #[test]
  fn test_matches_other_response() {
    let sourced_response = create_response!(
        headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        body: ResponseBody {
            json: vec![JsonKey::String("key1".to_string()), JsonKey::String("key2".to_string())],
        }
    );

    // Matches a perfect match
    assert!(sourced_response.is_subset_of(&sourced_response));

    // Fails if it doesn't match directly
    let non_matching_response = create_response!(status: "201".to_string());
    assert!(!sourced_response.is_subset_of(&non_matching_response));

    // Superset case
    let response_superset = {
      let mut res = sourced_response.clone();
      res.headers.insert("extra".to_string(), "header".to_string());
      res.body.json.push(JsonKey::String("key3".to_string()));
      res
    };
    assert!(sourced_response.is_subset_of(&response_superset));
  }

  #[test]
  fn test_response_with_missing_body() {
    let response =
      Response::from_payload(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n", br#""#)
        .unwrap();
    let expected_response = create_response!(
        headers: HashMap::from([("Content-Type".to_string(), "text/plain".to_string())]),
        body: ResponseBody { json: vec![] }
    );
    assert_eq!(response, expected_response);
  }

  #[test]
  fn test_invalid_body_parsing() {
    let header_bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let invalid_body_bytes = br#"This is not JSON"#;

    let result = Response::from_payload(header_bytes, invalid_body_bytes);
    assert!(result.is_err());

    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Failed to parse body as valid JSON"));
      },
      _ => panic!("Expected invalid manifest error for body parsing"),
    }
  }

  #[test]
  fn test_validate_invalid_status() {
    let response = create_response!(
        status: "404".to_string(), // Invalid status code
        message: "Not Found".to_string()
    );

    let result = response.validate();
    assert!(result.is_err());

    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Unsupported HTTP status"));
      },
      _ => panic!("Expected invalid manifest error for unsupported HTTP status"),
    }
  }

  #[test]
  fn test_validate_empty_message() {
    let response = create_response!(
        message: "".to_string(), // Invalid, empty message
        body: ResponseBody { json: vec![JsonKey::String("key1".to_string())] }
    );
    let result = response.validate();
    assert!(result.is_err());

    if let Err(ProofError::InvalidManifest(msg)) = result {
      assert!(msg.contains("Invalid message length"));
    } else {
      panic!("Expected invalid manifest error for empty message");
    }
  }

  #[test]
  fn test_valid_response_with_optional_body() {
    let response = Response::from_payload(
      b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
      br#"{"key1": "value1"}"#,
    )
    .unwrap();

    let expected_response = create_response!(
        body: ResponseBody {
            json: vec![JsonKey::String("key1".to_string())]
        }
    );
    assert_eq!(response, expected_response);
  }

  #[test]
  fn test_response_missing_json_with_application_json_header() {
    let header_bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let empty_body_bytes = br#"{}"#;

    let result = Response::from_payload(header_bytes, empty_body_bytes);
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.body.json.len(), 0);
  }

  #[test]
  fn test_subset_with_missing_key_in_other() {
    let base_response = create_response!(
        status: "200".to_string(),
        version: "HTTP/1.1".to_string(),
        message: "OK".to_string(),
        headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        body: ResponseBody {
            json: vec![JsonKey::String("key1".to_string()), JsonKey::String("key2".to_string())]
        }
    );
    let other_response = create_response!(
        status: "200".to_string(),
        version: "HTTP/1.1".to_string(),
        message: "OK".to_string(),
        headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        body: ResponseBody {
            json: vec![JsonKey::String("key1".to_string())] // Missing "key2"
        }
    );
    assert!(!base_response.is_subset_of(&other_response));
  }

  #[test]
  fn test_parse_request_valid_with_body() {
    let header_bytes = b"POST /path HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let body_bytes = br#"{"key1": "value1"}"#;

    let request = Request::from_payload(header_bytes, Some(body_bytes)).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "/path");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.headers.get("Content-Type").unwrap(), "application/json");
    assert!(request.body.is_some());
    assert!(request.body.unwrap().as_object().unwrap().contains_key("key1"));
  }

  #[test]
  fn test_parse_request_valid_without_body() {
    let header_bytes = b"GET /path HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n";

    let request = Request::from_payload(header_bytes, None).unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.url, "/path");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.headers.get("Content-Type").unwrap(), "text/plain");
    assert!(request.body.is_none());
  }

  #[test]
  fn test_invalid_header_utf8() {
    let header_bytes = b"\xFF\xFEInvalid UTF-8 Header";
    let body_bytes = br#"{}"#;

    let result = Request::from_payload(header_bytes, Some(body_bytes));
    assert!(result.is_err());

    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Failed to interpret headers as valid UTF-8"));
      },
      _ => panic!("Expected invalid UTF-8 headers error"),
    }
  }

  #[test]
  fn test_invalid_request_start_line() {
    let header_bytes = b"INVALID_START_LINE\r\nContent-Type: application/json\r\n\r\n";
    let body_bytes = br#"{}"#;

    let result = Request::from_payload(header_bytes, Some(body_bytes));
    assert!(result.is_err());

    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Invalid HTTP request start-line"));
      },
      _ => panic!("Expected invalid start-line error"),
    }
  }

  #[test]
  fn test_https_url_validation() {
    let header_bytes = b"GET /path HTTP/1.1\r\n\r\n";

    let mut request = Request::from_payload(header_bytes, None).unwrap();
    request.url = "http://example.com".to_string(); // Invalid (HTTP instead of HTTPS)

    let result = request.validate();
    assert!(result.is_err());
    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Only HTTPS URLs are allowed"));
      },
      _ => panic!("Expected error for non-HTTPS URL"),
    }
  }

  #[test]
  fn test_multiple_headers_parsing() {
    let header_bytes = b"POST /path HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer token\r\n\r\n";
    let body_bytes = br#"{"key": "value"}"#;

    let request = Request::from_payload(header_bytes, Some(body_bytes)).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers.len(), 2);
    assert_eq!(request.headers.get("Authorization").unwrap(), "Bearer token");
  }

  #[test]
  fn test_parse_invalid_body() {
    let header_bytes = b"POST /path HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let invalid_body_bytes = b"This is not a valid JSON body";

    let result = Request::from_payload(header_bytes, Some(invalid_body_bytes));
    assert!(result.is_err());

    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Invalid body bytes"));
      },
      _ => panic!("Expected invalid body parsing error"),
    }
  }

  #[test]
  fn test_validate_vars_with_missing_token() {
    let header_bytes = b"POST /path HTTP/1.1\r\nX-Custom-Header: <% missing_token %>\r\n\r\n";
    let body_bytes = br#"{"key": "value"}"#;

    let mut request = Request::from_payload(header_bytes, Some(body_bytes)).unwrap();
    request.vars = HashMap::new(); // No vars provided, but the template references a token

    let result = request.validate_vars();
    assert!(result.is_err());

    match result {
      Err(ProofError::InvalidManifest(msg)) => {
        assert!(msg.contains("Token `<% missing_token %>` not declared in `vars`"));
      },
      _ => panic!("Expected missing token error"),
    }
  }

  #[test]
  fn test_request_subset_comparison() {
    let base_request = create_request!(
        method: "GET".to_string(),
        url: "/path".to_string(),
        headers: HashMap::from([("Authorization".to_string(), "Bearer token".to_string())]),
        body: None,
        vars: HashMap::new()
    );

    // Create a superset of the base request with an additional header
    let mut other_request = base_request.clone();
    other_request.headers.insert("Extra-Header".to_string(), "Extra-Value".to_string());
    assert!(base_request.is_subset_of(&other_request));

    // Modify the method in the other request, making it not a subset
    other_request.method = "POST".to_string();
    assert!(!base_request.is_subset_of(&other_request));
  }
}
