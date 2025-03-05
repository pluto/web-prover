//! # HTTP Module
//!
//! The `http` module provides utilities for handling HTTP-related operations in the proof system.
//!
//! ## Structs
//!
//! - `ResponseBody`: Represents the body of an HTTP response, containing a vector of JSON keys.
//! - `Response`: Represents an HTTP response, including status, version, message, headers, and
//!   body.
//!
//! ## Functions
//!
//! - `default_version`: Returns the default HTTP version string.
//! - `default_message`: Returns the default HTTP response message string.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;
pub use web_proof_circuits_witness_generator::json::JsonKey;

use crate::{
  errors::ManifestError,
  parser::{DataFormat, ExtractionValues, ExtractorConfig},
  template,
  template::TemplateVar,
};

/// Max HTTP headers
pub const MAX_HTTP_HEADERS: usize = 25;
/// HTTP/1.1
pub const HTTP_1_1: &str = "HTTP/1.1";

/// A type of response body used to describe conditions in the client `Manifest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ManifestResponseBody(pub ExtractorConfig);

impl ManifestResponseBody {
  // TODO: A workaround for backwards-compatibility with JsonKey
  // TODO: It doesn't afford any security
  /// Returns the IDs of all extractors in the configuration
  pub fn json_path(&self) -> Vec<JsonKey> {
    self
      .0
      .extractors
      .iter()
      .flat_map(|extractor| extractor.selector.iter().map(|s| JsonKey::String(s.clone())))
      .collect()
  }
}

/// A type of response body returned by a notary. Must match `ManifestResponseBody` designated
/// by the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotaryResponseBody {
  /// Raw JSON value returned by a notary.
  pub json: Option<serde_json::Value>,
}

impl TryFrom<&[u8]> for NotaryResponseBody {
  type Error = ManifestError;

  fn try_from(body_bytes: &[u8]) -> Result<Self, Self::Error> {
    if body_bytes.is_empty() {
      return Ok(Self { json: None });
    }
    // Attempt to parse the body as JSON.
    let json: serde_json::Value = serde_json::from_slice(body_bytes).map_err(|_| {
      ManifestError::InvalidManifest("Failed to parse body as valid JSON".to_string())
    })?;
    Ok(Self { json: Some(json) })
  }
}

/// A response the made by the notary for a request from the client. Must match client response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotaryResponse {
  /// Client-designated response recovered from the notary
  pub response:             ManifestResponse,
  /// Raw response body from the notary
  pub notary_response_body: NotaryResponseBody,
}

impl NotaryResponse {
  /// Recovers all `Response` fields from the given payloads and creates a `Response` struct.
  ///
  /// - `header_bytes`: The bytes representing the HTTP response headers and metadata.
  /// - `body_bytes`: The bytes representing the HTTP response body.
  pub fn from_payload(bytes: &[u8]) -> Result<Self, ManifestError> {
    let delimiter = b"\r\n\r\n";
    let split_position = bytes
      .windows(delimiter.len())
      .position(|window| window == delimiter)
      .ok_or_else(|| ManifestError::InvalidManifest("Invalid HTTP format".to_string()))?;

    let (header_bytes, rest) = bytes.split_at(split_position);
    let body_bytes = &rest[delimiter.len()..];

    let (headers, status, version, message) = Self::parse_header(header_bytes)?;
    // We don't even parse the body here because we don't care about JSON path at this point
    let body = ManifestResponseBody::default();
    let response = ManifestResponse { status, version, message, headers, body };
    let notary_response_body = NotaryResponseBody::try_from(body_bytes)?;
    Ok(Self { response, notary_response_body })
  }

  /// Parses the HTTP response header from the given bytes.
  ///
  /// # Arguments
  ///
  /// * `header_bytes`: The bytes representing the HTTP response header.
  ///
  /// # Returns
  ///
  /// The parsed HTTP response header.
  fn parse_header(
    header_bytes: &[u8],
  ) -> Result<(HashMap<String, String>, String, String, String), ManifestError> {
    let headers_str = std::str::from_utf8(header_bytes).map_err(|_| {
      ManifestError::InvalidManifest("Failed to interpret headers as valid UTF-8".to_string())
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
          return Err(ManifestError::InvalidManifest(
            "Invalid HTTP response start-line".to_string(),
          ));
        }
        version = parts[0].to_string();
        status = parts[1].to_string();
        message = parts[2..].join(" ");
      } else {
        // Process subsequent lines as headers
        if let Some((key, value)) = line.split_once(": ") {
          headers.insert(key.to_string(), value.to_string());
        } else {
          return Err(ManifestError::InvalidManifest(format!("Invalid header line: {}", line)));
        }
      }
    }
    Ok((headers, status, version, message))
  }

  /// Tests matching between notary response, `self`,  and client-designated response, `other`.
  /// Returns `Some(values)` if at least all values in `other` are also present in `self` and `None`
  /// otherwise.
  pub fn match_and_extract(
    &self,
    other: &ManifestResponse,
  ) -> Result<Option<ExtractionValues>, ManifestError> {
    // Check basic response properties
    if self.response.status != other.status
      || self.response.version != other.version
      || self.response.message != other.message
    {
      debug!("Exact matches for status, version, or message do not match");
      return Ok(None);
    }

    // Check headers
    if !self.headers_match(other) {
      return Ok(None);
    }

    // Check body
    self.body_matches(other)
  }

  /// Helper method to check if headers match
  fn headers_match(&self, other: &ManifestResponse) -> bool {
    for (key, other_value) in &other.headers {
      match self
        .response
        .headers
        .get(key)
        .or_else(|| self.response.headers.get(&key.to_lowercase()))
      {
        Some(actual_value) if actual_value == other_value => continue,
        Some(actual_value) => {
          debug!(
            "Header mismatch for key: {}: expected={}, actual={}",
            key, other_value, actual_value
          );
          return false;
        },
        None => {
          debug!("Header key not present in self: {}", key);
          return false;
        },
      }
    }
    true
  }

  /// Helper method to check if body matches and extract values
  fn body_matches(
    &self,
    other: &ManifestResponse,
  ) -> Result<Option<ExtractionValues>, ManifestError> {
    match &self.notary_response_body.json {
      Some(json) => {
        let result = other.body.0.extract_and_validate(json)?;

        if !result.errors.is_empty() {
          debug!("JSON path does not match: {:?}", result.errors);
          return Ok(None);
        }

        if result.values.len() != other.body.0.extractors.len() {
          debug!("Not all extractors were matched");
          return Ok(None);
        }

        debug!("Client response matches");
        Ok(Some(result.values))
      },
      None if other.body.0.extractors.is_empty() => {
        // If we get here, there was a match but no JSON data to extract
        debug!("Client response matches (no JSON data)");
        Ok(Some(HashMap::new()))
      },
      None => {
        debug!("No JSON data to match against");
        Ok(None)
      },
    }
  }
}

/// Default HTTP version
fn default_version() -> String { HTTP_1_1.to_string() }
/// Default HTTP message
fn default_message() -> String { "OK".to_string() }

/// HTTP Response items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestResponse {
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
  pub body:    ManifestResponseBody,
}

impl ManifestResponse {
  /// Validates the HTTP response
  ///
  /// This function validates the HTTP response.
  ///
  /// # Arguments
  ///
  /// * `self`: The HTTP response to validate.
  ///
  /// # Returns
  ///
  /// The validated HTTP response.
  pub fn validate(&self) -> Result<(), ManifestError> {
    // We only support 200 and 201
    const VALID_STATUSES: [&str; 2] = ["200", "201"];
    if !VALID_STATUSES.contains(&self.status.as_str()) {
      return Err(ManifestError::InvalidManifest("Unsupported HTTP status".to_string()));
    }
    // We only support HTTP/1.1
    if self.version != "HTTP/1.1" {
      return Err(ManifestError::InvalidManifest(
        "Invalid HTTP version: ".to_string() + &self.version,
      ));
    }

    // An empty message is not allowed
    if self.message.len() > 1024 || self.message.is_empty() {
      return Err(ManifestError::InvalidManifest(
        "Invalid message length: ".to_string() + &self.message,
      ));
    }

    // We always expect at least one header, "Content-Type"
    if self.headers.len() > MAX_HTTP_HEADERS || self.headers.is_empty() {
      return Err(ManifestError::InvalidManifest(
        "Invalid headers length: ".to_string() + &self.headers.len().to_string(),
      ));
    }

    let content_type =
      self.headers.get("Content-Type").or_else(|| self.headers.get("content-type"));
    if content_type.is_none() {
      return Err(ManifestError::InvalidManifest("Missing 'Content-Type' header".to_string()));
    }
    let content_type = content_type.unwrap();

    const VALID_CONTENT_TYPES: [&str; 2] = ["application/json", "text/plain"];
    let is_valid_content_type = VALID_CONTENT_TYPES.iter().any(|&legal_type| {
      content_type == legal_type || content_type.starts_with(&format!("{};", legal_type))
    });
    if !is_valid_content_type {
      return Err(ManifestError::InvalidManifest(
        "Invalid Content-Type header: ".to_string() + content_type,
      ));
    }

    // When Content-Type is application/json, we expect at least one JSON item
    if content_type == "application/json" {
      if self.body.0.format != DataFormat::Json {
        return Err(ManifestError::InvalidManifest("Expected JSON format".to_string()));
      }

      if self.body.0.extractors.is_empty() {
        return Err(ManifestError::InvalidManifest("Expected at least one JSON item".to_string()));
      }
    }
    const MAX_EXTRACTORS: usize = 100;
    if self.body.0.extractors.len() > MAX_EXTRACTORS {
      return Err(ManifestError::InvalidManifest(format!(
        "Invalid extractors length: {}",
        self.body.0.extractors.len()
      )));
    }

    Ok(())
  }
}

/// Returns an empty `HashMap` as the default value for `vars`
fn default_empty_vars() -> HashMap<String, TemplateVar> { HashMap::new() }

/// HTTP Request items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestRequest {
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
  #[serde(default = "default_empty_vars")]
  pub vars:    HashMap<String, TemplateVar>,
}

impl ManifestRequest {
  /// This function validates the HTTP request.
  ///
  /// # Arguments
  ///
  /// * `self`: The HTTP request to validate.
  ///
  /// # Returns
  ///
  /// The validated HTTP request.
  pub fn validate(&self) -> Result<(), ManifestError> {
    // TODO: What HTTP methods are supported?
    const ALLOWED_METHODS: [&str; 2] = ["GET", "POST"];
    if !ALLOWED_METHODS.contains(&self.method.as_str()) {
      return Err(ManifestError::InvalidManifest("Invalid HTTP method".to_string()));
    }

    // Not a valid URL
    if url::Url::parse(&self.url).is_err() {
      return Err(ManifestError::InvalidManifest("Invalid URL: ".to_string() + &self.url));
    }

    if !self.url.starts_with("https://") {
      return Err(ManifestError::InvalidManifest("Only HTTPS URLs are allowed".to_string()));
    }

    // TODO: What HTTP versions are supported?
    if self.version != "HTTP/1.1" {
      return Err(ManifestError::InvalidManifest(
        "Invalid HTTP version: ".to_string() + &self.version,
      ));
    }

    Ok(())
  }

  // TODO(#517)
  #[allow(unused)]
  fn collect_tokens(&self) -> Vec<String> {
    let mut all_tokens = Vec::new();

    // Collect tokens from body
    if let Some(body_tokens) = self.body.as_ref().map(template::extract_tokens) {
      all_tokens.extend(body_tokens);
    }

    // Collect tokens from headers
    for value in self.headers.values() {
      let header_tokens = template::extract_tokens(&serde_json::Value::String(value.clone()));
      all_tokens.extend(header_tokens);
    }

    all_tokens
  }

  fn validate_tokens(&self, tokens: &[String]) -> Result<(), ManifestError> {
    for token in tokens {
      if !self.vars.contains_key(token) {
        return Err(ManifestError::InvalidManifest(format!(
          "Token `<% {} %>` not declared in `vars`",
          token
        )));
      }
    }
    Ok(())
  }

  pub fn validate_vars(&self) -> Result<(), ManifestError> {
    let all_tokens = self.collect_tokens();
    self.validate_tokens(&all_tokens)?;

    for (key, variable) in &self.vars {
      let is_used = all_tokens.contains(key);
      variable.validate(key, is_used)?;
    }

    Ok(())
  }

  /// Parses the HTTP request from the given bytes.
  pub fn from_payload(bytes: &[u8]) -> Result<Self, ManifestError> {
    // todo: dedup me
    let delimiter = b"\r\n\r\n";
    let split_position = bytes
      .windows(delimiter.len())
      .position(|window| window == delimiter)
      .ok_or_else(|| ManifestError::InvalidManifest("Invalid HTTP format".to_string()))?;

    let (header_bytes, rest) = bytes.split_at(split_position);
    let body_bytes = &rest[delimiter.len()..];

    let (method, url, version, headers) = Self::parse_header(header_bytes)?;

    let body = if !body_bytes.is_empty() {
      serde_json::from_slice(body_bytes)
        .map_err(|_| ManifestError::InvalidManifest("Invalid body bytes".to_string()))?
    } else {
      None
    };

    Ok(Self { method, url, version, headers, body, vars: HashMap::new() })
  }

  /// Parses the HTTP request start-line and headers from the given bytes.
  fn parse_header(
    header_bytes: &[u8],
  ) -> Result<(String, String, String, HashMap<String, String>), ManifestError> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
      ManifestError::InvalidManifest("Failed to interpret headers as valid UTF-8".to_string())
    })?;
    let mut lines = header_str.lines();

    let start_line = lines.next().ok_or_else(|| {
      ManifestError::InvalidManifest("Missing start-line in the HTTP request.".to_string())
    })?;

    let parts: Vec<&str> = start_line.split_whitespace().collect();
    if parts.len() < 3 {
      return Err(ManifestError::InvalidManifest("Invalid HTTP request start-line.".to_string()));
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
        return Err(ManifestError::InvalidManifest(format!("Invalid header line: {}", line)));
      }
    }

    Ok((method, path, version, headers))
  }

  /// Checks if the current request is a subset of the given `other` request.
  /// For the request to be a subset:
  /// - All headers in `self` must exist in `other` with matching values.
  /// - All vars in `self` must exist in `other` with matching constraints.
  /// - All remaining fields like `method`, `url`, and `body` must also match.
  pub fn is_subset_of(&self, other: &ManifestRequest) -> bool {
    // Check if all headers in `self` exist in `other` with the same value
    for (key, value) in &self.headers {
      let expected_header =
        other.headers.get(key).or_else(|| other.headers.get(&key.to_lowercase()));
      if expected_header != Some(value) {
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
pub mod tests {
  use std::{collections::HashMap, string::ToString};

  use serde_json::json;

  use super::*;
  use crate::{extractor, parser::ExtractorType};

  /// Creates a new `ManifestRequest` with optional parameters.
  #[macro_export]
  macro_rules! request {
    // Match with optional parameters
    ($($key:ident: $value:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut request = ManifestRequest {
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
                    description: Some("Authentication token".to_string()),
                    required: true,
                    default: None,
                    pattern: Some("^[A-Za-z0-9]+$".to_string()),
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

  /// Creates a new `ManifestResponse` with optional parameters.
  #[macro_export]
  macro_rules! response {
    // Match with optional parameters
    ($($key:ident: $value:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut response = ManifestResponse {
            status: "200".to_string(),
            version: "HTTP/1.1".to_string(),
            message: "OK".to_string(),
            headers: std::collections::HashMap::from([
                ("Content-Type".to_string(), "application/json".to_string())
            ]),
            body: ManifestResponseBody::default(),
        };

        // Override default fields with provided arguments
        $(
            response.$key = $value;
        )*

        response
    }};
  }

  /// Creates a `NotaryResponse` by taking a `ManifestResponse` and optional overrides for
  /// `NotaryResponseBody`.
  #[macro_export]
  macro_rules! notary_response {
    // Match with ManifestResponse and optional overrides for NotaryResponseBody
    ($response:expr, $($key:ident: $value:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut notary_response_body = NotaryResponseBody {
            json: Some(json!({})), // Default to empty JSON
        };

        // Apply custom key-value overrides for NotaryResponseBody
        $(
            notary_response_body.$key = $value;
        )*

        // Return the complete NotaryResponse
        NotaryResponse {
            response: $response,
            notary_response_body,
        }
    }};
  }

  #[test]
  fn test_parse_response() {
    let header_bytes: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let body = json!({"key1": { "key2": 3 }});
    let response =
      NotaryResponse::from_payload(&[header_bytes, body.to_string().as_bytes()].concat()).unwrap();
    assert_eq!(response.response.status, "200");
    assert_eq!(response.response.version, "HTTP/1.1");
    assert_eq!(response.response.message, "OK");
    assert_eq!(response.response.headers.len(), 1);
    assert_eq!(response.response.headers.get("Content-Type").unwrap(), "application/json");
    assert_eq!(response.response.body, ManifestResponseBody::default());
    assert_eq!(response.notary_response_body.json, Some(body));
  }

  #[test]
  fn test_notary_matches_other_response() {
    let response = response!(
        body: ManifestResponseBody(ExtractorConfig {
            format: DataFormat::Json,
            extractors: vec![extractor!(
                id: "testKey".to_string(),
                description: "Test key".to_string(),
                selector: vec!["key1".to_string(), "key2".to_string()],
                extractor_type: ExtractorType::Number,
            )],
        })
    );
    let notary_response = notary_response!(
      response.clone(),
      json: Some(json!({
            "key1": {"key2": 3},
        })),
    );

    // Is a perfect match with itself
    let matching_result = notary_response.match_and_extract(&response).unwrap();
    assert!(matching_result.is_some());
    assert_eq!(matching_result.unwrap().get("testKey").unwrap(), &json!(3));

    // Fails if it doesn't match directly
    let non_matching_response = response!(status: "201".to_string());
    assert!(notary_response.match_and_extract(&non_matching_response).unwrap().is_none());

    // Superset case
    let response_superset = {
      let mut res = notary_response.clone();
      res.response.headers.insert("extra".to_string(), "header".to_string());
      res.response.body.0.extractors.push(extractor!(
        id: "extra".to_string(),
        description: "Extra".to_string(),
        selector: vec!["key1".to_string(), "key2".to_string()],
        extractor_type: ExtractorType::Number,
      ));
      res
    };
    assert!(response_superset.match_and_extract(&response).unwrap().is_some());
  }

  #[test]
  fn test_response_with_missing_body() {
    let header_bytes: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    let empty_body: &[u8] = br#""#;

    let actual = NotaryResponse::from_payload(&[header_bytes, empty_body].concat()).unwrap();

    let expected = NotaryResponse {
      response:             response!(
        headers: HashMap::from([("Content-Type".to_string(), "text/plain".to_string())]),
        body: ManifestResponseBody::default(),
      ),
      notary_response_body: NotaryResponseBody { json: None },
    };

    assert_eq!(actual, expected);
  }

  #[test]
  fn test_invalid_body_parsing() {
    let header_bytes: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let invalid_body_bytes: &[u8] = br#"This is not JSON"#;

    let result = NotaryResponse::from_payload(&[header_bytes, invalid_body_bytes].concat());
    assert!(result.is_err());

    if let Err(ManifestError::InvalidManifest(msg)) = result {
      assert!(msg.contains("Failed to parse body as valid JSON"));
    } else {
      panic!("Expected an invalid manifest error for body parsing");
    }
  }

  #[test]
  fn test_validate_invalid_status() {
    let response = response!(
        status: "404".to_string(), // Invalid status code
        message: "Not Found".to_string()
    );

    let result = response.validate();
    assert!(result.is_err());

    match result {
      Err(ManifestError::InvalidManifest(msg)) => {
        assert!(msg.contains("Unsupported HTTP status"));
      },
      _ => panic!("Expected invalid manifest error for unsupported HTTP status"),
    }
  }

  #[test]
  fn test_validate_empty_message() {
    let invalid_response = response!(
        message: "".to_string(),
    );
    let result = invalid_response.validate();
    assert!(result.is_err());

    if let Err(ManifestError::InvalidManifest(msg)) = result {
      assert!(msg.contains("Invalid message length"));
    } else {
      panic!("Expected invalid manifest error for empty message");
    }
  }

  #[test]
  fn test_valid_response_with_optional_body() {
    let header_bytes: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let body_bytes: &[u8] = br#"{"key1": "value1"}"#;

    let response = NotaryResponse::from_payload(&[header_bytes, body_bytes].concat()).unwrap();
    let manifest_response = response!(
        headers: std::collections::HashMap::from([
            ("Content-Type".to_string(), "application/json".to_string())
        ]),
        body: ManifestResponseBody::default()
    );
    let expected_response = notary_response!(
        manifest_response,
        json: Some(json!({"key1": "value1"}))
    );

    assert_eq!(response, expected_response);
  }

  #[test]
  fn test_response_missing_json_with_application_json_header() {
    let header_bytes: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    let empty_body_bytes: &[u8] = br#"{}"#;

    let notary_response =
      NotaryResponse::from_payload(&[header_bytes, empty_body_bytes].concat()).unwrap();

    assert_eq!(notary_response.response.body, ManifestResponseBody::default());
    assert_eq!(notary_response.notary_response_body.json, Some(json!({})));
  }

  #[test]
  fn test_subset_with_missing_key_in_other() {
    let base_response = notary_response!(response!(),);
    let other_response = response!(
        body: ManifestResponseBody(ExtractorConfig {
            format: DataFormat::Json,
            extractors: vec![extractor!(
                id: "testKey".to_string(),
                description: "Test key".to_string(),
                selector: vec!["missingKey".to_string()],
                extractor_type: ExtractorType::String,
            )],
        })
    );
    assert!(!base_response.match_and_extract(&other_response).unwrap().is_some());
  }

  #[test]
  fn test_parse_request_valid_with_body() {
    let header_bytes: &[u8] = b"POST /path HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let body_bytes: &[u8] = br#"{"key1": "value1"}"#;

    let request = ManifestRequest::from_payload(&[header_bytes, body_bytes].concat()).unwrap();
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

    let request = ManifestRequest::from_payload(header_bytes).unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.url, "/path");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.headers.get("Content-Type").unwrap(), "text/plain");
    assert!(request.body.is_none());
  }

  #[test]
  fn test_invalid_header_utf8() {
    let header_bytes: &[u8] = b"\xFF\xFEInvalid UTF-8 Header\r\n\r\n";
    let body_bytes: &[u8] = br#"{}"#;

    let result = ManifestRequest::from_payload(&[header_bytes, body_bytes].concat());
    assert!(result.is_err());

    match result {
      Err(ManifestError::InvalidManifest(msg)) => {
        assert!(msg.contains("Failed to interpret headers as valid UTF-8"));
      },
      _ => panic!("Expected invalid UTF-8 headers error"),
    }
  }

  #[test]
  fn test_invalid_request_start_line() {
    let header_bytes: &[u8] = b"INVALID_START_LINE\r\nContent-Type: application/json\r\n\r\n";
    let body_bytes: &[u8] = br#"{}"#;

    let result = ManifestRequest::from_payload(&[header_bytes, body_bytes].concat());
    assert!(result.is_err());

    match result {
      Err(ManifestError::InvalidManifest(msg)) => {
        assert!(msg.contains("Invalid HTTP request start-line"));
      },
      _ => panic!("Expected invalid start-line error"),
    }
  }

  #[test]
  fn test_https_url_validation() {
    let header_bytes: &[u8] = b"GET /path HTTP/1.1\r\n\r\n";

    let mut request = ManifestRequest::from_payload(header_bytes).unwrap();
    request.url = "http://example.com".to_string(); // Invalid (HTTP instead of HTTPS)

    let result = request.validate();
    assert!(result.is_err());
    match result {
      Err(ManifestError::InvalidManifest(msg)) => {
        assert!(msg.contains("Only HTTPS URLs are allowed"));
      },
      _ => panic!("Expected error for non-HTTPS URL"),
    }
  }

  #[test]
  fn test_multiple_headers_parsing() {
    let header_bytes: &[u8] = b"POST /path HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer token\r\n\r\n";
    let body_bytes: &[u8] = br#"{"key": "value"}"#;

    let request = ManifestRequest::from_payload(&[header_bytes, body_bytes].concat()).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers.len(), 2);
    assert_eq!(request.headers.get("Authorization").unwrap(), "Bearer token");
  }

  #[test]
  fn test_parse_invalid_body() {
    let header_bytes: &[u8] = b"POST /path HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    let invalid_body_bytes: &[u8] = b"This is not a valid JSON body";

    let result = ManifestRequest::from_payload(&[header_bytes, invalid_body_bytes].concat());
    assert!(result.is_err());

    match result {
      Err(ManifestError::InvalidManifest(msg)) => {
        assert!(msg.contains("Invalid body bytes"));
      },
      _ => panic!("Expected invalid body parsing error"),
    }
  }

  #[test]
  fn test_request_with_template_vars() {
    let header_bytes: &[u8] = b"POST /path HTTP/1.1\r\nX-Custom-Header: <% test_var %>\r\n\r\n";
    let body_bytes: &[u8] = br#"{"key": "value"}"#;

    let mut request = ManifestRequest::from_payload(&[header_bytes, body_bytes].concat()).unwrap();
    request.vars.insert("test_var".to_string(), TemplateVar {
      description: Some("Test variable".to_string()),
      required:    true,
      default:     None,
      pattern:     Some("^[A-Za-z0-9]+$".to_string()),
    });

    assert!(request.validate_vars().is_ok());
  }
}
