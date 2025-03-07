//! # HTTP Module
//!
//! The `http` module provides utilities for handling HTTP-related operations in the proof system.
//! It defines structures and functions for representing, parsing, and validating HTTP requests
//! and responses.
//!
//! ## Key Components
//!
//! ### Request Handling
//!
//! - [`ManifestRequest`]: Defines the expected HTTP request pattern in a manifest
//! - [`TemplateVar`]: Defines template variables that can be used in requests
//!
//! ### Response Handling
//!
//! - [`ManifestResponse`]: Defines the expected HTTP response pattern in a manifest
//! - [`ManifestResponseBody`]: Represents the body of an expected HTTP response
//! - [`NotaryResponse`]: Represents an actual HTTP response from a notary service
//! - [`NotaryResponseBody`]: Represents the body of an actual HTTP response
//!
//! ### JSON Path Handling
//!
//! - [`JsonKey`]: Represents a key in a JSON path (either a string key or array index)
//!
//! ## Constants
//!
//! - [`MAX_HTTP_HEADERS`]: Maximum number of HTTP headers allowed
//! - [`HTTP_1_1`]: HTTP/1.1 version string
//!
//! ## Functions
//!
//! - [`default_version`]: Returns the default HTTP version string
//! - [`default_message`]: Returns the default HTTP response message string

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

/// Represents a key in a JSON path, which can be either a string key for objects
/// or a numeric index for arrays.
///
/// This enum is used to define paths for traversing JSON structures when validating
/// response bodies against expected patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum JsonKey {
  /// A string key used to access properties in a JSON object
  String(String),
  /// A numeric index used to access elements in a JSON array
  Num(usize),
}

use crate::error::WebProverCoreError;

/// Maximum number of HTTP headers allowed in a request or response
pub const MAX_HTTP_HEADERS: usize = 25;
/// HTTP/1.1 version string constant
pub const HTTP_1_1: &str = "HTTP/1.1";

/// A type of response body used to describe conditions in the client `Manifest`.
///
/// This structure defines the expected format and content of an HTTP response body
/// in a manifest, particularly focusing on JSON path traversal for validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ManifestResponseBody {
  /// JSON Path containing expected traversal keys and expected value.
  ///
  /// This vector defines a path through a JSON structure that should be present
  /// in the response. Each element in the vector represents a key or index in the
  /// path, with the last element typically being the expected value.
  #[serde(rename = "json")] // TODO: Remove after migrating to a JSON DSL
  pub json_path: Vec<JsonKey>,
}

impl TryFrom<&[u8]> for ManifestResponseBody {
  type Error = WebProverCoreError;

  /// Attempts to create a `ManifestResponseBody` from a byte slice.
  ///
  /// If the byte slice is empty, returns a default `ManifestResponseBody` with an empty path.
  /// Otherwise, attempts to parse the bytes as a JSON array of `JsonKey` elements.
  ///
  /// # Arguments
  ///
  /// * `body_bytes` - The byte slice containing the JSON representation of the path
  ///
  /// # Returns
  ///
  /// A `Result` containing either the parsed `ManifestResponseBody` or an error
  fn try_from(body_bytes: &[u8]) -> Result<Self, Self::Error> {
    if body_bytes.is_empty() {
      return Ok(Self { json_path: vec![] });
    }
    // Attempt to parse the body as JSON path.
    let json_path: Vec<JsonKey> = serde_json::from_slice(body_bytes).map_err(|_| {
      WebProverCoreError::InvalidManifest("Failed to parse body as valid JSON".to_string())
    })?;
    Ok(Self { json_path })
  }
}

/// A type of response body returned by a notary. Must match `ManifestResponseBody` designated
/// by the client.
///
/// This structure represents the actual JSON response body received from a notary service,
/// which will be validated against the expected pattern defined in a `ManifestResponseBody`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotaryResponseBody {
  /// Raw JSON value returned by a notary.
  ///
  /// This field contains the parsed JSON response from the notary service.
  /// It is `None` if the response body was empty or could not be parsed as JSON.
  pub json: Option<serde_json::Value>,
}

impl TryFrom<&[u8]> for NotaryResponseBody {
  type Error = WebProverCoreError;

  /// Attempts to create a `NotaryResponseBody` from a byte slice.
  ///
  /// If the byte slice is empty, returns a `NotaryResponseBody` with `json` set to `None`.
  /// Otherwise, attempts to parse the bytes as a JSON value.
  ///
  /// # Arguments
  ///
  /// * `body_bytes` - The byte slice containing the JSON response
  ///
  /// # Returns
  ///
  /// A `Result` containing either the parsed `NotaryResponseBody` or an error
  fn try_from(body_bytes: &[u8]) -> Result<Self, Self::Error> {
    if body_bytes.is_empty() {
      return Ok(Self { json: None });
    }
    // Attempt to parse the body as JSON.
    let json: serde_json::Value = serde_json::from_slice(body_bytes).map_err(|_| {
      WebProverCoreError::InvalidManifest("Failed to parse body as valid JSON".to_string())
    })?;
    Ok(Self { json: Some(json) })
  }
}

impl NotaryResponseBody {
  /// Verifies if the notary's JSON response matches the client-provided `json_path`.
  ///
  /// The `json_path` defines a sequence of keys for traversing the JSON structure.
  /// Each key specifies either:
  /// - A string to look for in a JSON object.
  /// - An index to access an element in a JSON array.
  /// - A concrete value at the end of the path.
  ///
  /// The function traverses the JSON step-by-step, returning `true` if all keys match,
  /// or `false` otherwise.
  ///
  /// # Arguments
  ///
  /// * `json_path` - A slice of `JsonKey` elements defining the expected path
  ///
  /// # Returns
  ///
  /// `true` if the JSON response matches the expected path, `false` otherwise
  fn matches_path(&self, json_path: &[JsonKey]) -> bool {
    if json_path.is_empty() {
      debug!("Invalid json_path: Path is empty");
      return false;
    }
    let Some(json) = &self.json else {
      debug!("No JSON data to match against");
      return false;
    };
    self.traverse_json_path(json, json_path)
  }

  /// Traverses a JSON value using a specified path of keys and verifies if it matches the given
  /// sequence.
  ///
  /// # Arguments
  /// * `initial_value` - The root JSON value to start traversal from.
  /// * `json_path` - A sequence of `JsonKey` elements defining the traversal path.
  ///
  /// # Returns
  /// `true` if the traversal successfully matches the sequence or reaches the expected value;
  /// `false` otherwise.
  fn traverse_json_path(&self, initial_value: &serde_json::Value, json_path: &[JsonKey]) -> bool {
    let mut current = initial_value;

    for (i, key) in json_path.iter().enumerate() {
      // If the element is last, we return true because we've reached the end of the path
      let is_last = i == json_path.len() - 1;

      match key {
        JsonKey::String(expected) => {
          if !self.handle_string_key(current, expected, is_last) {
            return false;
          }
          if is_last {
            return true;
          }
          current = current.as_object().and_then(|obj| obj.get(expected)).unwrap();
        },
        JsonKey::Num(expected) => {
          if !self.handle_numeric_key(current, expected, is_last) {
            return false;
          }
          if is_last {
            return true;
          }
          current = current.as_array().and_then(|arr| arr.get(*expected)).unwrap();
        },
      }
    }

    false
  }

  /// Handles validation for string keys in the JSON path.
  ///
  /// # Arguments
  ///
  /// * `current` - The current JSON value being examined
  /// * `expected` - The expected string key or value
  /// * `is_last` - Whether this is the last element in the path
  ///
  /// # Returns
  ///
  /// `true` if the key exists or the value matches (if last), `false` otherwise
  fn handle_string_key(&self, current: &serde_json::Value, expected: &str, is_last: bool) -> bool {
    match current {
      serde_json::Value::String(actual) => is_last && actual == expected,
      serde_json::Value::Object(obj) => obj.contains_key(expected),
      _ => {
        debug!("Expected string or object, found: {:?}", current);
        false
      },
    }
  }

  /// Handles validation for numeric keys in the JSON path.
  ///
  /// # Arguments
  ///
  /// * `current` - The current JSON value being examined
  /// * `expected` - The expected array index or numeric value
  /// * `is_last` - Whether this is the last element in the path
  ///
  /// # Returns
  ///
  /// `true` if the index exists or the value matches (if last), `false` otherwise
  fn handle_numeric_key(
    &self,
    current: &serde_json::Value,
    expected: &usize,
    is_last: bool,
  ) -> bool {
    match current {
      serde_json::Value::Number(actual) => {
        if !is_last {
          return false;
        }
        if let Some(n) = actual.as_u64() {
          return n == (*expected as u64);
        }
        if let Some(n) = actual.as_i64() {
          return n == (*expected as i64);
        }
        if let Some(n) = actual.as_f64() {
          return (n - (*expected as f64)).abs() < f64::EPSILON;
        }
        false
      },
      serde_json::Value::Array(arr) => expected >= &0 && *expected < arr.len(),
      _ => {
        debug!("Expected number or array, found: {:?}", current);
        false
      },
    }
  }
}

/// A response made by the notary for a request from the client. Must match client response.
///
/// This structure represents a complete HTTP response from a notary service, including
/// both the response metadata (status, headers, etc.) and the parsed body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotaryResponse {
  /// Client-designated response recovered from the notary.
  ///
  /// This field contains the parsed HTTP response metadata, including status code,
  /// headers, and other information.
  pub response: ManifestResponse,

  /// Raw response body from the notary.
  ///
  /// This field contains the parsed JSON body of the response, which will be
  /// validated against the expected pattern.
  pub notary_response_body: NotaryResponseBody,
}

impl NotaryResponse {
  /// Recovers all `Response` fields from the given payloads and creates a `Response` struct.
  ///
  /// # Arguments
  ///
  /// * `bytes` - The complete HTTP response as a byte slice, including headers and body
  ///
  /// # Returns
  ///
  /// A `Result` containing either the parsed `NotaryResponse` or an error
  pub fn from_payload(bytes: &[u8]) -> Result<Self, WebProverCoreError> {
    let delimiter = b"\r\n\r\n";
    let split_position = bytes
      .windows(delimiter.len())
      .position(|window| window == delimiter)
      .ok_or_else(|| WebProverCoreError::InvalidManifest("Invalid HTTP format".to_string()))?;

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
  /// A tuple containing the parsed headers, status code, HTTP version, and status message.
  fn parse_header(
    header_bytes: &[u8],
  ) -> Result<(HashMap<String, String>, String, String, String), WebProverCoreError> {
    let headers_str = std::str::from_utf8(header_bytes).map_err(|_| {
      WebProverCoreError::InvalidManifest("Failed to interpret headers as valid UTF-8".to_string())
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
          return Err(WebProverCoreError::InvalidManifest(
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
          return Err(WebProverCoreError::InvalidManifest(format!(
            "Invalid header line: {}",
            line
          )));
        }
      }
    }
    Ok((headers, status, version, message))
  }

  /// Tests matching between notary response, `self`, and client-designated response, `other`.
  /// Returns true if at least all values in `other` are also present in `self`.
  ///
  /// # Arguments
  ///
  /// * `other` - The client-designated response to match against
  ///
  /// # Returns
  ///
  /// `true` if the notary response matches the client manifest, `false` otherwise
  pub fn matches_client_manifest(&self, other: &ManifestResponse) -> bool {
    if self.response.status != other.status
      || self.response.version != other.version
      || self.response.message != other.message
    {
      debug!("Exact matches for status, version, or message do not match");
      return false;
    }

    // Ensure all headers in `other` are present in `self`
    for (key, other_value) in &other.headers {
      let value =
        self.response.headers.get(key).or_else(|| self.response.headers.get(&key.to_lowercase()));
      if let Some(actual_value) = value {
        if actual_value != other_value {
          debug!(
            "Header mismatch for key: {}: expected={}, actual={}",
            key, other_value, actual_value
          );
          return false;
        }
      } else {
        debug!("Header key not present in self: {}", key);
        return false;
      }
    }

    // Check if the `body` of `other` matches the `json_path` within `self`.
    if !self.notary_response_body.matches_path(&other.body.json_path) {
      debug!(
        "JSON path does not match. notary_response_body={:?}, json_path={:?}",
        self.notary_response_body, other.body.json_path,
      );
      return false;
    }

    debug!("Client response matches");
    true
  }
}

/// Returns the default HTTP version string (HTTP/1.1)
pub fn default_version() -> String { HTTP_1_1.to_string() }

/// Returns the default HTTP response message string ("OK")
pub fn default_message() -> String { "OK".to_string() }

/// Returns an empty `HashMap` as the default value for `vars`
fn default_empty_vars() -> HashMap<String, TemplateVar> { HashMap::new() }

/// HTTP Response items required for circuits
///
/// This structure defines the expected HTTP response pattern in a manifest,
/// including status code, headers, and body validation rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestResponse {
  /// HTTP response status code as a string (e.g., "200", "201")
  pub status: String,

  /// HTTP version string (e.g., "HTTP/1.1")
  #[serde(default = "default_version")]
  pub version: String,

  /// HTTP response status message (e.g., "OK", "Created")
  #[serde(default = "default_message")]
  pub message: String,

  /// HTTP headers to validate in the response
  pub headers: HashMap<String, String>,

  /// HTTP body validation rules
  pub body: ManifestResponseBody,
}

impl ManifestResponse {
  /// Validates the HTTP response
  ///
  /// This function validates the HTTP response against a set of rules:
  /// - Status code must be supported (currently 200 or 201)
  /// - HTTP version must be valid (currently only HTTP/1.1)
  /// - Message must be of valid length
  /// - Headers must include Content-Type with a supported value
  /// - JSON path must be valid when Content-Type is application/json
  ///
  /// # Returns
  ///
  /// `Ok(())` if the response is valid, or an error describing the validation failure
  pub fn validate(&self) -> Result<(), WebProverCoreError> {
    // TODO: What are legal statuses?
    const VALID_STATUSES: [&str; 2] = ["200", "201"];
    if !VALID_STATUSES.contains(&self.status.as_str()) {
      return Err(WebProverCoreError::InvalidManifest("Unsupported HTTP status".to_string()));
    }

    // TODO: What HTTP versions are supported?
    if self.version != "HTTP/1.1" {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid HTTP version: ".to_string() + &self.version,
      ));
    }

    // TODO: What is the max supported message length?
    // TODO: Not covered by serde's #default annotation. Is '""' a valid message?
    if self.message.len() > 1024 || self.message.is_empty() {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid message length: ".to_string() + &self.message,
      ));
    }

    // We always expect at least one header, "Content-Type"
    if self.headers.len() > MAX_HTTP_HEADERS || self.headers.is_empty() {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid headers length: ".to_string() + &self.headers.len().to_string(),
      ));
    }

    let content_type =
      self.headers.get("Content-Type").or_else(|| self.headers.get("content-type"));
    if content_type.is_none() {
      return Err(WebProverCoreError::InvalidManifest("Missing 'Content-Type' header".to_string()));
    }
    let content_type = content_type.unwrap();

    const VALID_CONTENT_TYPES: [&str; 2] = ["application/json", "text/plain"];
    let is_valid_content_type = VALID_CONTENT_TYPES.iter().any(|&legal_type| {
      content_type == legal_type || content_type.starts_with(&format!("{};", legal_type))
    });
    if !is_valid_content_type {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid Content-Type header: ".to_string() + content_type,
      ));
    }

    // When Content-Type is application/json, we expect at least one JSON item
    if content_type == "application/json" && self.body.json_path.is_empty() {
      return Err(WebProverCoreError::InvalidManifest(
        "Expected at least one JSON item".to_string(),
      ));
    }

    const MAX_JSON_PATH_LENGTH: usize = 100;
    if self.body.json_path.len() > MAX_JSON_PATH_LENGTH {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid JSON path length: ".to_string() + &self.body.json_path.len().to_string(),
      ));
    }

    Ok(())
  }
}

/// Template variable type
///
/// This structure defines constraints for template variables that can be used
/// in HTTP requests, allowing for dynamic content with validation rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateVar {
  /// Regular expression pattern for validating the variable value
  ///
  /// If provided, the value of the variable must match this regex pattern.
  pub regex: Option<String>,

  /// Required length of the variable value
  ///
  /// If provided, the value of the variable must be exactly this length.
  pub length: Option<usize>,

  /// Type constraint for the variable
  ///
  /// If provided, specifies the expected format of the variable (e.g., "base64", "hex").
  pub r#type: Option<String>,
}

/// HTTP Request items required for circuits
///
/// This structure defines the expected HTTP request pattern in a manifest,
/// including method, URL, headers, and body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestRequest {
  /// HTTP method (e.g., "GET", "POST")
  pub method: String,

  /// HTTP request URL
  pub url: String,

  /// HTTP version string (e.g., "HTTP/1.1")
  #[serde(default = "default_version")]
  pub version: String,

  /// Request headers to include
  pub headers: HashMap<String, String>,

  /// Request JSON body (if any)
  pub body: Option<serde_json::Value>,

  /// Template variables that can be used in the request
  ///
  /// These variables allow for dynamic content in the request while
  /// maintaining validation rules.
  #[serde(default = "default_empty_vars")]
  pub vars: HashMap<String, TemplateVar>,
}

impl ManifestRequest {
  /// Validates the HTTP request against a set of rules.
  ///
  /// This function checks:
  /// - Method must be supported (currently GET or POST)
  /// - URL must be valid and use HTTPS
  /// - HTTP version must be valid (currently only HTTP/1.1)
  ///
  /// # Returns
  ///
  /// `Ok(())` if the request is valid, or an error describing the validation failure
  pub fn validate(&self) -> Result<(), WebProverCoreError> {
    // TODO: What HTTP methods are supported?
    const ALLOWED_METHODS: [&str; 2] = ["GET", "POST"];
    if !ALLOWED_METHODS.contains(&self.method.as_str()) {
      return Err(WebProverCoreError::InvalidManifest("Invalid HTTP method".to_string()));
    }

    // Not a valid URL
    if url::Url::parse(&self.url).is_err() {
      return Err(WebProverCoreError::InvalidManifest("Invalid URL: ".to_string() + &self.url));
    }

    if !self.url.starts_with("https://") {
      return Err(WebProverCoreError::InvalidManifest("Only HTTPS URLs are allowed".to_string()));
    }

    // TODO: What HTTP versions are supported?
    if self.version != "HTTP/1.1" {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid HTTP version: ".to_string() + &self.version,
      ));
    }

    Ok(())
  }

  // TODO (autoparallel): This function is not used anywhere at the moment, but i did not want to
  // delete it.

  /// Validates template variables in the request.
  ///
  /// This function performs comprehensive validation of template variables:
  /// 1. Ensures all tokens used in the body and headers are declared in `vars`
  /// 2. Ensures all variables declared in `vars` are actually used in the request
  /// 3. Validates each variable against its constraints (regex, length, type)
  ///
  /// # Returns
  ///
  /// `Ok(())` if all variables are valid, or an error describing the validation failure
  #[allow(unused)]
  fn validate_vars(&self) -> Result<(), WebProverCoreError> {
    let mut all_tokens = vec![];

    // Parse and validate tokens in the body
    if let Some(body_tokens) = self.body.as_ref().map(extract_tokens) {
      for token in &body_tokens {
        if !self.vars.contains_key(token) {
          return Err(WebProverCoreError::InvalidManifest(format!(
            "Token `<% {token} %>` not declared in `vars`",
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
          return Err(WebProverCoreError::InvalidManifest(format!(
            "Token `<% {} %>` not declared in `vars`",
            token
          )));
        }
      }
      all_tokens.extend(header_tokens);
    }

    // Ensure all declared variables are actually used somewhere in the request
    for var_key in self.vars.keys() {
      if !all_tokens.contains(var_key) {
        return Err(WebProverCoreError::InvalidManifest(format!(
          "Token `<% {} %>` not declared in `body` or `headers`",
          var_key
        )));
      }
    }

    // Validate each `vars` entry against its constraints
    for (key, var_def) in &self.vars {
      // Validate regex pattern (if defined)
      if let Some(regex_pattern) = var_def.regex.as_ref() {
        // Using `regress` crate for compatibility with ECMAScript regular expressions
        let _regex = regress::Regex::new(regex_pattern).map_err(|_| {
          WebProverCoreError::InvalidManifest(format!("Invalid regex pattern for `{}`", key))
        })?;
        // TODO: It will definitely not match it here because it's a template variable, not an
        // actual variable
        // TODO: How does the Manifest receiver (notary) verifies this?
        // if let Some(value) = self.body.as_ref().and_then(|b| b.get(key)) {
        //   if regex.find(value.as_str().unwrap_or("")).is_none() {
        //     return Err(ManifestError::InvalidManifest(format!(
        //       "Value for token `<% {} %>` does not match regex",
        //       key
        //     )));
        //   }
        // }
      }

      // Validate length constraint (if applicable)
      if let Some(length) = var_def.length {
        if let Some(value) = self.body.as_ref().and_then(|b| b.get(key)) {
          if value.as_str().unwrap_or("").len() != length {
            return Err(WebProverCoreError::InvalidManifest(format!(
              "Value for token `<% {} %>` does not meet length constraint",
              key
            )));
          }
        }
      }

      // TODO: Validate the token "type" constraint (e.g., base64, hex)
    }
    Ok(())
  }

  /// Parses the HTTP request from the given bytes.
  ///
  /// # Arguments
  ///
  /// * `bytes` - The complete HTTP request as a byte slice, including headers and body
  ///
  /// # Returns
  ///
  /// A `Result` containing either the parsed `ManifestRequest` or an error
  pub fn from_payload(bytes: &[u8]) -> Result<Self, WebProverCoreError> {
    // todo: dedup me
    let delimiter = b"\r\n\r\n";
    let split_position = bytes
      .windows(delimiter.len())
      .position(|window| window == delimiter)
      .ok_or_else(|| WebProverCoreError::InvalidManifest("Invalid HTTP format".to_string()))?;

    let (header_bytes, rest) = bytes.split_at(split_position);
    let body_bytes = &rest[delimiter.len()..];

    let (method, url, version, headers) = Self::parse_header(header_bytes)?;

    let body = if !body_bytes.is_empty() {
      serde_json::from_slice(body_bytes)
        .map_err(|_| WebProverCoreError::InvalidManifest("Invalid body bytes".to_string()))?
    } else {
      None
    };

    Ok(Self { method, url, version, headers, body, vars: HashMap::new() })
  }

  /// Parses the HTTP request start-line and headers from the given bytes.
  ///
  /// # Arguments
  ///
  /// * `header_bytes` - The bytes containing the HTTP request headers
  ///
  /// # Returns
  ///
  /// A tuple containing the parsed method, URL, HTTP version, and headers
  fn parse_header(
    header_bytes: &[u8],
  ) -> Result<(String, String, String, HashMap<String, String>), WebProverCoreError> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
      WebProverCoreError::InvalidManifest("Failed to interpret headers as valid UTF-8".to_string())
    })?;
    let mut lines = header_str.lines();

    let start_line = lines.next().ok_or_else(|| {
      WebProverCoreError::InvalidManifest("Missing start-line in the HTTP request.".to_string())
    })?;

    let parts: Vec<&str> = start_line.split_whitespace().collect();
    if parts.len() < 3 {
      return Err(WebProverCoreError::InvalidManifest(
        "Invalid HTTP request start-line.".to_string(),
      ));
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
        return Err(WebProverCoreError::InvalidManifest(format!("Invalid header line: {}", line)));
      }
    }

    Ok((method, path, version, headers))
  }

  /// Checks if the current request is a subset of the given `other` request.
  ///
  /// For the request to be a subset:
  /// - All headers in `self` must exist in `other` with matching values.
  /// - All vars in `self` must exist in `other` with matching constraints.
  /// - All remaining fields like `method`, `url`, and `body` must also match.
  ///
  /// This function is useful for determining if a request satisfies the requirements
  /// specified in another request template.
  ///
  /// # Arguments
  ///
  /// * `other` - The request to check against
  ///
  /// # Returns
  ///
  /// `true` if this request is a subset of the other request, `false` otherwise
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

/// Extracts template variable tokens from a JSON value.
///
/// This function recursively searches through a JSON value (string, object, or array)
/// to find all template variable tokens in the format `<% token_name %>`.
///
/// # Arguments
///
/// * `value` - The JSON value to search for tokens
///
/// # Returns
///
/// A vector of strings containing the extracted token names (without the `<% %>` delimiters)
fn extract_tokens(value: &serde_json::Value) -> Vec<String> {
  let mut tokens = vec![];

  match value {
    serde_json::Value::String(s) => {
      // For string values, use regex to find all tokens in the format <% token_name %>
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
    _ => {}, // Ignore other JSON value types (numbers, booleans, null)
  }

  tokens
}

#[cfg(test)]
pub mod tests {
  use std::{collections::HashMap, string::ToString};

  use serde_json::json;

  use super::*;
  use crate::http::{ManifestRequest, ManifestResponse};

  /// Creates a new HTTP request with optional parameters.
  #[macro_export]
  macro_rules! request {
    // Match with optional parameters
    ($($key:ident: $value:expr),* $(,)?) => {{
        // Make clippy happy
        #[allow(unused_mut) ]
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

  /// Creates a new HTTP response with optional parameters.
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
            body: ManifestResponseBody {
                json_path: vec![
                    JsonKey::String("key1".to_string()),
                    JsonKey::String("key2".to_string()),
                    JsonKey::Num(3)
                ]
            },
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
    assert_eq!(response.response.body.json_path.len(), 0);
    assert_eq!(response.notary_response_body.json, Some(body));
  }

  #[test]
  fn test_notary_matches_other_response() {
    let response = response!();
    let notary_response = notary_response!(
      response.clone(),
      json: Some(json!({
            "key1": {"key2": 3},
        })),
    );

    // Is a perfect match with itself
    assert!(notary_response.matches_client_manifest(&response));
    assert!(notary_response.matches_client_manifest(&notary_response.response));

    // Fails if it doesn't match directly
    let non_matching_response = response!(status: "201".to_string());
    assert!(!notary_response.matches_client_manifest(&non_matching_response));

    // Superset case
    let response_superset = {
      let mut res = notary_response.clone();
      res.response.headers.insert("extra".to_string(), "header".to_string());
      res.response.body.json_path = notary_response.response.body.json_path.clone();
      res.response.body.json_path.push(JsonKey::Num(3));
      res
    };
    assert!(response_superset.matches_client_manifest(&response));
  }

  #[test]
  fn test_response_with_missing_body() {
    let header_bytes: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    let empty_body: &[u8] = br#""#;

    let actual = NotaryResponse::from_payload(&[header_bytes, empty_body].concat()).unwrap();

    let expected = NotaryResponse {
      response:             response!(
        headers: HashMap::from([("Content-Type".to_string(), "text/plain".to_string())]),
        body: ManifestResponseBody { json_path: vec![] }
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

    if let Err(WebProverCoreError::InvalidManifest(msg)) = result {
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
      Err(WebProverCoreError::InvalidManifest(msg)) => {
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

    if let Err(WebProverCoreError::InvalidManifest(msg)) = result {
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
        body: ManifestResponseBody {
            json_path: vec![],
        }
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

    assert_eq!(notary_response.response.body.json_path.len(), 0);
    assert_eq!(notary_response.notary_response_body.json, Some(json!({})));
  }

  #[test]
  fn test_subset_with_missing_key_in_other() {
    let base_response = notary_response!(response!(),);
    let other_response = response!(
        body: ManifestResponseBody {
            json_path: vec![JsonKey::String("key1".to_string())],
        }
    );
    assert!(!base_response.matches_client_manifest(&other_response));
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
      Err(WebProverCoreError::InvalidManifest(msg)) => {
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
      Err(WebProverCoreError::InvalidManifest(msg)) => {
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
      Err(WebProverCoreError::InvalidManifest(msg)) => {
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
      Err(WebProverCoreError::InvalidManifest(msg)) => {
        assert!(msg.contains("Invalid body bytes"));
      },
      _ => panic!("Expected invalid body parsing error"),
    }
  }

  #[test]
  fn test_validate_vars_with_missing_token() {
    let header_bytes: &[u8] =
      b"POST /path HTTP/1.1\r\nX-Custom-Header: <% missing_token %>\r\n\r\n";
    let body_bytes: &[u8] = br#"{"key": "value"}"#;

    let mut request = ManifestRequest::from_payload(&[header_bytes, body_bytes].concat()).unwrap();
    request.vars = HashMap::new(); // No vars provided, but the template references a token

    let result = request.validate_vars();
    assert!(result.is_err());

    match result {
      Err(WebProverCoreError::InvalidManifest(msg)) => {
        assert!(msg.contains("Token `<% missing_token %>` not declared in `vars`"));
      },
      _ => panic!("Expected missing token error"),
    }
  }

  #[test]
  fn test_request_subset_comparison() {
    let base_request = request!(
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

  /// Creates a response body with a given serde_json::Value
  #[macro_export]
  macro_rules! notary_body {
    ($($key:tt : $value:tt),* $(,)?) => {{
        NotaryResponseBody {
            json: Some(json!({
                $(
                    $key: $value
                ),*
            }))
        }
    }};
}

  #[test]
  fn test_json_contains_path_valid_object_path() {
    let json = notary_body!(
        "key1": {
            "key2": {
                "key3": "value"
            }
        }
    );
    // ["key1", "key2", "key3"]
    let path = vec![
      JsonKey::String("key1".to_string()),
      JsonKey::String("key2".to_string()),
      JsonKey::String("key3".to_string()),
    ];
    assert!(json.matches_path(&path));

    // ["key1", "key2", "key3", "value"]
    let mut path_with_value = path.clone();
    path_with_value.push(JsonKey::String("value".to_string()));
    assert!(json.matches_path(&path_with_value));

    // ["key1", "key2", "key3", "value", "invalid"]
    let mut path_with_invalid_value = path.clone();
    path_with_invalid_value.push(JsonKey::String("invalid_value".to_string()));
    assert!(!json.matches_path(&path_with_invalid_value));
  }

  #[test]
  fn test_json_contains_path_valid_array_path() {
    let json = notary_body!(
        "key1": [
            {
                "key2": "value1"
            },
            {
                "key3": "value2"
            }
        ]
    );
    let path = vec![
      JsonKey::String("key1".to_string()),
      JsonKey::Num(1),
      JsonKey::String("key3".to_string()),
      JsonKey::String("value2".to_string()),
    ];
    assert!(json.matches_path(&path));
  }

  #[test]
  fn test_json_contains_path_invalid_key() {
    let json = notary_body!(
        "key1": {
            "key2": "value"
        }
    );
    let path =
      vec![JsonKey::String("key1".to_string()), JsonKey::String("invalid_key".to_string())];
    assert!(!json.matches_path(&path));
  }

  #[test]
  fn test_json_contains_path_invalid_array_index() {
    let json = notary_body!(
        "key1": [
            "value1",
            "value2"
        ]
    );
    let path = vec![
      JsonKey::String("key1".to_string()),
      JsonKey::Num(3), // Out of bounds
    ];
    assert!(!json.matches_path(&path));
  }

  #[test]
  fn test_json_contains_path_index_on_non_array() {
    let json = notary_body!(
        "key1": {
            "key2": "value"
        }
    );
    let path = vec![
      JsonKey::String("key1".to_string()),
      JsonKey::Num(0), // Applying index on a non-array
    ];
    assert!(!&json.matches_path(&path));
  }

  #[test]
  fn test_empty_path() {
    let json = notary_body!(
        "key1": {
            "key2": {
                "key3": "value"
            }
        }
    );
    let path: Vec<JsonKey> = vec![];
    assert!(!json.matches_path(&path));
  }

  #[test]
  fn test_empty_body() {
    let json = notary_body!();
    let mut path: Vec<JsonKey> = vec![];
    assert!(!json.matches_path(&path));

    path.push(JsonKey::String("key1".to_string()));
    assert!(!json.matches_path(&path));
  }

  #[test]
  fn test_number_matching() {
    let test_cases = vec![
      // Unsigned integers
      (json!({"val": 42u64}), 42, true),
      // Signed integers
      (json!({"val": -42}), -42, true),
      // Floating point
      (json!({"val": 42.0}), 42, true),
      // Large numbers
      (json!({"val": u64::MAX}), u64::MAX as i64, true),
      // Mismatched types
      (json!({"val": "42"}), 42, false),
      // Edge cases
      (json!({"val": 42.000001}), 42, false),
    ];

    for (json, expected, should_match) in test_cases {
      let body = NotaryResponseBody { json: Some(json.clone()) };
      assert_eq!(
        body.matches_path(&[JsonKey::String("val".to_string()), JsonKey::Num(expected as usize)]),
        should_match,
        "Failed for value: {:?}, expected: {}",
        json,
        expected
      );
    }
  }

  #[test]
  fn test_nested_array_path() {
    let json = notary_body!(
        "data": [
            [1, 2, 3],
            [4, 5, 6]
        ]
    );
    assert!(json.matches_path(&[
      JsonKey::String("data".to_string()),
      JsonKey::Num(1),
      JsonKey::Num(1),
      JsonKey::Num(5),
    ]));
  }

  #[test]
  fn test_mixed_types_in_array() {
    let json = notary_body!(
        "mixed": [
            42,
            "string",
            { "key": "value" },
            [1, 2, 3]
        ]
    );
    assert!(json.matches_path(&[
      JsonKey::String("mixed".to_string()),
      JsonKey::Num(0),
      JsonKey::Num(42),
    ]));
    assert!(json.matches_path(&[
      JsonKey::String("mixed".to_string()),
      JsonKey::Num(1),
      JsonKey::String("string".to_string()),
    ]));
    assert!(json.matches_path(&[
      JsonKey::String("mixed".to_string()),
      JsonKey::Num(2),
      JsonKey::String("key".to_string()),
      JsonKey::String("value".to_string()),
    ]));
  }

  #[test]
  fn test_empty_string_keys_and_values() {
    let json = notary_body!(
        "": {
            "empty": ""
        }
    );
    // Test empty string keys and values
    assert!(json.matches_path(&[
      JsonKey::String("".to_string()),
      JsonKey::String("empty".to_string()),
      JsonKey::String("".to_string()),
    ]));
  }

  #[test]
  fn test_very_deep_nesting() {
    // Test different depths: 5, 25, and 100 levels
    let depths = vec![5, 25, 100];

    for depth in depths {
      // Build nested JSON structure
      let mut json_value = json!("value");
      for i in (0..depth).rev() {
        json_value = json!({
            format!("level{}", i): json_value
        });
      }

      let json = NotaryResponseBody { json: Some(json_value) };

      // Build the path
      let mut path = Vec::new();
      for i in 0..depth {
        path.push(JsonKey::String(format!("level{}", i)));
      }
      path.push(JsonKey::String("value".to_string()));

      // Test the path
      let result = json.matches_path(&path);
      assert!(result, "Failed to match path at depth {}: {:?}", depth, path);
    }
  }
}
