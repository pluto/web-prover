use derive_more::From;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};
use tracing::debug;

use crate::{
  error::WebProverCoreError,
  http::{ManifestRequest, ManifestResponse, NotaryResponse},
  parser::{ExtractionResult, ExtractionValues},
};

/// Manifest validation summary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ManifestValidationResult {
  errors:            Vec<String>,
  extraction_result: ExtractionResult,
}

impl ManifestValidationResult {
  /// Returns `true` if no validation errors were found and extraction was successful
  pub fn is_success(&self) -> bool { self.errors.is_empty() && self.extraction_result.is_success() }

  /// Returns the extracted values
  pub fn values(&self) -> ExtractionValues { self.extraction_result.values.clone() }

  /// Adds an error to the summary
  pub fn add_error(&mut self, error: &str) { self.errors.push(error.to_string()); }

  /// Appends an extraction result to the summary
  pub fn merge_extraction_result(&mut self, other: &ExtractionResult) {
    self.extraction_result.merge(other);
  }

  /// Merges another validation result into this one
  pub fn merge(&mut self, other: &ManifestValidationResult) {
    self.errors.extend(other.clone().errors);
    self.extraction_result.merge(&other.extraction_result);
  }

  /// Returns validation and extraction errors
  pub fn errors(&self) -> Vec<String> {
    let mut errors = self.errors.clone();
    errors.extend(self.extraction_result.errors.clone());
    errors
  }

  /// Adds an error to the summary and logs it
  pub fn report_error(&mut self, error: ManifestError) {
    debug!("Manifest validation error: {}", error);
    self.errors.push(error.to_string());
  }
}

/// Manifest containing [`ManifestRequest`] and [`ManifestResponse`]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, From)]
// #[serde(rename_all = "camelCase")]
pub struct Manifest {
  // /// Manifest version
  // pub manifest_version: String,
  // /// ID of the manifest
  // pub id:               String,
  // /// Title of the manifest
  // pub title:            String,
  // /// Description of the manifest
  // pub description:      String,
  /// HTTP request lock items
  pub request:  ManifestRequest,
  /// HTTP response lock items
  pub response: ManifestResponse,
}

impl Manifest {
  fn validate_manifest(&self) -> ManifestValidationResult {
    let mut summary = ManifestValidationResult::default();

    // TODO: Validate manifest version, id, title, description, prepareUrl
    if let Err(e) = self.request.validate() {
      debug!("Invalid manifest request: {:?}", e);
      summary.errors.push(e.to_string());
    }
    if let Err(e) = self.response.validate() {
      debug!("Invalid manifest response: {:?}", e);
      summary.errors.push(e.to_string());
    }
    if let Err(e) = self.request.validate_vars() {
      debug!("Invalid manifest request template variables: {:?}", e);
      summary.errors.push(e.to_string());
    }

    summary
  }

  /// Validates `Manifest` request and response fields. They are validated against valid statuses,
  /// HTTPs methods, and template variables. Finally, it checks if the request and response match.
  pub fn validate_with(
    &self,
    request: &ManifestRequest,
    response: &NotaryResponse,
  ) -> Result<ManifestValidationResult, ManifestError> {
    let mut result = ManifestValidationResult::default();

    // Validate manifest fields
    result.merge(&self.validate_manifest());

    // Check if request matches manifest requirements
    result.merge(&self.request.is_subset_of(request)?);

    // Check if response matches manifest and extract values
    result.merge(&response.match_and_extract(&self.response)?);

    Ok(result)
  }

  /// Compute a `Keccak256` hash of the serialized Manifest
  pub fn to_keccak_digest(&self) -> Result<[u8; 32], WebProverCoreError> {
    let as_bytes: Vec<u8> = self.try_into()?;
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(&as_bytes);
    hasher.finalize(&mut output);

    Ok(output)
  }
}

impl TryFrom<&[u8]> for Manifest {
  type Error = serde_json::Error;

  fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> { serde_json::from_slice(bytes) }
}

impl TryFrom<&Manifest> for Vec<u8> {
  type Error = serde_json::Error;

  fn try_from(manifest: &Manifest) -> Result<Self, Self::Error> { serde_json::to_vec(manifest) }
}

impl TryFrom<Manifest> for Vec<u8> {
  type Error = serde_json::Error;

  fn try_from(manifest: Manifest) -> Result<Self, Self::Error> { serde_json::to_vec(&manifest) }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use serde_json::json;

  use crate::{
    error::WebProverCoreError,
    extractor,
    extractor,
    http::{ManifestResponseBody, NotaryResponse, NotaryResponseBody, HTTP_1_1},
    manifest::{Manifest, ManifestRequest, ManifestResponse, ManifestValidationResult},
    parser::{DataFormat, ExtractionResult, ExtractionValues, ExtractorConfig, ExtractorType},
    request, response,
    template::TemplateVar,
    test_utils::TEST_MANIFEST,
  };

  macro_rules! create_manifest {
    (
        $request:expr,
        $response:expr
        $(, $field:ident = $value:expr)* $(,)?
    ) => {{
        Manifest {
            // manifest_version: "1".to_string(),
            // id: "Default Manifest ID".to_string(),
            // title: "Default Manifest Title".to_string(),
            // description: "Default description.".to_string(),
            request: $request,
            response: $response,
            $(
                $field: $value,
            )*
        }
    }};
  }

  #[test]
  fn test_deserialize_from_string() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();
    // verify defaults are working
    assert_eq!(manifest.request.version, HTTP_1_1);
    assert_eq!(manifest.request.method, "GET");
    assert_eq!(manifest.request.headers.len(), 2);
    assert_eq!(manifest.request.headers.get("host").unwrap(), "gist.githubusercontent.com");

    // verify defaults are working
    assert_eq!(manifest.response.status, "200");
    assert_eq!(manifest.response.version, HTTP_1_1);
    assert_eq!(manifest.response.headers.len(), 2);
    assert_eq!(manifest.response.headers.get("Content-Type").unwrap(), "text/plain; charset=utf-8");

    let expected_body = ManifestResponseBody(ExtractorConfig {
      format:     DataFormat::Json,
      extractors: vec![extractor! {
        id:             "userInfo".to_string(),
        description:    "Extract user information".to_string(),
        selector:       vec!["hello".to_string()],
        extractor_type: ExtractorType::String,
      }],
    });
    assert_eq!(manifest.response.body, expected_body);
  }

  #[test]
  fn test_manifest_serialization() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();
    let serialized: Vec<u8> = manifest.clone().try_into().unwrap();
    let deserialized = Manifest::try_from(serialized.as_slice()).unwrap();
    assert_eq!(manifest, deserialized);
  }

  #[test]
  fn test_green_path_manifest_validation() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();
    let result = manifest.validate_manifest();
    assert!(result.is_success());
    assert!(result.values().is_empty());
  }

  const TEST_MANIFEST_WITHOUT_VARS: &str = r#"
{
    "manifestVersion": "1",
    "id": "reddit-user-karma",
    "title": "Total Reddit Karma",
    "description": "Generate a proof that you have a certain amount of karma",
    "prepareUrl": "https://www.reddit.com/login/",
    "request": {
        "method": "GET",
        "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
        "headers": {
            "host": "gist.githubusercontent.com",
            "connection": "close",
            "Authorization": "Bearer <% token %>",
            "User-Agent": "test-agent"
        }
    },
    "response": {
        "status": "200",
        "headers": {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": "22"
        },
        "body": {
            "format": "json",
            "extractors": [
                {
                    "id": "userInfo",
                    "description": "Extract user information",
                    "selector": ["hello"],
                    "type": "string"
                }
            ]
        }
    }
}
"#;

  #[test]
  fn test_parse_manifest_without_vars() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST_WITHOUT_VARS).unwrap();
    let result = manifest.validate_manifest();
    assert!(!result.is_success());

    assert!(manifest.request.body.is_none()); // Optional field we omitted
    assert_eq!(manifest.request.vars, HashMap::new()); // Optional field we provide default for

    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0], "Invalid manifest: Token `<% token %>` not declared in `vars`");
  }

  #[test]
  fn test_manifest_validation_invalid_method() {
    let manifest = create_manifest!(request!(method: "INVALID".to_string()), response!(),);
    let result = manifest.validate_manifest();
    assert!(!result.is_success());
    assert!(result.values().is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0], "Invalid manifest: Invalid HTTP method");
  }

  #[test]
  fn test_manifest_validation_invalid_url() {
    let manifest = create_manifest!(request!(url: "ftp://example.com".to_string()), response!(),);
    let result = manifest.validate_manifest();
    assert!(!result.is_success());
    assert!(result.values().is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0], "Invalid manifest: Only HTTPS URLs are allowed");
  }

  #[test]
  fn test_manifest_validation_invalid_response_status() {
    let manifest = create_manifest!(request!(), response!(status: "500".to_string()),);
    let result = manifest.validate_manifest();
    assert!(!result.is_success());
    assert!(result.values().is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0], "Invalid manifest: Unsupported HTTP status");
  }

  #[test]
  fn test_manifest_validation_missing_vars() {
    let mut vars = HashMap::new();
    vars.insert("TOKEN".to_string(), TemplateVar {
      description: Some("Authentication token".to_string()),
      required:    true,
      default:     None,
      pattern:     Some("^[A-Za-z0-9]+$".to_string()),
    });
    let manifest = create_manifest!(
      request!(
          headers: HashMap::new(), // Invalid because "Authorization" makes use of `<TOKEN>`
          vars: vars
      ),
      response!(),
    );
    let result = manifest.validate_manifest();
    assert!(!result.is_success());
    assert!(result.values().is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(
      result.errors[0],
      "Template error: Required variable `TOKEN` is not used in the template"
    );
  }

  #[test]
  fn test_manifest_validation_invalid_content_type() {
    let manifest = create_manifest!(
      request!(),
      response!(headers: HashMap::from([
          ("Content-Type".to_string(), "invalid/type".to_string())
      ])),
    );
    let result = manifest.validate_manifest();
    assert!(!result.is_success());
    assert!(result.values().is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0], "Invalid manifest: Invalid Content-Type header: invalid/type");
  }

  #[test]
  fn test_manifest_validation_result_with_extraction() {
    let mut result = ManifestValidationResult::default();

    // Create an ExtractionResult with some values
    let mut values = ExtractionValues::new();
    values.insert("key1".to_string(), json!("value1"));
    values.insert("key2".to_string(), json!(42));

    let extraction = ExtractionResult { values, errors: vec!["extraction error".to_string()] };

    result.merge_extraction_result(&extraction);

    // Test that both validation and extraction errors are returned
    result.add_error("validation error");
    let all_errors = result.errors();
    assert_eq!(all_errors.len(), 2);
    assert!(all_errors.contains(&"validation error".to_string()));
    assert!(all_errors.contains(&"extraction error".to_string()));

    // Test values are accessible
    let values = result.values();
    assert_eq!(values.get("key1"), Some(&json!("value1")));
    assert_eq!(values.get("key2"), Some(&json!(42)));

    // Test success state
    assert!(!result.is_success()); // Should be false due to errors
    assert!(!result.is_success()); // Should be false due to validation error
  }

  #[test]
  fn test_manifest_validation_result_merge() {
    let mut result1 = ManifestValidationResult::default();
    let mut result2 = ManifestValidationResult::default();

    // Setup first result
    result1.add_error("error1");
    let mut values1 = ExtractionValues::new();
    values1.insert("key1".to_string(), json!("value1"));
    result1.merge_extraction_result(&ExtractionResult {
      values: values1,
      errors: vec!["extraction1".to_string()],
    });

    // Setup second result
    result2.add_error("error2");
    let mut values2 = ExtractionValues::new();
    values2.insert("key2".to_string(), json!("value2"));
    result2.merge_extraction_result(&ExtractionResult {
      values: values2,
      errors: vec!["extraction2".to_string()],
    });

    // Merge results
    result1.merge(&result2);

    // Verify merged state
    let all_errors = result1.errors();
    assert_eq!(all_errors.len(), 4);
    assert!(all_errors.contains(&"error1".to_string()));
    assert!(all_errors.contains(&"error2".to_string()));
    assert!(all_errors.contains(&"extraction1".to_string()));
    assert!(all_errors.contains(&"extraction2".to_string()));

    let values = result1.values();
    assert_eq!(values.get("key1"), Some(&json!("value1")));
    assert_eq!(values.get("key2"), Some(&json!("value2")));
  }

  #[test]
  fn test_manifest_validation_result_success_cases() {
    let mut result = ManifestValidationResult::default();

    // Test initial state
    assert!(result.is_success());
    assert!(result.is_success());

    // Test with successful extraction only
    let mut values = ExtractionValues::new();
    values.insert("key".to_string(), json!("value"));
    result.merge_extraction_result(&ExtractionResult { values, errors: vec![] });

    assert!(result.is_success());
    assert!(result.is_success());
    assert_eq!(result.errors().len(), 0);
    assert_eq!(result.values().len(), 1);
  }

  #[test]
  fn test_manifest_comprehensive_error_cases() {
    let mut vars = HashMap::new();
    vars.insert("UNUSED_TOKEN".to_string(), TemplateVar {
      description: Some("This token is required but unused".to_string()),
      required:    true,
      default:     None,
      pattern:     Some("^[A-Za-z0-9]+$".to_string()),
    });

    // Create a manifest with multiple validation issues
    let manifest = create_manifest!(
      request!(
          method: "INVALID_METHOD".to_string(),
          url: "ftp://invalid-scheme.com".to_string(),
          headers: HashMap::from([
              ("Authorization".to_string(), "Bearer <% MISSING_TOKEN %>".to_string()),
              ("Content-Type".to_string(), "invalid/type".to_string())
          ]),
          vars: vars
      ),
      response!(
          status: "599".to_string(), // Invalid status
          headers: HashMap::from([
              ("Content-Type".to_string(), "invalid/content-type".to_string())
          ]),
          body: ManifestResponseBody(ExtractorConfig {
              format: DataFormat::Json,
              extractors: vec![
                  extractor! {
                      id: "invalid_extractor".to_string(),
                      description: "This will fail".to_string(),
                      selector: vec!["invalid".to_string(), "$.".to_string(), "path".to_string()],
                      extractor_type: ExtractorType::String,
                  },
                  extractor! {
                      id: "another_invalid".to_string(),
                      description: "This will also fail".to_string(),
                      selector: vec!["[5]".to_string(), "outofbounds".to_string()],
                      extractor_type: ExtractorType::Number,
                  }
              ],
          })
      ),
    );

    // Validate the manifest
    let request = request!(
        method: "POST".to_string(),
        url: "https://api.example.com".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: HashMap::from([
            ("Authorization".to_string(), "Bearer invalid-token".to_string()),
            ("Content-Type".to_string(), "application/json".to_string())
        ]),
    );
    let response = NotaryResponse {
      response:             manifest.response.clone(),
      notary_response_body: NotaryResponseBody { body: None },
    };
    let result = manifest.validate_with(&request, &response).expect("validation should not fail");

    // Verify we get multiple validation errors
    let mut all_errors = result.errors();
    all_errors.sort();
    let mut expected = vec![
      "Invalid manifest: Invalid HTTP method",
      "Invalid manifest: Unsupported HTTP status",
      "Invalid manifest: Token `<% MISSING_TOKEN %>` not declared in `vars`",
      "Manifest HTTP error: HTTP header mismatch: expected Bearer <% MISSING_TOKEN %>, actual Bearer invalid-token",
      "Manifest HTTP error: HTTP header mismatch: expected invalid/type, actual application/json",
      "Template error: Variable missing for key: UNUSED_TOKEN",
      "Manifest HTTP error: HTTP method mismatch: expected POST, actual INVALID_METHOD",
      "Manifest HTTP error: HTTP URL mismatch: expected https://api.example.com, actual ftp://invalid-scheme.com",
      "Extraction failed: No data to match against"
    ];
    expected.sort();
    assert_eq!(all_errors, expected);

    // Verify the overall state
    assert!(!result.is_success());
    assert!(result.values().is_empty());
  }
}
