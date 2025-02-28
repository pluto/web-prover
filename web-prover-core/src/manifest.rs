use derive_more::From;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::{
  errors::ManifestError,
  http::{ManifestRequest, ManifestResponse},
};

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
  /// Validates `Manifest` request and response fields. They are validated against valid statuses,
  /// http methods, and template variables.
  pub fn validate(&self) -> Result<(), ManifestError> {
    // TODO: Validate manifest version, id, title, description, prepareUrl
    self.request.validate()?;
    self.response.validate()?;

    // TODO: Do we want to run this here instead of in Request::validate in order to cross-examine
    //  Request and Response template vars?
    // TODO: Commented out because it breaks when existing fixtures, i.e. tokens encoded in the
    //  body of client.tee_tcp_local.json
    // self.request.validate_vars()?;
    Ok(())
  }

  /// Compute a `Keccak256` hash of the serialized Manifest
  pub fn to_keccak_digest(&self) -> Result<[u8; 32], ManifestError> {
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

  use crate::{
    errors::ManifestError,
    http::{TemplateVar, HTTP_1_1},
    manifest::Manifest,
    request, response,
    test_utils::TEST_MANIFEST,
  };

  macro_rules! create_manifest {
    (
        $request:expr,
        $response:expr
        $(, $field:ident = $value:expr)* $(,)?
    ) => {{
        crate::manifest::Manifest {
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
  fn test_serialize() {
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
    assert_eq!(manifest.response.body.json_path.len(), 1);
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
    let result = manifest.validate();
    assert!(result.is_ok());
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
            "json": [
                "hello"
            ]
        }
    }
}
"#;

  #[test]
  fn test_parse_manifest_without_vars() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST_WITHOUT_VARS).unwrap();
    let result = manifest.validate();
    assert!(result.is_ok());

    assert!(manifest.request.body.is_none()); // Optional field we omitted
    assert_eq!(manifest.request.vars, HashMap::new()); // Optional field we provide default for
  }

  #[test]
  fn test_manifest_validation_invalid_method() {
    let manifest = create_manifest!(request!(method: "INVALID".to_string()), response!(),);
    let result = manifest.validate();
    assert!(result.is_err());
    if let Err(ManifestError::InvalidManifest(message)) = result {
      assert_eq!(message, "Invalid HTTP method");
    } else {
      panic!("Expected ManifestError::InvalidManifest");
    }
  }

  #[test]
  fn test_manifest_validation_invalid_url() {
    let manifest = create_manifest!(request!(url: "ftp://example.com".to_string()), response!(),);
    let result = manifest.validate();
    assert!(result.is_err());
    if let Err(ManifestError::InvalidManifest(message)) = result {
      assert_eq!(message, "Only HTTPS URLs are allowed");
    } else {
      panic!("Expected ManifestError::InvalidManifest");
    }
  }

  #[test]
  fn test_manifest_validation_invalid_response_status() {
    let manifest = create_manifest!(request!(), response!(status: "500".to_string()),);
    let result = manifest.validate();
    assert!(result.is_err());
    if let Err(ManifestError::InvalidManifest(message)) = result {
      assert_eq!(message, "Unsupported HTTP status");
    } else {
      panic!("Expected ManifestError::InvalidManifest");
    }
  }

  #[ignore] // TODO: Unignore after fixtures are fixed and token validation is re-enabled
  #[test]
  fn test_manifest_validation_missing_vars() {
    let mut vars = HashMap::new();
    vars.insert("TOKEN".to_string(), TemplateVar {
      regex:  Some("^[A-Za-z0-9]+$".to_string()),
      length: Some(20),
      r#type: Some("base64".to_string()),
    });
    let manifest = create_manifest!(
      request!(
          headers: HashMap::new(), // Invalid because "Authorization" makes use of `<TOKEN>`
          vars: vars
      ),
      response!(),
    );
    let result = manifest.validate();
    assert!(result.is_err());
  }

  #[test]
  fn test_manifest_validation_invalid_content_type() {
    let manifest = create_manifest!(
      request!(),
      response!(headers: HashMap::from([
          ("Content-Type".to_string(), "invalid/type".to_string())
      ])),
    );
    let result = manifest.validate();
    assert!(result.is_err());
    if let Err(ManifestError::InvalidManifest(message)) = result {
      assert_eq!(message, "Invalid Content-Type header: invalid/type");
    } else {
      panic!("Expected ManifestError::InvalidManifest");
    }
  }
}
