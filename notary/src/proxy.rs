use std::{sync::Arc, time::Duration};

use axum::{
  extract::{self, Query, State},
  Json,
};
use reqwest::{Request, Response};
use serde::Deserialize;
use serde_json::Value;
use tracing::info;
use uuid::Uuid;
use web_prover_core::{
  http::{
    ManifestRequest, ManifestResponse, ManifestResponseBody, NotaryResponse, NotaryResponseBody,
  },
  manifest::Manifest,
  proof::{TeeProof, TeeProofData},
};

use crate::{
  error::NotaryServerError,
  verifier::{sign_verification, VerifyOutput},
  SharedState,
};

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id: Uuid,
}

pub async fn proxy(
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<web_prover_client::ProxyConfig>,
) -> Result<Json<TeeProof>, NotaryServerError> {
  let session_id = query.session_id;

  info!("Starting proxy with ID: {}", session_id);

  let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
  let method: reqwest::Method = payload.target_method.parse().unwrap();

  let mut request_builder: reqwest::RequestBuilder = client.request(method, payload.target_url);
  for (key, value) in payload.target_headers {
    request_builder = request_builder.header(key, value);
  }
  if !payload.target_body.is_empty() {
    request_builder = request_builder.body(payload.target_body.clone());
  }

  let reqwest_request = request_builder.try_clone().unwrap().build().unwrap();
  let reqwest_response = request_builder.send().await.unwrap();

  let request = from_reqwest_request(&reqwest_request);
  // debug!("{:?}", request);

  let response = from_reqwest_response(reqwest_response).await;
  // debug!("{:?}", response);

  let tee_proof = create_tee_proof(&payload.manifest, &request, &response, State(state))?;

  Ok(Json(tee_proof))
}

// TODO: This, similarly to other from_* methods, should be a trait
// Requires adding reqwest to proofs crate
async fn from_reqwest_response(response: Response) -> NotaryResponse {
  let status = response.status().as_u16().to_string();
  let version = format!("{:?}", response.version());
  let message = response.status().canonical_reason().unwrap_or("").to_string();
  let headers = response
    .headers()
    .iter()
    .map(|(k, v)| (capitalize_header(k.as_ref()), v.to_str().unwrap_or("").to_string()))
    .collect();
  let json = response.json().await.ok();
  NotaryResponse {
    response:             ManifestResponse {
      status,
      version,
      message,
      headers,
      // TODO: This makes me think that perhaps this should be an optional field or something else
      body: ManifestResponseBody::default(),
    },
    notary_response_body: NotaryResponseBody { body: json },
  }
}

fn from_reqwest_request(request: &Request) -> ManifestRequest {
  let method = request.method().to_string();
  let url = request.url().to_string();
  let version = format!("{:?}", request.version());
  let headers = request
    .headers()
    .iter()
    .map(|(k, v)| (capitalize_header(k.as_ref()), v.to_str().unwrap_or("").to_string()))
    .collect();
  let body: Value = request.body().map(|b| b.as_bytes().unwrap_or_default().to_vec()).into();
  ManifestRequest { method, url, version, headers, body: Some(body), vars: Default::default() }
}

// TODO: Not sure how to normalize data from different formats/protocols into a canonical
//  `ManifestRequest` and `ManifestResponse`, so for now using this helper as a workaround
fn capitalize_header(header: &str) -> String {
  header
    .split('-')
    .map(|part| {
      let mut chars = part.chars();
      chars.next().map(|c| c.to_ascii_uppercase()).into_iter().chain(chars).collect::<String>()
    })
    .collect::<Vec<_>>()
    .join("-")
}

// TODO: Should TeeProof and other proofs be moved to `proofs` crate?
// Otherwise, adding TeeProof::manifest necessitates extra dependencies on the client
// Notice that all inputs to this function are from `proofs` crate
pub fn create_tee_proof(
  manifest: &Manifest,
  request: &ManifestRequest,
  response: &NotaryResponse,
  State(state): State<Arc<SharedState>>,
) -> Result<TeeProof, NotaryServerError> {
  validate_notarization_legal(manifest, request, response)?;

  let manifest_hash = manifest.to_keccak_digest()?;
  let to_sign = VerifyOutput {
    // Using manifest hash as a value here since we are not exposing any values extracted
    // from the request or response
    value:    format!("0x{}", hex::encode(manifest_hash)),
    manifest: manifest.clone(),
  };
  let signature = sign_verification(to_sign, State(state)).unwrap();
  let data = TeeProofData { manifest_hash: manifest_hash.to_vec() };

  Ok(TeeProof { data, signature })
}

/// Check if `manifest`, `request`, and `response` all fulfill requirements necessary for
/// a proof to be created
fn validate_notarization_legal(
  manifest: &Manifest,
  request: &ManifestRequest,
  response: &NotaryResponse,
) -> Result<(), NotaryServerError> {
  let req_result = manifest.request.is_subset_of(request)?;
  if !req_result.is_success() {
    info!("Manifest request validation failed: {:?}", req_result.errors());
    return Err(NotaryServerError::ManifestRequestMismatch);
  }

  let result = response.match_and_extract(&manifest.response)?;
  if !result.is_success() {
    info!("Manifest validation failed: {:?}", result.errors());
  }
  info!("Manifest returned values: {:?}", result.values());
  Ok(())
}
