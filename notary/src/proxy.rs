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
  proof::TeeProof,
};

use crate::{errors::NotaryServerError, tee::create_tee_proof, SharedState};

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id: Uuid,
}

pub async fn proxy(
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<client::ProxyConfig>,
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
