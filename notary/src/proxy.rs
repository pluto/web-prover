use std::{sync::Arc, time::Duration};

use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use client::{TeeProof, TeeProofData};
use serde::Deserialize;
use tracing::info;

use crate::SharedState;

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id: String,
}

pub async fn proxy(
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<client::ProxyConfig>,
) -> Json<TeeProof> {
  let session_id = query.session_id.clone();

  info!("Starting proxy with ID: {}", session_id);

  let method: reqwest::Method = payload.target_method.parse().unwrap();

  let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
  let mut request_builder: reqwest::RequestBuilder = client.request(method, payload.target_url);

  for (key, value) in payload.target_headers {
    request_builder = request_builder.header(key, value);
  }

  if !payload.target_body.is_empty() {
    request_builder = request_builder.body(payload.target_body.clone());
  }

  let response = request_builder.send().await.unwrap();

  // TODO
  // apply manifest to request/ response

  let tee_proof = TeeProof {
    data:      TeeProofData { manifest_hash: "todo".to_string().into_bytes() },
    signature: "sign(hash(ProxyProofData))".to_string(),
  };

  Json(tee_proof)
}
