use std::sync::Arc;

use axum::{
  extract::{self, State},
  Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::NotaryServerError, SharedState};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Prompt {
  pub title: String,
  pub types: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromptRequest {
  pub uuid:    String,
  pub prompts: Vec<Prompt>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PromptResponse {
  pub inputs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProveRequest {
  pub uuid:  String,
  pub key:   String,
  pub value: Value,
}

pub async fn prompt(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<PromptRequest>,
) -> Result<Json<PromptResponse>, NotaryServerError> {
  let inputs = payload.prompts.iter().map(|prompt| prompt.title.clone()).collect();
  let response = PromptResponse { inputs };
  Ok(Json(response))
}

pub async fn prove(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<ProveRequest>,
) -> Result<Json<()>, NotaryServerError> {
  println!("Proving: {:?}", payload);
  Ok(Json(()))
}
