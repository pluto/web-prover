use std::sync::Arc;

use axum::{
  extract::{self, State},
  Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

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

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
  #[error("Playwright session disconnected")]
  PlaywrightSessionDisconnected,
  #[error("Playwright session not connected")]
  PlaywrightSessionNotConnected,
  #[error(transparent)]
  FrameError(#[from] crate::frame::FrameError),
}

pub async fn prompt(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<PromptRequest>,
) -> Result<Json<PromptResponse>, NotaryServerError> {
  debug!("Prompting: {:?}", payload);
  // let inputs = payload.prompts.iter().map(|prompt| prompt.title.clone()).collect();
  // let response = PromptResponse { inputs };

  let session_id = uuid::Uuid::parse_str(&payload.uuid).unwrap();
  let frame_sessions = state.frame_sessions.lock().await;
  let response = match frame_sessions.get(&session_id) {
    Some(crate::frame::ConnectionState::Connected) => {
      let session = state.sessions.lock().await.get(&session_id).unwrap().clone();
      let response =
        session.lock().await.handle_prompt(payload.prompts).await.map_err(RunnerError::from)?;
      Ok::<PromptResponse, RunnerError>(response)
    },
    Some(crate::frame::ConnectionState::Disconnected(_)) => {
      return Err(RunnerError::PlaywrightSessionDisconnected).map_err(NotaryServerError::from);
    },
    None => {
      return Err(RunnerError::PlaywrightSessionNotConnected).map_err(NotaryServerError::from);
    },
  }?;

  drop(frame_sessions);

  Ok(Json(response))
}

pub async fn prove(
  State(_state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<ProveRequest>,
) -> Result<Json<()>, NotaryServerError> {
  debug!("Proving: {:?}", payload);
  Ok(Json(()))
}
