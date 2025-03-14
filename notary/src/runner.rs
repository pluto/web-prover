use std::sync::Arc;

use axum::{
  extract::{self, State},
  Json,
};
use tracing::debug;
use web_prover_core::frame::{PromptRequest, PromptResponse, ProveOutput};

use crate::{error::NotaryServerError, SharedState};

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
  #[error("Playwright session disconnected")]
  PlaywrightSessionDisconnected,
  #[error("Playwright session not connected")]
  PlaywrightSessionNotConnected,
  #[error(transparent)]
  FrameError(#[from] crate::frame::FrameError),
  #[error(transparent)]
  RecvError(#[from] tokio::sync::oneshot::error::RecvError),
}

pub async fn prompt(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<PromptRequest>,
) -> Result<Json<PromptResponse>, NotaryServerError> {
  debug!("Prompting: {:?}", payload);

  let session_id = uuid::Uuid::parse_str(&payload.uuid).unwrap();

  let frame_sessions = state.frame_sessions.lock().await;
  let prompt_response_receiver = match frame_sessions.get(&session_id) {
    Some(crate::frame::ConnectionState::Connected) => {
      let session = state.sessions.lock().await.get(&session_id).unwrap().clone();
      let prompt_response_receiver =
        session.lock().await.handle_prompt(payload.prompts).await.map_err(RunnerError::from)?;
      debug!("prompt_response_receiver acquired");
      Ok::<tokio::sync::oneshot::Receiver<PromptResponse>, RunnerError>(prompt_response_receiver)
    },
    Some(crate::frame::ConnectionState::Disconnected(_)) => {
      return Err(RunnerError::PlaywrightSessionDisconnected).map_err(NotaryServerError::from);
    },
    None => {
      return Err(RunnerError::PlaywrightSessionNotConnected).map_err(NotaryServerError::from);
    },
  }?;

  debug!("waiting for prompt response");
  let response = tokio::time::timeout(std::time::Duration::from_secs(30), prompt_response_receiver)
    .await
    .map_err(|_| RunnerError::FrameError(crate::frame::FrameError::PromptTimeout))?
    .map_err(RunnerError::from)?;

  Ok(Json(response))
}

pub async fn prove(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<ProveOutput>,
) -> Result<Json<()>, NotaryServerError> {
  debug!("Proving: {:?}", payload);

  let session_id = uuid::Uuid::parse_str(&payload.uuid).unwrap();

  let frame_sessions = state.frame_sessions.lock().await;
  let session = match frame_sessions.get(&session_id) {
    Some(crate::frame::ConnectionState::Connected) =>
      state.sessions.lock().await.get(&session_id).unwrap().clone(),
    Some(crate::frame::ConnectionState::Disconnected(_)) => {
      return Err(RunnerError::PlaywrightSessionDisconnected).map_err(NotaryServerError::from);
    },
    None => {
      return Err(RunnerError::PlaywrightSessionNotConnected).map_err(NotaryServerError::from);
    },
  };

  session.lock().await.handle_prove(payload.proof).await.map_err(RunnerError::from)?;

  Ok(Json(()))
}
