use std::sync::Arc;

use axum::{
  extract::{self, State},
  Json,
};
use tracing::debug;
use web_prover_core::frame::{PromptRequest, PromptResponse, ProveRequest};

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
  // let inputs = payload.prompts.iter().map(|prompt| prompt.title.clone()).collect();
  // let response = PromptResponse { inputs };

  let session_id = uuid::Uuid::parse_str(&payload.uuid).unwrap();
  debug!("session_id: {:?}", session_id);
  let frame_sessions = state.frame_sessions.lock().await;
  debug!("frame_sessions_got");
  let response = match frame_sessions.get(&session_id) {
    Some(crate::frame::ConnectionState::Connected) => {
      let session = state.sessions.lock().await.get(&session_id).unwrap().clone();
      debug!("session lock acquired");
      let prompt_response_receiver =
        session.lock().await.handle_prompt(payload.prompts).await.map_err(RunnerError::from)?;
      debug!("prompt_response_receiver acquired");
      // TODO: is there a deadlock here???
      // prompt response is received after timeout has passed
      let response =
        tokio::time::timeout(std::time::Duration::from_secs(30), prompt_response_receiver)
          .await
          .map_err(|_| RunnerError::FrameError(crate::frame::FrameError::PromptTimeout))?
          .map_err(RunnerError::from)?;
      // let response = match prompt_response_receiver.await {
      //   Ok(response) => response,
      //   Err(e) => return Err(e).map_err(RunnerError::from)?,
      // };
      debug!("Prompt response: {:?}", response);
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
