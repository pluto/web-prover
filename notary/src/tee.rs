use std::{sync::Arc, time::SystemTime};

use axum::{
  extract::{self, State},
  Json,
};
use serde::{Deserialize, Serialize};

use crate::{errors::TeeError, manifest::Manifest, SharedState, TeeSession};

#[derive(Deserialize, Debug, Clone)]
pub struct NewSessionBody {
  session_id: String,
  manifest:   Manifest,
}

#[derive(Serialize)]
pub struct NewSessionReply {}

pub async fn new_session(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<NewSessionBody>,
) -> Result<Json<NewSessionReply>, TeeError> {
  state.tee_sessions.lock().unwrap().insert(payload.session_id.to_string(), TeeSession {
    manifest:   payload.manifest.clone(),
    request:    Default::default(),
    _timestamp: SystemTime::now(),
  });

  let response = NewSessionReply {};

  Ok(Json(response))
}
