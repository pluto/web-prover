use std::{sync::Arc, time::SystemTime};

use axum::{
  extract::{ws::WebSocket, Query, State, WebSocketUpgrade},
  response::IntoResponse,
};
use tracing::info;
use uuid::Uuid;

use crate::SharedState;

pub enum ConnectionState<Session> {
  Connected,
  Disconnected(Session, SystemTime), /* TODO run a task that cleans up disconnected sessions
                                      * every 60 secs */
}

pub struct Session {
  session_id: Uuid,
}

impl Session {
  pub fn new(session_id: Uuid) -> Self { Session { session_id } }
}

pub async fn handler(
  ws: WebSocketUpgrade,
  Query(params): Query<std::collections::HashMap<String, String>>,
  State(state): State<Arc<SharedState>>,
) -> impl IntoResponse {
  // Parse ?session_id from query
  let session_id = match params.get("session_id") {
    Some(id) => match Uuid::parse_str(id) {
      Ok(uuid) => uuid,
      Err(_) =>
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid session_id format, expected UUID")
          .into_response(),
    },
    None =>
      return (axum::http::StatusCode::BAD_REQUEST, "Missing required session_id query parameter")
        .into_response(),
  };

  let mut frame_sessions = state.frame_sessions.lock().await;

  let session = match frame_sessions.remove(&session_id) {
    Some(ConnectionState::Connected) => {
      frame_sessions.insert(session_id, ConnectionState::Connected);
      return (axum::http::StatusCode::BAD_REQUEST, "Session already connected").into_response();
    },

    Some(ConnectionState::Disconnected(session, _)) => {
      frame_sessions.insert(session_id, ConnectionState::Connected);
      session
    },

    None => {
      let session = Session::new(session_id);
      frame_sessions.insert(session_id, ConnectionState::Connected);
      session
    },
  };

  drop(frame_sessions); // drop mutex guard

  ws.on_upgrade(move |socket| handle_websocket_connection(state, socket, session))
}

async fn handle_websocket_connection(state: Arc<SharedState>, socket: WebSocket, session: Session) {
  info!("[{}] New Websocket connected", session.session_id);

  // TODO: Handle Websocket messages

  // If the Websocket connection drops, mark it as disconnected, unless it was correctly closed.
  info!("[{}] Websocket disconnected", session.session_id);
  let mut frame_sessions = state.frame_sessions.lock().await;
  frame_sessions
    .insert(session.session_id, ConnectionState::Disconnected(session, SystemTime::now()));
}
