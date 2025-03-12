use std::{sync::Arc, time::SystemTime};

use axum::{
  extract::{ws::WebSocket, Query, State, WebSocketUpgrade},
  response::IntoResponse,
};
use futures::StreamExt;
use tracing::{info, warn};
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

  /// Called when the client closes the connection.
  pub async fn on_client_close(&mut self) {}
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

async fn handle_websocket_connection(
  state: Arc<SharedState>,
  socket: WebSocket,
  mut session: Session,
) {
  info!("[{}] New Websocket connected", session.session_id);
  let mut disconnected = false;
  let (sender, mut receiver) = socket.split();

  // TODO what if next() returns None?!
  while let Some(result) = receiver.next().await {
    match result {
      Ok(message) => {
        match message {
          axum::extract::ws::Message::Text(text) => {
            // TODO
          },
          axum::extract::ws::Message::Binary(_) => {
            warn!("Binary messages are not supported");
            disconnected = true;
            break;
          },
          axum::extract::ws::Message::Ping(_) => {
            todo!("Are Pings handled by axum's tokio-tungstenite?");
          },
          axum::extract::ws::Message::Pong(_) => {
            todo!("Are Pongs handled by axum's tokio-tungstenite?");
          },
          axum::extract::ws::Message::Close(_) => {
            session.on_client_close().await;
            disconnected = true;
            break;
          },
        }
      },
      Err(_err) => {
        disconnected = false;
        break;
      },
    }
  }

  let mut frame_sessions = state.frame_sessions.lock().await;
  if !disconnected {
    // If the Websocket connection drops, mark it as disconnected, unless it was correctly closed.
    info!("[{}] Websocket disconnected", session.session_id);
    frame_sessions
      .insert(session.session_id, ConnectionState::Disconnected(session, SystemTime::now()));
  } else {
    frame_sessions.remove(&session.session_id);
  }
}
