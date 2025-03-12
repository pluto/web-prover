use std::{sync::Arc, time::SystemTime};

use axum::{
  extract::{ws::WebSocket, Query, State, WebSocketUpgrade},
  response::IntoResponse,
};
use futures::StreamExt;
use tracing::{info, warn};
use uuid::Uuid;
use views::View;

use crate::SharedState;

pub mod views;

pub enum ConnectionState<Session> {
  Connected,
  Disconnected(Session, SystemTime), /* TODO run a task that cleans up disconnected sessions
                                      * every 60 secs */
}

pub struct Session {
  session_id:   Uuid,
  // client:       Option<Client>,
  current_view: View,
}

impl Session {
  pub fn new(session_id: Uuid) -> Self {
    Session { session_id, current_view: View::InitialView(views::InitialView {}) }
  }

  // pub async fn handle(&mut self, request: Request) -> Response;

  /// Called when the client connects. Can be called multiple times.
  pub async fn on_client_connect(&mut self) {
    // TODO send current_view serialized
  }

  /// Called when the client disconnects unexpectedly. Can be called multiple times.
  pub async fn on_client_disconnect(&mut self) {}

  /// Called when the client closes the connection. Called only once.
  pub async fn on_client_close(&mut self) {}
}

pub async fn on_websocket(
  ws: WebSocketUpgrade,
  Query(params): Query<std::collections::HashMap<String, String>>,
  State(state): State<Arc<SharedState>>,
) -> impl IntoResponse {
  // Parse ?session_id from query
  let session_id = match params.get("session_id") {
    Some(id) => match Uuid::parse_str(id) {
      Ok(uuid) => uuid,
      Err(_) =>
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid session_id format, expected UUID") // TODO return json error
          .into_response(),
    },
    None =>
      return (axum::http::StatusCode::BAD_REQUEST, "Missing required session_id query parameter") // TODO return json error
        .into_response(),
  };

  let mut frame_sessions = state.frame_sessions.lock().await;

  let session = match frame_sessions.remove(&session_id) {
    Some(ConnectionState::Connected) => {
      frame_sessions.insert(session_id, ConnectionState::Connected);
      return (axum::http::StatusCode::BAD_REQUEST, "Session already connected").into_response(); // TODO return json error
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
  let mut keepalive = false;
  let (sender, mut receiver) = socket.split();
  session.on_client_connect().await; // TODO pass sender?

  // TODO what if next() returns None?!
  while let Some(result) = receiver.next().await {
    match result {
      Ok(message) => {
        match message {
          axum::extract::ws::Message::Text(text) => {
            // TODO parse json text and call session handle func, then call send with it
          },
          axum::extract::ws::Message::Binary(_) => {
            warn!("Binary messages are not supported");
            keepalive = false;
            break;
          },
          axum::extract::ws::Message::Ping(_) => {
            todo!("Are Pings handled by axum's tokio-tungstenite?");
          },
          axum::extract::ws::Message::Pong(_) => {
            todo!("Are Pongs handled by axum's tokio-tungstenite?");
          },
          axum::extract::ws::Message::Close(_) => {
            keepalive = false;
            break;
          },
        }
      },
      Err(_err) => {
        keepalive = true;
        break;
      },
    }
  }

  let mut frame_sessions = state.frame_sessions.lock().await;
  if keepalive {
    // If the Websocket connection drops, mark it as disconnected, unless it was correctly closed.
    info!("[{}] Websocket disconnected", session.session_id);
    session.on_client_disconnect().await;
    frame_sessions
      .insert(session.session_id, ConnectionState::Disconnected(session, SystemTime::now()));
  } else {
    session.on_client_close().await;
    frame_sessions.remove(&session.session_id);
  }
}
