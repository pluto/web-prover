use std::{sync::Arc, time::SystemTime};

use axum::{
  extract::{
    ws::{Message, WebSocket},
    Query, State, WebSocketUpgrade,
  },
  response::IntoResponse,
};
use futures::StreamExt;
use futures_util::{stream::SplitSink, SinkExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{info, warn};
use uuid::Uuid;

// use views::View;
use crate::SharedState;

// pub mod views;

#[derive(Debug, Error)]
pub enum FrameError {}

pub enum ConnectionState<Session> {
  Connected,
  Disconnected(Session, SystemTime), /* TODO run a task that cleans up disconnected sessions
                                      * every 60 secs */
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Action {
  pub kind:    String,
  pub payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub enum View {
  InitialView,
}

pub struct Session {
  session_id:   Uuid,
  // sender:        Option<SplitSink<WebSocket, Message>>,
  current_view: View,
  cancel:       oneshot::Sender<()>,
}

impl Session {
  pub fn new(session_id: Uuid) -> Self {
    let (cancel_sender, cancel_receiver) = oneshot::channel();
    let session = Session { session_id, current_view: View::InitialView, cancel: cancel_sender };
    // TODO: this moves session to the new task, so we can't use it anymore
    // Run should be executed elsewhere
    // tokio::spawn(session.run(cancel_receiver));
    session
  }

  async fn run(&self, cancel: oneshot::Receiver<()>) {
    // TODO start running playwright script
    //

    // TODO kill the session if cancelled
    let _ = cancel.await;
  }

  pub async fn handle(&mut self, request: Action) -> Action { todo!("") }

  /// Called when the client connects. Can be called multiple times.
  pub async fn on_client_connect(&mut self) {
    // TODO send current_view serialized
  }

  /// Called when the client disconnects unexpectedly. Can be called multiple times.
  pub async fn on_client_disconnect(&mut self) {}

  /// Called when the client closes the connection. Called only once.
  pub async fn on_client_close(&self) { let _ = self.cancel.send(()); }
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
  let (mut sender, mut receiver) = socket.split();
  session.on_client_connect().await; // TODO pass sender?

  // TODO what if next() returns None?!
  while let Some(result) = receiver.next().await {
    match result {
      Ok(message) => match message {
        axum::extract::ws::Message::Text(text) => {
          process_text_message(text, &mut session, &mut sender).await;
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

async fn process_text_message(
  text: String,
  session: &mut Session,
  sender: &mut SplitSink<WebSocket, Message>,
) {
  let action = serde_json::from_str::<Action>(&text);
  match action {
    Ok(action) => {
      let result = session.handle(action).await;
      // TODO send result to client
    },
    Err(err) => {
      // TODO send error to client
      let _ = sender.send(Message::Text(format!("Invalid action: {}", err))).await;
    },
  }
  // TODO send error result to client
  // TODO send action result to client
}
