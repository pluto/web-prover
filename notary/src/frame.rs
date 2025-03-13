use core::panic;
use std::{
  path::PathBuf,
  process::Command,
  sync::Arc,
  time::{Duration, SystemTime},
};

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
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::runner::{Prompt, PromptResponse};
// use views::View;
use crate::SharedState;

// pub mod views;

#[derive(Debug, Error)]
pub enum FrameError {
  #[error("WebSocket error: {0}")]
  WebSocketError(String),
  #[error("Prompt timeout")]
  PromptTimeout,
}

// TODO: either session should live under connection state or connection state should be a session
#[derive(Debug)]
pub enum ConnectionState {
  Connected,
  Disconnected(SystemTime), /* TODO run a task that cleans up disconnected sessions
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
  PromptView { prompts: Vec<Prompt> },
}

pub struct Session {
  session_id:             Uuid,
  ws_sender:              Option<SplitSink<WebSocket, Message>>,
  // sender:                Option<mpsc::Sender<View>>,
  current_view:           View,
  prompt_response_sender: Arc<Mutex<Option<oneshot::Sender<PromptResponse>>>>,
  // cancel:       oneshot::Sender<()>,
}

impl Session {
  pub fn new(session_id: Uuid) -> Self {
    // let (cancel_sender, cancel_receiver) = oneshot::channel();
    let session = Session {
      session_id,
      current_view: View::InitialView,
      ws_sender: None,
      prompt_response_sender: Arc::new(Mutex::new(None)),
    };
    session
  }

  async fn run(&self) {
    let playwright_runner_config = web_prover_executor::playwright::PlaywrightRunnerConfig {
      script:          "".to_string(),
      timeout_seconds: 0,
    };

    let node_path =
      Command::new("which").arg("node").output().expect("Failed to run `which node`").stdout;
    let node_path = String::from_utf8_lossy(&node_path).trim().to_string();

    let playwright_runner = web_prover_executor::playwright::PlaywrightRunner::new(
      playwright_runner_config,
      web_prover_executor::playwright::PLAYWRIGHT_TEMPLATE.to_string(),
      PathBuf::from(node_path),
      vec![(String::from("DEBUG"), String::from("pw:api"))],
    );

    let session_id = self.session_id.clone();
    let script_result =
      tokio::spawn(async move { playwright_runner.run_script(&session_id).await });

    match script_result.await {
      Ok(Ok(output)) => {
        info!("Playwright output: {:?}", output);
      },
      Ok(Err(e)) => {
        error!("Playwright script failed: {:?}", e);
      },
      Err(e) => {
        error!("Failed to await script result: {:?}", e);
      },
    }

    // TODO kill the session if cancelled
    // let _ = cancel.await;
  }

  pub async fn handle(&mut self, request: Action) -> Action { todo!("") }

  pub async fn handle_prompt(
    &mut self,
    prompts: Vec<Prompt>,
  ) -> Result<PromptResponse, FrameError> {
    let prompt_view = View::PromptView { prompts };
    let serialized_view = serde_json::to_string(&prompt_view).unwrap();

    let (prompt_response_sender, prompt_response_receiver) = oneshot::channel::<PromptResponse>();
    self.prompt_response_sender.lock().await.replace(prompt_response_sender);

    // TODO: session should store each view sent with a request id, so that it can match the
    // response
    self.ws_sender.as_mut().unwrap().send(Message::Text(serialized_view)).await.unwrap();

    self.current_view = prompt_view;

    match tokio::time::timeout(Duration::from_secs(60), prompt_response_receiver).await {
      Ok(Ok(prompt_response)) => Ok(prompt_response),
      Ok(Err(_)) => Err(FrameError::WebSocketError("Prompt response channel closed".to_string())),
      Err(_) => Err(FrameError::PromptTimeout),
    }
  }

  pub async fn handle_prompt_response(&mut self, prompt_response: PromptResponse) {
    let prompt_response_sender = self.prompt_response_sender.lock().await.take().unwrap();
    prompt_response_sender.send(prompt_response).unwrap();
  }

  /// Called when the client connects. Can be called multiple times.
  pub async fn on_client_connect(&mut self) {
    // send initial view
    let current_view_serialized = serde_json::to_string(&self.current_view).unwrap();
    self.ws_sender.as_mut().unwrap().send(Message::Text(current_view_serialized)).await.unwrap();
  }

  /// Called when the client disconnects unexpectedly. Can be called multiple times.
  pub async fn on_client_disconnect(&mut self) {}

  /// Called when the client closes the connection. Called only once.
  pub async fn on_client_close(&mut self) {
    // let _ = self.cancel.send(());
    // TODO: cancel other tasks like playwright
    if let Some(mut ws_sender) = self.ws_sender.take() {
      let _ = ws_sender.close().await; // attempt to close the websocket connection gracefully
    }
  }
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

    Some(ConnectionState::Disconnected(_)) => {
      frame_sessions.insert(session_id, ConnectionState::Connected);
      let session = state.sessions.lock().await.get(&session_id).unwrap().clone();
      session
    },

    None => {
      let session = Session::new(session_id);
      frame_sessions.insert(session_id, ConnectionState::Connected);
      Arc::new(Mutex::new(session))
    },
  };

  drop(frame_sessions); // drop mutex guard

  ws.on_upgrade(move |socket| handle_websocket_connection(state, socket, session))
}

async fn handle_websocket_connection(
  state: Arc<SharedState>,
  socket: WebSocket,
  session: Arc<Mutex<Session>>,
) {
  info!("[{}] New Websocket connected", session.lock().await.session_id);
  let mut keepalive = false;
  let (sender, mut receiver) = socket.split();

  session.lock().await.ws_sender = Some(sender);

  state.sessions.lock().await.insert(session.lock().await.session_id, session.clone());

  session.lock().await.on_client_connect().await; // TODO pass sender?

  session.lock().await.run().await;

  // TODO what if next() returns None?!
  while let Some(result) = receiver.next().await {
    match result {
      Ok(message) => match message {
        axum::extract::ws::Message::Text(text) => {
          process_text_message(text, session.clone()).await;
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
    info!("[{}] Websocket disconnected", session.lock().await.session_id);
    session.lock().await.on_client_disconnect().await;
    frame_sessions
      .insert(session.lock().await.session_id, ConnectionState::Disconnected(SystemTime::now()));
  } else {
    session.lock().await.on_client_close().await;
    frame_sessions.remove(&session.lock().await.session_id);
    state.sessions.lock().await.remove(&session.lock().await.session_id);
  }
  drop(frame_sessions);
}

async fn process_text_message(text: String, session: Arc<Mutex<Session>>) {
  let action = serde_json::from_str::<Action>(&text);
  match action {
    Ok(action) => {
      let action = session.lock().await.handle(action).await;
      match action.kind.as_str() {
        "prompt_response" => {
          let prompt_response = serde_json::from_value::<PromptResponse>(action.payload).unwrap();
          session.lock().await.handle_prompt_response(prompt_response).await;
        },
        _ => {
          panic!("Invalid action: {}", action.kind);
        },
      }
      // TODO send result to client
    },
    Err(err) => {
      // TODO send error to client

      // let sender = session.lock().await.ws_sender.as_mut();

      // // Send an error message to the client
      // if let Some(sender) = sender {
      //   let _ =
      //     sender.send(axum::extract::ws::Message::Text(format!("Invalid action: {}",
      // err))).await; }
    },
  }
  // TODO send error result to client
  // TODO send action result to client
}
