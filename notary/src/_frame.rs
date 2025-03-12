use std::sync::Arc;

use axum::{
  extract::{ws::WebSocket, Query, State, WebSocketUpgrade},
  response::IntoResponse,
};
use futures::StreamExt;
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

use crate::SharedState;

pub mod sessions;
pub use sessions::Session;

// pub mod _views;
// pub mod actions;

// pub mod __views;

// pub enum SessionState {
//   Connected,
//   Disconnected(Session),
// }


// impl SessionState {
//   pub fn connect(self) -> Session {
//     match self {
//       SessionState::Connected => panic!(),
//       SessionState::Disconnected(sess) => sess,
//     }
//   }
// }
// HashMap<Uuid, SessionState>


pub struct MyStruct<S: State> {
  _d: PhantomData<S>,
  data: S::Data,
}

// MyStruct<Start> {
//   data: Session
// }

pub trait State {
   type Data;
}

pub struct Start;
impl State for Start {
  type Data = Session;
}
pub struct End;
impl State for End {
  type Data = ();
}

impl<S: State>  MyStruct<S> {
  pub fn have_fun(&mut self) {
    todo!("does something")
  }
}

impl MyStruct<Start> {
  pub fn end(self) -> MyStruct<End> {
    self.data.set_writer(writer)
    MyStruct<End>
  }
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


  let frame_sessions = state.frame_sessions.lock().await;

  frame_sessions.contains_key(&session_idion_id) {

    
    // if yes: 
    match frame_sessions.get(&session_id) {
      // None: websocket is already connected
      // Some(session), no websocket currently connected
    }

    // if no:
    // session does not exist, create a new one
  }


  // when connected, set uuid to None

  drop(frame_sessions);


  // create or resume session
  // let session = {
  //   let mut sessions = state.frame_sessions.lock().await;
  //   match sessions.get(&session_id) {
  //     Some(session) => session.clone(),
  //     None => {
  //       let session = Session::new(session_id);
  //       sessions.insert(session_id, session);
  //       &session
  //     },
  //   }
  // };

  ws.on_upgrade(move |socket| handle_websocket(session, socket, state))
}

async fn handle_websocket(
  mut session: Session<WebSocketWriter>,
  socket: WebSocket,
  _state: Arc<SharedState>,
) {
  let (sender, mut receiver) = socket.split();

  // allow frame session to write to websocket
  session.set_writer(Some(WebSocketWriter::new(sender))).await;

  // send current view to client
  // TODO

  // handle incoming websocket messages
  while let Some(Ok(message)) = receiver.next().await {
    match message {
      axum::extract::ws::Message::Text(text) => {
        // let state = match serde_json::from_str::<actions::State>(&text) {
        //   Ok(state) => state,
        //   Err(e) => {
        //     warn!("Failed to parse websocket message: {}", e);
        //     continue;
        //   },
        // };
        // session.read(state).await;
        todo!("fsdf")
      },
      axum::extract::ws::Message::Binary(_) => {
        warn!("Binary messages are not supported");
        break;
      },
      axum::extract::ws::Message::Ping(_) => {
        todo!("Are Pings handled by axum's tokio-tungstenite?");
      },
      axum::extract::ws::Message::Pong(_) => {
        todo!("Are Pongs handled by axum's tokio-tungstenite?");
      },
      axum::extract::ws::Message::Close(_) => {
        break;
      },
    }
  }

  session.close().await;
}

pub struct WebSocketWriter {
  sender: futures::stream::SplitSink<axum::extract::ws::WebSocket, axum::extract::ws::Message>,
}

impl WebSocketWriter {
  pub fn new(
    sender: futures::stream::SplitSink<axum::extract::ws::WebSocket, axum::extract::ws::Message>,
  ) -> Self {
    WebSocketWriter { sender }
  }
}

impl sessions::Writer for WebSocketWriter {
  async fn write<T: Serialize + Send + Sync>(&mut self, data: &T) -> Result<(), String> {
    use futures::SinkExt;

    let json =
      serde_json::to_string(data).map_err(|e| format!("Failed to serialize to JSON: {}", e))?;

    self
      .sender
      .send(axum::extract::ws::Message::Text(json))
      .await
      .map_err(|e| format!("Failed to send message: {}", e))
  }
}
