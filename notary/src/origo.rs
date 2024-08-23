use std::sync::Arc;

use axum::{
  extract::{Query, State},
  response::Response,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  tlsn::{NotaryServerError, ProtocolUpgrade},
  SharedState,
};

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id: String,
}

pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

  debug!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| websocket_notarize(socket, session_id)),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| tcp_notarize(stream, session_id)),
  }
}

pub async fn websocket_notarize(socket: WebSocket, session_id: String) {
  debug!("Upgraded to websocket connection");
  let stream = WsStream::new(socket.into_inner()).compat();
  match proxy_service(stream, &session_id).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using websocket!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using websocket: {err}");
    },
  }
}

pub async fn tcp_notarize(stream: TokioIo<Upgraded>, session_id: String) {
  debug!("Upgraded to tcp connection");
  match proxy_service(stream, &session_id).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

pub async fn proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
  socket: S,
  session_id: &str,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  todo!("implement proxy");
  //  socket.compat()

  Ok(())
}
