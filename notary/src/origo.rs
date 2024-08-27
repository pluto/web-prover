use std::sync::Arc;

use axum::{
  extract::{Query, State},
  response::Response,
};
use futures_util::{SinkExt, StreamExt};
use hex;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};
use tracing::{debug, error, info};

use crate::{
  axum_websocket::WebSocket,
  tlsn::{NotaryServerError, ProtocolUpgrade},
  SharedState,
};

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id:  String,
  target_host: String,
  target_port: u16,
}

pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

  debug!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(socket, session_id, query.target_host.clone(), query.target_port.clone())
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, session_id, query.target_host.clone(), query.target_port.clone())
    }),
  }
}

pub async fn websocket_notarize(
  socket: WebSocket,
  session_id: String,
  target_host: String,
  target_port: u16,
) {
  debug!("Upgraded to websocket connection");
  match proxy_service(socket.into_inner(), &session_id, &target_host, target_port).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using websocket!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using websocket: {err}");
    },
  }
}

pub async fn tcp_notarize(
  stream: TokioIo<Upgraded>,
  session_id: String,
  target_host: String,
  target_port: u16,
) {
  debug!("Upgraded to tcp connection");
  todo!("tcp_notarize");
  // match proxy_service(stream, &session_id, &target_host, target_port).await {
  //   Ok(_) => {
  //     info!(?session_id, "Successful notarization using tcp!");
  //   },
  //   Err(err) => {
  //     error!(?session_id, "Failed notarization using tcp: {err}");
  //   },
  // }
}

pub async fn proxy_service(
  socket: WebSocketStream<TokioIo<Upgraded>>,
  session_id: &str,
  target_host: &str,
  target_port: u16,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  info!("Connecting to target {}:{}", target_host, target_port);
  let mut tcp_stream = TcpStream::connect(format!("{}:{}", target_host, target_port))
    .await
    .expect("Failed to connect to TCP server");

  let mut tcp_buf = [0; 4096];

  let (mut ws_sink, mut ws_stream) = socket.split();
  loop {
    tokio::select! {
        Some(ws_msg) = ws_stream.next() => {
            let ws_msg = ws_msg.expect("failed to read ws");

            // TODO: dedup me
            if let Message::Binary(data) = ws_msg {
                println!("=== forward binary message === bytes={:?}, msg={:?}", data.len(), hex::encode(&data));
                tcp_stream.write_all(&data).await.expect("failed to write target server");
                let n = tcp_stream.read(&mut tcp_buf).await.expect("failed to read target server");
                println!("=== received response from server === bytes={:?}, message={:?}", n, hex::encode(tcp_buf[..n].to_vec()));

                if n == 0 {
                    println!("=== CLOSING SOCKET === bytes={:?}, message={:?}, buf_len={:?}", n, hex::encode(tcp_buf[..n].to_vec()), tcp_buf.len());
                    ws_sink.close().await.expect("failed to close socket");
                } else {
                    ws_sink.send(Message::Binary(tcp_buf[..n].to_vec())).await.expect("failed to forward to socket");
                }
            } else if let Message::Text(data) = ws_msg {
                println!("forward text message: {:?}", data);
                tcp_stream.write(data.as_bytes()).await.expect("failed to write to server");
                let n = tcp_stream.read(&mut tcp_buf).await.expect("failed to read target server");
                let msg = String::from_utf8(tcp_buf[..n].to_vec()).expect("failed to parse str");
                ws_sink.send(Message::Text(msg)).await.expect("failed to forward to socket");
            } else if let Message::Close(_) = ws_msg {
                println!("=== Client sent close message === {:?}", ws_msg);
                ws_sink.close().await.expect("failed to close socket");
            } else {
                println!("receiving data of unhandled format: {:?}", ws_msg);
            }
        },
        else => break,
    }
  }

  Ok(())
}
