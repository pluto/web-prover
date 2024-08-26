use std::sync::Arc;

use axum::{
  extract::{Query, State},
  response::Response,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
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
  let stream = WsStream::new(socket.into_inner()).compat();
  match proxy_service(stream, &session_id, &target_host, target_port).await {
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
  match proxy_service(stream, &session_id, &target_host, target_port).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

pub async fn proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
  mut socket: S,
  session_id: &str,
  target_host: &str,
  target_port: u16,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  info!("Connecting to target {}:{}", target_host, target_port);
  let mut tcp_stream = TcpStream::connect(format!("{}:{}", target_host, target_port))
    .await
    .expect("Failed to connect to TCP server");

  let (mut tcp_read, mut tcp_write) = tcp_stream.split();

  let (mut socket_read, mut socket_write) = tokio::io::split(socket);

  let client_to_server = async {
    // tokio::io::copy(&mut socket_read, &mut tcp_write).await.unwrap();

    let mut buf = [0; 4096];
    loop {
      let n = socket_read.read(&mut buf).await.unwrap();
      if n == 0 {
        debug!("close client_to_server");
        break;
      }
      if n > 0 {
        let data = &buf[..n];
        debug!("write to server");
        tcp_write.write_all(data).await.unwrap();
      }
    }
  };

  let server_to_client = async {
    // tokio::io::copy(&mut tcp_read, &mut socket_write).await.unwrap();

    let mut buf = [0; 4096];
    loop {
      let n = tcp_read.read(&mut buf).await.unwrap();
      if n == 0 {
        debug!("close server_to_client");
        break;
      }
      if n > 0 {
        let data = &buf[..n];
        debug!("write to client");
        socket_write.write_all(data).await.unwrap();
      }
    }
  };

  // client_to_server.await;
  // server_to_client.await;

  tokio::join!(client_to_server, server_to_client);

  // send from socket to tcp_stream, then return from tcp_stream to socket

  //  TokioIo::new(socket)

  // TODO better error handling
  // tokio::io::copy_bidirectional(&mut socket, &mut tcp_stream).await.unwrap();

  // let (r, w) = tcp_stream.split();

  // tokio::io::copy(&mut socket, &mut tcp_stream).await.unwrap();
  // tokio::io::copy(&mut socket, &mut tcp_socketait.unwrtcp_stream

  Ok(())
}
