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

pub async fn attestation(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<NewSessionBody>,
) -> Result<Json<NewSessionReply>, TeeError> {

}

pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

  info!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(
        socket,
        session_id,
        query.target_host.clone(),
        query.target_port.clone(),
        state,
      )
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, session_id, query.target_host.clone(), query.target_port.clone(), state)
    }),
  }
}

pub async fn websocket_notarize(
  socket: WebSocket,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to websocket connection");
  let stream = WsStream::new(socket.into_inner()).compat();
  match proxy_service(stream, &session_id, &target_host, target_port, state).await {
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
  state: Arc<SharedState>,
) {
  debug!("Upgraded to tcp connection");
  match proxy_service(stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

pub async fn proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin>(
  socket: S,
  session_id: &str,
  target_host: &str,
  target_port: u16,
  state: Arc<SharedState>,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  info!("Connecting to target {}:{}", target_host, target_port);
  let mut tcp_stream = TcpStream::connect(format!("{}:{}", target_host, target_port))
    .await
    .expect("Failed to connect to TCP server");

  let (mut tcp_read, mut tcp_write) = tcp_stream.split();

  let (mut socket_read, mut socket_write) = tokio::io::split(socket);

  let request_buf = Arc::new(Mutex::new(vec![0u8; 0]));

  let client_to_server = async {
    let mut buf = [0u8; 8192];
    loop {
      match socket_read.read(&mut buf).await {
        Ok(0) => break,
        Ok(n) => {
          debug!("sending to server len={:?}, data={:?}", n, hex::encode(&buf[..n]));
          tcp_write.write_all(&buf[..n]).await?;
          let mut buffer = request_buf.lock().unwrap();
          buffer.extend_from_slice(&buf[..n]);
        },
        Err(e) => return Err(e),
      }
    }
    tcp_write.shutdown().await.unwrap();
    Ok(())
  };

  let server_to_client = async {
    let mut buf = [0u8; 8192];
    loop {
      match tcp_read.read(&mut buf).await {
        Ok(0) => break,
        Ok(n) => {
          debug!("sending to client len={:?}, data={:?}", n, hex::encode(&buf[..n]));
          socket_write.write_all(&buf[..n]).await?;
          let mut buffer = request_buf.lock().unwrap();
          buffer.extend_from_slice(&buf[..n]);
        },
        Err(e) => return Err(e),
      }
    }
    socket_write.shutdown().await.unwrap();
    Ok(())
  };

  use futures::{future::select, pin_mut};
  pin_mut!(client_to_server, server_to_client);
  let _ = select(client_to_server, server_to_client).await.factor_first().0;

  state.origo_sessions.lock().unwrap().insert(session_id.to_string(), OrigoSession {
    // TODO currently request is both, request and response. will this become a problem?
    request:    request_buf.lock().unwrap().to_vec(),
    _timestamp: SystemTime::now(),
  });

  Ok(())
}