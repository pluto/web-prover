use std::sync::Arc;

use axum::{
  extract::{Query, State},
  response::Response,
};
#[cfg(feature = "tee-google-confidential-space-token-generator")]
use caratls_ekm_google_confidential_space_server::GoogleConfidentialSpaceTokenGenerator;
#[cfg(feature = "tee-dummy-token-generator")]
use caratls_ekm_server::DummyTokenGenerator;
use caratls_ekm_server::TeeTlsAcceptor;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use proofs::program::{manifest, manifest::Manifest};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket, errors::NotaryServerError, origo::proxy_service,
  tlsn::ProtocolUpgrade, SharedState,
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

  info!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(socket, session_id, query.target_host.clone(), query.target_port, state)
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, session_id, query.target_host.clone(), query.target_port, state)
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
  debug!("Upgraded to TEE TLS via websocket connection");
  let stream = WsStream::new(socket.into_inner()).compat();
  match tee_proxy_service(stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using TEE TLS via websocket!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using TEE TLS via websocket: {err}");
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
  debug!("Upgraded to TEE TLS connection");
  match tee_proxy_service(stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using TEE TLS!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using TEE TLS: {err}");
    },
  }
}

pub async fn tee_proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin>(
  socket: S,
  session_id: &str,
  target_host: &str,
  target_port: u16,
  state: Arc<SharedState>,
) -> Result<(), NotaryServerError> {
  #[cfg(feature = "tee-google-confidential-space-token-generator")]
  let token_generator = GoogleConfidentialSpaceTokenGenerator::new("audience");

  #[cfg(feature = "tee-dummy-token-generator")]
  let token_generator = DummyTokenGenerator { token: "dummy".to_string() };

  let tee_tls_acceptor = TeeTlsAcceptor::new_with_ephemeral_cert(token_generator, "example.com"); // TODO example.com
  let mut tee_tls_stream = tee_tls_acceptor.accept(socket).await?;
  proxy_service(&mut tee_tls_stream, session_id, target_host, target_port, state.clone()).await?;

  debug!("Waiting for bytes to be read:");

  // TODO wait for TLS secrets


  // TODO wait for manifest
  let manifest = recover_manifest(&mut tee_tls_stream).await;
  dbg!(manifest);

  // Keep reading into buf until you get the ending byte
  loop {
    let mut buf: [u8; 10] = [0u8; 10];
    tee_tls_stream.read(&mut buf).await?;
    dbg!(buf);
    if buf.to_vec().iter().all(|b| *b == 0) {
      debug!("Got all bytes");
      break;
    }
  }

  // TODO decrypt session with TLS secrets
  let transcript = state.origo_sessions.lock().unwrap().get(session_id).cloned().unwrap();

  // TODO apply manifest
  // TODO return web proof

  Ok(())
}

async fn recover_manifest<R: AsyncReadExt + Unpin>(stream: &mut R) -> Manifest {
  // Buffer to store the "header" (4 bytes, indicating the length of the Manifest)
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf).await.unwrap();

  // Deserialize the length prefix (convert from little-endian to usize)
  let manifest_length = u32::from_le_bytes(len_buf) as usize;

  // Allocate a buffer to hold only the bytes needed for the Manifest
  let mut manifest_buf = vec![0u8; manifest_length];
  stream.read_exact(&mut manifest_buf).await.unwrap();

  Manifest::from_wire_bytes(&manifest_buf)
}
