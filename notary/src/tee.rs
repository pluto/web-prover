use std::sync::Arc;

use axum::{
  extract,
  extract::{Query, State},
  response::Response,
};
#[cfg(feature = "tee-google-confidential-space-token-generator")]
use caratls_ekm_google_confidential_space_server::GoogleConfidentialSpaceTokenGenerator;
#[cfg(feature = "tee-dummy-token-generator")]
use caratls_ekm_server::DummyTokenGenerator;
use caratls_ekm_server::TeeTlsAcceptor;
use client::{
  origo::{OrigoSecrets, SignBody},
  TeeProof, TeeProofData,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use proofs::program::{manifest, manifest::Manifest};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  errors::{NotaryServerError, ProxyError},
  origo::proxy_service,
  tlsn::ProtocolUpgrade,
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

  debug!("Create TLS acceptor");
  let tee_tls_acceptor = TeeTlsAcceptor::new_with_ephemeral_cert(token_generator, "example.com"); // TODO example.com
  let mut tee_tls_stream = tee_tls_acceptor.accept(socket).await?;
  debug!("Proxying");
  proxy_service(&mut tee_tls_stream, session_id, target_host, target_port, state.clone()).await?;

  // Send a magic byte to the client, indicating readiness to read
  debug!("Sending magic byte to indicate readiness to read");
  tee_tls_stream.write_all(&[0xAA]).await?;

  debug!("Reading manifest");
  let manifest_bytes = read_wire_struct(&mut tee_tls_stream).await;
  // TODO: Consider implementing from_stream instead of read_wire_struct
  let manifest = Manifest::from_wire_bytes(&manifest_bytes);
  // dbg!(&manifest);

  debug!("Reading secret");
  let secret_bytes = read_wire_struct(&mut tee_tls_stream).await;
  let origo_secrets = OrigoSecrets::from_wire_bytes(&secret_bytes);
  // dbg!(&origo_secrets);

  let handshake_server_key =
    origo_secrets.handshake_server_key().expect("Handshake server key missing");
  let handshake_server_iv =
    origo_secrets.handshake_server_iv().expect("Handshake server IV missing");

  // TODO (autoparallel): This duplicates some code we see in `notary/src/origo.rs`, so we could
  //  maybe clean this up and share code.
  debug!("Parsing transcript");
  let transcript = state
    .origo_sessions
    .lock()
    .unwrap()
    .get(session_id)
    .cloned()
    .ok_or(NotaryServerError::SessionNotFound(session_id.to_string()))?;
  let parsed_transcript = transcript
    .into_flattened()
    .unwrap()
    .into_parsed(&handshake_server_key, &handshake_server_iv)
    .map_err(NotaryServerError::from)?;
  // dbg!(parsed_transcript);
  debug!("Parsing transcript done");
  // TODO apply manifest to parsed_transcript

  debug!("Sending TEE proof");
  // send TeeProof to client
  let tee_proof = TeeProof {
    data:      TeeProofData { manifest_hash: "todo".to_string() },
    signature: "sign(hash(TeeProofData))".to_string(),
  };
  let tee_proof_bytes = tee_proof.to_write_bytes();
  tee_tls_stream.write_all(&tee_proof_bytes).await?;

  debug!("Done");
  Ok(())
}

// TODO: Refactor into struct helpers/trait
async fn read_wire_struct<R: AsyncReadExt + Unpin>(stream: &mut R) -> Vec<u8> {
  // Buffer to store the "header" (4 bytes, indicating the length of the struct)
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf).await.unwrap();
  // dbg!(format!("len_buf={:?}", len_buf));

  // Deserialize the length prefix (convert from little-endian to usize)
  let body_len = u32::from_le_bytes(len_buf) as usize;
  // dbg!(format!("body_len={body_len}"));

  // Allocate a buffer to hold only the bytes needed for the struct
  let mut body_buf = vec![0u8; body_len];
  stream.read_exact(&mut body_buf).await.unwrap();
  // dbg!(format!("manifest_buf={:?}", manifest_buf));

  // Prepend len_buf to manifest_buf
  let mut wire_struct_buf = len_buf.to_vec();
  wire_struct_buf.extend(body_buf);

  wire_struct_buf
}
