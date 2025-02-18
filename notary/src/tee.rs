use std::sync::{Arc, OnceLock};

use axum::{
  extract::{Query, State},
  response::Response,
};
#[cfg(feature = "tee-google-confidential-space-token-generator")]
use caratls_ekm_google_confidential_space_server::GoogleConfidentialSpaceTokenGenerator;
#[cfg(feature = "tee-dummy-token-generator")]
use caratls_ekm_server::DummyTokenGenerator;
use caratls_ekm_server::TeeTlsAcceptor;
use client::{
  origo::{OrigoSecrets, VerifyReply},
  TeeProof, TeeProofData,
};
use futures_util::SinkExt;
use hyper::{body::Bytes, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use proofs::program::{
  http::{ManifestRequest, ManifestResponse},
  manifest::Manifest,
};
use serde::Deserialize;
use tls_client2::tls_core::msgs::message::MessagePayload;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::{
  codec::{Framed, LengthDelimitedCodec},
  compat::FuturesAsyncReadCompatExt,
};
use tracing::{debug, error, info};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  errors::NotaryServerError,
  origo::{proxy_service, sign_verification},
  tls_parser::{Direction, ParsedMessage, WrappedPayload},
  tlsn::ProtocolUpgrade,
  SharedState,
};

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id:  Uuid,
  target_host: String,
  target_port: u16,
}

pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.to_string();

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

#[cfg(feature = "tee-dummy-token-generator")]
static TEE_TLS_ACCEPTOR_LOCK: OnceLock<TeeTlsAcceptor<DummyTokenGenerator>> = OnceLock::new();

#[cfg(feature = "tee-dummy-token-generator")]
fn tee_tls_acceptor() -> &'static TeeTlsAcceptor<DummyTokenGenerator> {
  TEE_TLS_ACCEPTOR_LOCK.get_or_init(|| {
    let token_generator = DummyTokenGenerator { token: "dummy".to_string() };
    TeeTlsAcceptor::new_with_ephemeral_cert(token_generator, "example.com") // TODO example.com
  })
}

#[cfg(feature = "tee-google-confidential-space-token-generator")]
static TEE_TLS_ACCEPTOR_LOCK: OnceLock<TeeTlsAcceptor<GoogleConfidentialSpaceTokenGenerator>> =
  OnceLock::new();

#[cfg(feature = "tee-google-confidential-space-token-generator")]
fn tee_tls_acceptor() -> &'static TeeTlsAcceptor<GoogleConfidentialSpaceTokenGenerator> {
  TEE_TLS_ACCEPTOR_LOCK.get_or_init(|| {
    let token_generator = GoogleConfidentialSpaceTokenGenerator::new("dummy".to_string());
    TeeTlsAcceptor::new_with_ephemeral_cert(token_generator, "example.com") // TODO example.com
  })
}

pub async fn tee_proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin>(
  socket: S,
  session_id: &str,
  target_host: &str,
  target_port: u16,
  state: Arc<SharedState>,
) -> Result<(), NotaryServerError> {
  let tee_tls_acceptor = tee_tls_acceptor();
  let mut tee_tls_stream = tee_tls_acceptor.accept(socket).await?;
  proxy_service(&mut tee_tls_stream, session_id, target_host, target_port, state.clone()).await?;

  use tokio::time::{timeout, Duration};
  let mut buf = [0u8; 1024];
  debug!("synchronizing socket");
  match timeout(Duration::from_millis(200), tee_tls_stream.read(&mut buf)).await {
    Ok(Ok(n)) => {
      debug!("read bytes: n={:?}, buf={:?}", n, hex::encode(buf));
    },
    Ok(Err(e)) => {
      panic!("unexpected error: {:?}", e);
    },
    Err(_elapsed) => {
      debug!("no bytes to read, proceeding");
    },
  }

  debug!("Sending magic byte to indicate readiness to read");
  tee_tls_stream.write_all(&[0xAA]).await?;

  let mut framed_stream = Framed::new(tee_tls_stream, LengthDelimitedCodec::new());

  let manifest_frame =
    framed_stream.next().await.ok_or_else(|| NotaryServerError::ManifestMissing)??;
  let manifest = Manifest::from_bytes(&manifest_frame)?;
  // dbg!(&manifest);

  let secret_frame =
    framed_stream.next().await.ok_or_else(|| NotaryServerError::MissingOrigoSecrets)??;
  let origo_secrets = OrigoSecrets::from_bytes(&secret_frame)?;
  // dbg!(&origo_secrets);

  let handshake_server_key =
    origo_secrets.handshake_server_key().expect("Handshake server key missing");
  let handshake_server_iv =
    origo_secrets.handshake_server_iv().expect("Handshake server IV missing");
  let app_server_key = origo_secrets.app_server_key().expect("Application server IV missing");
  let app_server_iv = origo_secrets.app_server_iv().expect("Application server key missing");
  let app_client_key = origo_secrets.app_client_key().expect("Application client IV missing");
  let app_client_iv = origo_secrets.app_client_iv().expect("Application client key missing");

  // TODO (autoparallel): This duplicates some code we see in `notary/src/origo.rs`, so we could
  //  maybe clean this up and share code.
  let transcript = state.origo_sessions.lock().unwrap().get(session_id).cloned().unwrap();
  let parsed_transcript = transcript
    .into_flattened()
    .unwrap()
    .into_parsed(
      &handshake_server_key,
      &handshake_server_iv,
      Some(app_server_key.to_vec()),
      Some(app_server_iv.to_vec()),
      Some(app_client_key.to_vec()),
      Some(app_client_iv.to_vec()),
    )
    .unwrap();
  // dbg!(parsed_transcript);

  let (request, response) = extract_request_and_response(&parsed_transcript.payload)?;

  // send TeeProof to client
  let tee_proof = create_tee_proof(&manifest, &request, &response, State(state))?;
  framed_stream.send(Bytes::from(tee_proof.to_bytes()?)).await?;
  framed_stream.flush().await?;

  Ok(())
}

pub fn extract_request_and_response(
  parsed_transcript: &[ParsedMessage],
) -> Result<(ManifestRequest, ManifestResponse), NotaryServerError> {
  let mut request_header = None;
  let mut request_body = None;
  let mut response_header = None;
  let mut response_body = None;

  // Classify parsed messages into headers and bodies
  for ParsedMessage { payload, direction, .. } in parsed_transcript {
    if let Some(app_data) = get_app_data(payload) {
      debug!("App data message {:?}: {:?}", direction, String::from_utf8_lossy(&app_data));
      match direction {
        Direction::Sent if request_header.is_none() => request_header = Some(app_data),
        Direction::Sent => request_body = Some(app_data),
        Direction::Received if response_header.is_none() => response_header = Some(app_data),
        Direction::Received => response_body = Some(app_data),
      }
    }
  }

  // Ensure mandatory headers are present
  let request_header =
    request_header.ok_or(NotaryServerError::MissingAppDataMessages(Direction::Sent, 2, 0))?;
  let response_header =
    response_header.ok_or(NotaryServerError::MissingAppDataMessages(Direction::Received, 2, 0))?;

  let request = ManifestRequest::from_payload(&request_header, request_body.as_deref())?;
  let response =
    ManifestResponse::from_payload(&response_header, response_body.as_deref().unwrap_or_default())?;

  Ok((request, response))
}

// TODO: Should TeeProof and other proofs be moved to `proofs` crate?
// Otherwise, adding TeeProof::manifest necessitates extra dependencies on the client
// Notice that all inputs to this function are from `proofs` crate
pub fn create_tee_proof(
  manifest: &Manifest,
  request: &ManifestRequest,
  response: &ManifestResponse,
  State(state): State<Arc<SharedState>>,
) -> Result<TeeProof, NotaryServerError> {
  validate_notarization_legal(manifest, request, response)?;

  let manifest_hash = manifest.to_keccak_digest()?;
  let data = TeeProofData { manifest_hash: manifest_hash.to_vec() };

  // TODO: That doesn't seem right
  let to_sign = VerifyReply {
    value:    format!("0x{}", hex::encode(manifest_hash)),
    manifest: manifest.clone(),
  };
  let origo_sig = sign_verification(to_sign, State(state)).unwrap();
  let as_bytes = hex::decode(&origo_sig.signature[2..]).unwrap();
  let signature = hex::encode(&as_bytes);
  Ok(TeeProof { data, signature })
}

/// Check if `manifest`, `request`, and `response` all fulfill requirements necessary for
/// a proof to be created
fn validate_notarization_legal(
  manifest: &Manifest,
  request: &ManifestRequest,
  response: &ManifestResponse,
) -> Result<(), NotaryServerError> {
  manifest.validate()?;
  if !manifest.request.is_subset_of(&request) {
    return Err(NotaryServerError::ManifestRequestMismatch);
  }
  if !manifest.response.is_subset_of(&response) {
    return Err(NotaryServerError::ManifestResponseMismatch);
  }
  Ok(())
}

fn get_app_data(payload: &WrappedPayload) -> Option<Vec<u8>> {
  match payload {
    WrappedPayload::Decrypted(decrypted) => match &decrypted.payload {
      MessagePayload::ApplicationData(app_data) => Some(app_data.clone().0),
      _ => None,
    },
    _ => None,
  }
}
