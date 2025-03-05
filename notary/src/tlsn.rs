use std::{sync::Arc, time::Duration};

use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use client::tlsn::TlsnVerifyBody;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use p256::ecdsa::SigningKey;
use serde::Deserialize;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{
  attestation::AttestationConfig,
  presentation::PresentationOutput,
  signing::{SignatureAlgId, VerifyingKey},
  CryptoProvider,
};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info};
use uuid::Uuid;
use web_prover_core::proof::SignedVerificationReply;
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket, errors::NotaryServerError, tcp::ProtocolUpgrade,
  verifier::VerifyOutput, SharedState,
};
// TODO: use this place of our local file once this gets merged: https://github.com/tokio-rs/axum/issues/2848
// use axum::extract::ws::{WebSocket, WebSocketUpgrade};

pub async fn notary_service<
  S: futures_util::AsyncWrite + futures_util::AsyncRead + Send + Unpin + 'static,
>(
  socket: S,
  signing_key: &SigningKey,
  session_id: &str,
  max_sent_data: Option<usize>,
  max_recv_data: Option<usize>,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  let mut provider = CryptoProvider::default();
  provider.signer.set_secp256k1(&signing_key.to_bytes()).unwrap();

  // Setup the config. Normally a different ID would be generated
  // for each notarization.
  let config_validator = ProtocolConfigValidator::builder()
    .max_sent_data(max_sent_data.unwrap())
    .max_recv_data(max_recv_data.unwrap())
    .build()
    .unwrap();

  let config = VerifierConfig::builder()
    .protocol_config_validator(config_validator)
    .crypto_provider(provider)
    .build()
    .unwrap();

  let attestation_config = AttestationConfig::builder()
    .supported_signature_algs(vec![SignatureAlgId::SECP256K1])
    .build()
    .unwrap();

  Verifier::new(config).notarize(socket, &attestation_config).await.unwrap();
  Ok(())
}

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id: Uuid,
}

// TODO Response or impl IntoResponse?
pub async fn notarize(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.to_string();

  debug!("Starting notarize with ID: {}", session_id);

  let max_sent_data = Some(state.tlsn_max_sent_data);
  let max_recv_data = Some(state.tlsn_max_recv_data);
  let notary_signing_key = state.notary_signing_key.clone();

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(socket, notary_signing_key, session_id, max_sent_data, max_recv_data)
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, notary_signing_key, session_id, max_sent_data, max_recv_data)
    }),
  }
}

pub async fn websocket_notarize(
  socket: WebSocket,
  notary_signing_key: SigningKey,
  session_id: String,
  max_sent_data: Option<usize>,
  max_recv_data: Option<usize>,
) {
  debug!("Upgraded to websocket connection");
  let stream = WsStream::new(socket.into_inner());
  match notary_service(stream, &notary_signing_key, &session_id, max_sent_data, max_recv_data).await
  {
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
  notary_signing_key: SigningKey,
  session_id: String,
  max_sent_data: Option<usize>,
  max_recv_data: Option<usize>,
) {
  debug!("Upgraded to tcp connection");
  match notary_service(
    stream.compat(),
    &notary_signing_key,
    &session_id,
    max_sent_data,
    max_recv_data,
  )
  .await
  {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

pub async fn verify(
  State(state): State<Arc<SharedState>>,
  extract::Json(verify_body): extract::Json<TlsnVerifyBody>,
) -> Result<Json<SignedVerificationReply>, NotaryServerError> {
  let provider = CryptoProvider::default();

  let VerifyingKey { alg, data: key_data } = verify_body.proof.verifying_key();

  println!("Verifying presentation with {alg} key: {}", hex::encode(key_data));

  // Verify the presentation.
  let PresentationOutput { server_name, connection_info, transcript, .. } =
    verify_body.proof.verify(&provider).unwrap();

  // TODO: how should notary sign these fields? Should these be combined with a domain separator?
  // The time at which the connection was started.
  let _time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
  let _server_name = server_name.unwrap();

  // Set the unauthenticated bytes so they are distinguishable.
  let mut partial_transcript = transcript.unwrap();
  partial_transcript.set_unauthed(b'X');

  crate::verifier::sign_verification(
    VerifyOutput { manifest: verify_body.manifest, value: partial_transcript.received_unsafe() },
    State(state),
  )
  .map(Json)
}
