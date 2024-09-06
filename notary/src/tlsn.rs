use std::{error::Error, sync::Arc};

use async_trait::async_trait;
use axum::{
  extract::{FromRequestParts, Query, State},
  http::{header, request::Parts, StatusCode},
  response::{IntoResponse, Response},
};
use eyre::Report;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use p256::ecdsa::{Signature, SigningKey};
use serde::Deserialize;
use tlsn_verifier::tls::{Verifier, VerifierConfig, VerifierConfigBuilderError, VerifierError};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::{WebSocket, WebSocketUpgrade},
  tcp::{header_eq, TcpUpgrade},
  SharedState,
};
// TODO: use this place of our local file once this gets merged: https://github.com/tokio-rs/axum/issues/2848
// use axum::extract::ws::{WebSocket, WebSocketUpgrade};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket or TCP clients,
/// so that we can use a single endpoint and handler for notarization for both types of clients
pub enum ProtocolUpgrade {
  Tcp(TcpUpgrade),
  Ws(WebSocketUpgrade),
}

#[async_trait]
impl<S> FromRequestParts<S> for ProtocolUpgrade
where S: Send + Sync
{
  type Rejection = NotaryServerError;

  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
    info!("from_request_parts");
    // Extract tcp connection for websocket client
    if header_eq(&parts.headers, header::UPGRADE, "websocket") {
      let extractor = WebSocketUpgrade::from_request_parts(parts, state)
        .await
        .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
      return Ok(Self::Ws(extractor));
    // Extract tcp connection for tcp client
    } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
      let extractor = TcpUpgrade::from_request_parts(parts, state)
        .await
        .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
      return Ok(Self::Tcp(extractor));
    } else {
      return Err(NotaryServerError::BadProverRequest(
        "Upgrade header is not set for client".to_string(),
      ));
    }
  }
}

pub async fn notary_service<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
  socket: S,
  signing_key: &SigningKey,
  session_id: &str,
  max_sent_data: Option<usize>,
  max_recv_data: Option<usize>,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  let mut config_builder = VerifierConfig::builder();

  config_builder = config_builder
    .id(session_id)
    .max_transcript_size(max_sent_data.unwrap() + max_recv_data.unwrap()); // TODO unwrap, probably shouldn't be Option in the first place

  let config = config_builder.build()?;

  Verifier::new(config).notarize::<_, Signature>(socket.compat(), signing_key).await?;

  Ok(())
}

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id: String,
}

// TODO Response or impl IntoResponse?
pub async fn notarize(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

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
  let stream = WsStream::new(socket.into_inner()).compat();
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
  match notary_service(stream, &notary_signing_key, &session_id, max_sent_data, max_recv_data).await
  {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
  #[error(transparent)]
  Unexpected(#[from] Report),
  #[error("Failed to connect to prover: {0}")]
  Connection(String),
  #[error("Error occurred during notarization: {0}")]
  Notarization(Box<dyn Error + Send + 'static>),
  #[error("Invalid request from prover: {0}")]
  BadProverRequest(String),
  #[error("Unauthorized request from prover: {0}")]
  UnauthorizedProverRequest(String),
}

impl From<VerifierError> for NotaryServerError {
  fn from(error: VerifierError) -> Self { Self::Notarization(Box::new(error)) }
}

impl From<VerifierConfigBuilderError> for NotaryServerError {
  fn from(error: VerifierConfigBuilderError) -> Self { Self::Notarization(Box::new(error)) }
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
  fn into_response(self) -> Response {
    match self {
      bad_request_error @ NotaryServerError::BadProverRequest(_) =>
        (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response(),
      unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) =>
        (StatusCode::UNAUTHORIZED, unauthorized_request_error.to_string()).into_response(),
      _ => (StatusCode::INTERNAL_SERVER_ERROR, "Something wrong happened.").into_response(),
    }
  }
}
