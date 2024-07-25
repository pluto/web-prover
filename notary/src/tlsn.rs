use async_trait::async_trait;
use axum::{
  extract::FromRequestParts,
  http::{header, request::Parts},
  response::Response,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use notary_server::NotaryServerError;
use p256::ecdsa::{Signature, SigningKey};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, error, info};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::{WebSocket, WebSocketUpgrade},
  tcp::{header_eq, load_notary_signing_key, TcpUpgrade},
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

  config_builder = config_builder.id(session_id);

  if let Some(max_sent_data) = max_sent_data {
    config_builder = config_builder.max_sent_data(max_sent_data);
  }

  if let Some(max_recv_data) = max_recv_data {
    config_builder = config_builder.max_recv_data(max_recv_data);
  }

  let config = config_builder.build()?;

  Verifier::new(config).notarize::<_, Signature>(socket.compat(), signing_key).await?;

  Ok(())
}

// TODO Response or impl IntoResponse?
pub async fn notarize(protocol_upgrade: ProtocolUpgrade) -> Response {
  // We manually just create a UUID4 for the remaining calls here
  // TODO Should we just hardcode one UUID4 and pass in the same for all calls?
  let session_id = Uuid::new_v4().to_string();

  let max_sent_data = Some(10000); // TODO matches client_wasm/demo/js/index.js proof config
  let max_recv_data = Some(10000); // TODO matches client_wasm/demo/js/index.js proof config

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      let notary_signing_key = load_notary_signing_key("./fixture/certs/notary.key"); // TODO don't do this for every request, pass in as axum state?
      websocket_notarize(socket, notary_signing_key, session_id, max_sent_data, max_recv_data)
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      let notary_signing_key = load_notary_signing_key("./fixture/certs/notary.key"); // TODO don't do this for every request, pass in as axum state?
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
  debug!(?session_id, "Upgraded to tcp connection");
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
