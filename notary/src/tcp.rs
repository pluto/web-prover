use std::future::Future;

use async_trait::async_trait;
use axum::{
  extract::FromRequestParts,
  http::{header, request::Parts, HeaderValue, StatusCode},
  response::Response,
};
use axum_core::body::Body;
use http::header::{HeaderMap, HeaderName};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use tracing::{error, info};

use crate::{axum_websocket::WebSocketUpgrade, errors::NotaryServerError};

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

/// Custom extractor used to extract underlying TCP connection for TCP client — using the same
/// upgrade primitives used by the WebSocket implementation where the underlying TCP connection
/// (wrapped in an Upgraded object) only gets polled as an OnUpgrade future after the ongoing HTTP request is finished (ref: https://github.com/tokio-rs/axum/blob/a6a849bb5b96a2f641fa077fe76f70ad4d20341c/axum/src/extract/ws.rs#L122)
///
/// More info on the upgrade primitives: https://docs.rs/hyper/latest/hyper/upgrade/index.html
pub struct TcpUpgrade {
  pub on_upgrade: OnUpgrade,
}

#[async_trait]
impl<S> FromRequestParts<S> for TcpUpgrade
where S: Send + Sync
{
  type Rejection = NotaryServerError;

  async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
    let on_upgrade = parts.extensions.remove::<OnUpgrade>().ok_or(
      NotaryServerError::BadProverRequest("Upgrade header is not set for TCP client".to_string()),
    )?;

    Ok(Self { on_upgrade })
  }
}

impl TcpUpgrade {
  /// Utility function to complete the http upgrade protocol by
  /// (1) Return 101 switching protocol response to client to indicate the switching to TCP
  /// (2) Spawn a new thread to await on the OnUpgrade object to claim the underlying TCP connection
  pub fn on_upgrade<C, Fut>(self, callback: C) -> Response
  where
    C: FnOnce(TokioIo<Upgraded>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static, {
    let on_upgrade = self.on_upgrade;
    tokio::spawn(async move {
      let upgraded = match on_upgrade.await {
        Ok(upgraded) => upgraded,
        Err(err) => {
          error!("Something wrong with upgrading HTTP: {:?}", err);
          return;
        },
      };
      let upgraded = TokioIo::new(upgraded);

      callback(upgraded).await;
    });

    #[allow(clippy::declare_interior_mutable_const)]
    const UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
    #[allow(clippy::declare_interior_mutable_const)]
    const TCP: HeaderValue = HeaderValue::from_static("tcp");

    let builder = Response::builder()
      .status(StatusCode::SWITCHING_PROTOCOLS)
      .header(header::CONNECTION, UPGRADE)
      .header(header::UPGRADE, TCP);

    builder.body(Body::empty()).unwrap()
  }
}

pub fn header_eq(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
  if let Some(header) = headers.get(&key) {
    header.as_bytes().eq_ignore_ascii_case(value.as_bytes())
  } else {
    false
  }
}
