// use std::io::{BufReader, Cursor};

use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::{body::Bytes, Request, StatusCode};
// use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
#[cfg(target_arch = "wasm32")]
use {
  wasm_bindgen_futures::spawn_local, wasm_utils::WasmAsyncIo as AsyncIo, ws_stream_wasm::WsMeta,
};
#[cfg(target_arch = "wasm32")]
type NetworkStream = ws_stream_wasm::WsStream;
#[cfg(not(target_arch = "wasm32"))]
use {
  hyper::client::conn::http1::Parts,
  hyper_util::rt::TokioIo as AsyncIo,
  std::sync::Arc,
  tokio::net::TcpStream,
  tokio::spawn,
  tokio_rustls::{client::TlsStream, TlsConnector},
};
#[cfg(not(target_arch = "wasm32"))]
type NetworkStream = TlsStream<TcpStream>;

use super::*;

// TODO: The `ClientType` and  `NotarizationSessionRequest` and `NotarizationSessionResponse` is
// redundant with what we had in `request` for the wasm version which was deprecated. May have to be
// careful with the camelCase used here.

/// Requests notarization from the Notary server.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip_all))]
pub async fn request_notarization(
  notary_host: &str,
  notary_port: u16,
  config_notarization_session_request: &ConfigNotarizationSessionRequest,
) -> Result<(NetworkStream, String), ClientErrors> {
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Configure TLS Notary session and get session id
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // TODO the following applies to WASM only, make it work with non wasm as well

  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "configure_tls_notary_session").entered();
  let mut opts = web_sys::RequestInit::new();
  opts.method("POST");
  opts.mode(web_sys::RequestMode::Cors);

  let headers = web_sys::Headers::new().unwrap(); // TODO fix unwrap
  headers.append("Host", notary_host).unwrap(); // TODO fix unwrap
  headers.append("Content-Type", "application/json").unwrap(); // TODO fix unwrap
  opts.headers(&headers);

  let notarization_session_request = NotarizationSessionRequest {
    client_type:   config_notarization_session_request.client_type,
    max_sent_data: config_notarization_session_request.max_sent_data,
    max_recv_data: config_notarization_session_request.max_recv_data,
  };

  let payload = serde_json::to_string(&notarization_session_request).unwrap(); // TODO fix unwrap
  opts.body(Some(&wasm_bindgen::JsValue::from_str(&payload)));

  let url = format!("https://{}:{}/session", notary_host, notary_port);

  let raw_notarization_session_response =
    wasm_utils::fetch_as_json_string(&url, &opts).await.unwrap(); // TODO fix unwrap
  let notarization_response =
    serde_json::from_str::<NotarizationSessionResponse>(&raw_notarization_session_response)
      .unwrap(); // TODO fix unwrap
  #[cfg(feature = "tracing")]
  info!("Session configured, session_id: {}", notarization_response.session_id);
  #[cfg(feature = "tracing")]
  drop(_span);

  // TODO: Be careful to put this in with the right target arch
  #[cfg(feature = "tracing")]
  debug!("TLS socket created with TCP connection");
  let (_, notary_tls_socket) = WsMeta::connect(
    format!(
      "wss://{}:{}/notarize?sessionId={}",
      notary_host, notary_port, notarization_response.session_id
    ),
    None,
  )
  .await?;
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // Claim back the TLS socket after HTTP exchange is done
  // #[cfg(not(target_arch = "wasm32"))]
  // let Parts { io: notary_tls_socket, .. } = connection_task.await??;
  #[cfg(not(target_arch = "wasm32"))]
  return Ok((notary_tls_socket.into_inner(), notarization_response.session_id.to_string()));
  #[cfg(target_arch = "wasm32")]
  return Ok((notary_tls_socket, notarization_response.session_id.to_string()));
}
