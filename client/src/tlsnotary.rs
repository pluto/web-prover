use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

#[cfg(not(target_arch = "wasm32"))]
use {
  tokio::net::TcpStream,
  tokio_rustls::client::TlsStream,
};

use super::*;

use std::io::{BufReader, Cursor};
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::{body::Bytes, Request, StatusCode};
#[cfg(target_arch = "wasm32")]
use {
  wasm_bindgen_futures::spawn_local, ws_stream_wasm::WsMeta, super::wasm_utils
};

#[cfg(not(target_arch = "wasm32"))]
use {
  hyper::client::conn::http1::Parts,
  std::sync::Arc,
  tokio::net::TcpStream,
  tokio::spawn,
  tokio_rustls::{client::TlsStream, TlsConnector},
};

// TODO can we import and use struct from https://sourcegraph.com/github.com/tlsnotary/tlsn/-/blob/notary/server/src/domain/notary.rs ?
/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")] // required
struct NotarizationSessionRequestAPI {
  pub client_type:   ClientType,
  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,
}

// TODO can we import and use struct from https://sourcegraph.com/github.com/tlsnotary/tlsn/-/blob/notary/server/src/domain/notary.rs ?
/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotarizationSessionResponse {
  /// Unique session id that is generated by notary and shared to prover
  pub session_id: String,
}

#[cfg(target_arch = "wasm32")]
type NetworkStream = ws_stream_wasm::WsStream;

#[cfg(not(target_arch = "wasm32"))]
type NetworkStream = TlsStream<TcpStream>;

// TODO will have to adapt request_notarization for other target as well
#[cfg(target_arch = "wasm32")]
pub async fn request_notarization(
  notary_host: &str,
  notary_port: u16,
  config_notarization_session_request: &NotarizationSessionRequest,
) -> Result<(NetworkStream, String), errors::ClientErrors> {


  let _span = tracing::span!(tracing::Level::TRACE, "configure_tls_notary_session").entered();
  let mut opts = web_sys::RequestInit::new();
  opts.method("POST");
  opts.mode(web_sys::RequestMode::Cors);

  let headers = web_sys::Headers::new().unwrap(); // TODO fix unwrap
  headers.append("Host", notary_host).unwrap(); // TODO fix unwrap
  headers.append("Content-Type", "application/json").unwrap(); // TODO fix unwrap
  opts.headers(&headers);

  let notarization_session_request = NotarizationSessionRequestAPI {
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

  info!("Session configured, session_id: {}", notarization_response.session_id);

  drop(_span);

  // TODO: Be careful to put this in with the right target arch

  debug!("TLS socket created with TCP connection");
  let (_, notary_tls_socket) = WsMeta::connect(
    format!(
      "wss://{}:{}/notarize?sessionId={}",
      notary_host, notary_port, notarization_response.session_id
    ),
    None,
  )
  .await.unwrap();

  // TODO
  // Claim back the TLS socket after HTTP exchange is done
  // #[cfg(not(target_arch = "wasm32"))]
  // let Parts { io: notary_tls_socket, .. } = connection_task.await??;
  #[cfg(not(target_arch = "wasm32"))]
  return Ok((notary_tls_socket.into_inner(), notarization_response.session_id.to_string()));
  #[cfg(target_arch = "wasm32")]
  return Ok((notary_tls_socket, notarization_response.session_id.to_string()));
}
