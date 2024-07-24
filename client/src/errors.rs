use thiserror::Error;
#[cfg(not(target_arch = "wasm32"))]
use tokio_rustls::rustls;

#[derive(Debug, Error)]
pub enum ClientErrors {
  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  RustTls(#[from] rustls::Error),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),

  #[cfg(all(target_arch = "wasm32", feature = "websocket"))]
  #[error(transparent)]
  WebSocket(#[from] ws_stream_wasm::WsErr),

  #[cfg(target_arch = "wasm32")]
  #[error("{0}")]
  JsValueAsError(String),

  #[error(transparent)]
  Hyper(#[from] hyper::Error),

  #[error(transparent)]
  Http(#[from] hyper::http::Error),

  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  Join(#[from] tokio::task::JoinError),

  #[error(transparent)]
  Utf8(#[from] std::str::Utf8Error),

  #[error(transparent)]
  UrlParse(#[from] url::ParseError),

  #[error(transparent)]
  ProverConfigBuilder(#[from] tlsn_prover::tls::ProverConfigBuilderError),

  #[error(transparent)]
  Prover(#[from] tlsn_prover::tls::ProverError),

  #[error(transparent)]
  InvalidHeaderName(#[from] hyper::header::InvalidHeaderName),

  #[error(transparent)]
  InvalidHeaderValue(#[from] hyper::header::InvalidHeaderValue),

  #[error(transparent)]
  Base64Decode(#[from] base64::DecodeError),

  #[error(transparent)]
  HttpProver(#[from] tlsn_prover::http::HttpProverError),

  #[error(transparent)]
  SubstringsProofBuilder(#[from] tlsn_core::proof::SubstringsProofBuilderError),
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for ClientErrors {
  fn from(val: wasm_bindgen::JsValue) -> ClientErrors {
    ClientErrors::JsValueAsError(serde_wasm_bindgen::from_value::<String>(val).unwrap())
  }
}
