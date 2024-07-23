use thiserror::Error;
#[cfg(not(target_arch = "wasm32"))]
use tokio_rustls::rustls;

#[derive(Debug, Error)]
pub enum ClientErrors {
  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  RustTlsError(#[from] rustls::Error),

  #[error(transparent)]
  IoError(#[from] std::io::Error),

  #[error(transparent)]
  SerdeJsonError(#[from] serde_json::Error),

  #[cfg(all(target_arch = "wasm32", feature = "websocket"))]
  #[error(transparent)]
  WebSocketError(#[from] ws_stream_wasm::WsErr),

  #[cfg(target_arch = "wasm32")]
  #[error("{0}")]
  JsValueAsError(String),

  #[error(transparent)]
  HyperError(#[from] hyper::Error),

  #[error(transparent)]
  HttpError(#[from] hyper::http::Error),

  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  JoinError(#[from] tokio::task::JoinError),

  #[error(transparent)]
  Utf8Error(#[from] std::str::Utf8Error),

  #[error(transparent)]
  UrlParseError(#[from] url::ParseError),

  #[error(transparent)]
  ProverConfigBuilderError(#[from] tlsn_prover::tls::ProverConfigBuilderError),

  #[error(transparent)]
  ProverError(#[from] tlsn_prover::tls::ProverError),

  #[error(transparent)]
  InvalidHeaderNameError(#[from] hyper::header::InvalidHeaderName),

  #[error(transparent)]
  InvalidHeaderValueError(#[from] hyper::header::InvalidHeaderValue),

  #[error(transparent)]
  Base64DecodeError(#[from] base64::DecodeError),

  #[error(transparent)]
  HttpProverError(#[from] tlsn_prover::http::HttpProverError),

  #[error(transparent)]
  SubstringsProofBuilderError(#[from] tlsn_core::proof::SubstringsProofBuilderError),
}

impl From<wasm_bindgen::JsValue> for ClientErrors {
  fn from(val: wasm_bindgen::JsValue) -> ClientErrors {
    ClientErrors::JsValueAsError(serde_wasm_bindgen::from_value::<String>(val).unwrap())
  }
}
