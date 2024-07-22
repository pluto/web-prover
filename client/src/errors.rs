use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientErrors {
  // #[cfg(not(target_arch = "wasm32"))]
  // #[error(transparent)]
  // RustTlsError(#[from] rustls::Error),

  #[error(transparent)]
  IoError(#[from] std::io::Error),

  // #[error(transparent)]
  // SerdeJsonError(#[from] serde_json::Error),

  // #[cfg(all(target_arch = "wasm32", feature = "websocket"))]
  // #[error(transparent)]
  // WebSocketError(#[from] ws_stream_wasm::WsErr),

  #[error(transparent)]
  HyperError(#[from] hyper::Error),

  #[error(transparent)]
  HttpError(#[from] hyper::http::Error),

  // #[cfg(not(target_arch = "wasm32"))]
  // #[error(transparent)]
  // JoinError(#[from] tokio::task::JoinError),

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
