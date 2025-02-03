use std::array::TryFromSliceError;

use thiserror::Error;
impl From<TryFromSliceError> for ClientErrors {
  fn from(err: TryFromSliceError) -> ClientErrors { ClientErrors::Other(err.to_string()) }
}

#[derive(Debug, Error)]
pub enum ClientErrors {
  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  RustTls(#[from] rustls::Error),

  #[error(transparent)]
  SpansyError(#[from] spansy::ParseError),

  #[error(transparent)]
  HttpCommitError(#[from] tlsn_formats::http::HttpCommitError),

  #[error(transparent)]
  TranscriptCommitConfigBuilderError(
    #[from] tlsn_core::transcript::TranscriptCommitConfigBuilderError,
  ),

  #[error(transparent)]
  ProtocolConfigBuilder(#[from] tlsn_common::config::ProtocolConfigBuilderError),

  #[error(transparent)]
  FromUtf8(#[from] std::string::FromUtf8Error),

  #[error(transparent)]
  Reqwest(#[from] reqwest::Error),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  TeeTlsConnectorError(#[from] caratls_ekm_client::TeeTlsConnectorError),

  #[error("TLS error: {0}")]
  TlsCrypto(String),

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
  ProverError(#[from] tlsn_prover::ProverError),

  #[error(transparent)]
  ProverConfigBuilder(#[from] tlsn_prover::ProverConfigBuilderError),

  #[error(transparent)]
  TranscriptProofBuilderError(#[from] tlsn_core::transcript::TranscriptProofBuilderError),

  #[error(transparent)]
  PresentationBuilderError(#[from] tlsn_core::presentation::PresentationBuilderError),
  #[error(transparent)]
  InvalidHeaderName(#[from] hyper::header::InvalidHeaderName),

  #[error(transparent)]
  InvalidHeaderValue(#[from] hyper::header::InvalidHeaderValue),

  #[error(transparent)]
  Base64Decode(#[from] base64::DecodeError),

  #[error(transparent)]
  ProofError(#[from] proofs::errors::ProofError),

  #[error(transparent)]
  HexDecode(#[from] hex::FromHexError),

  #[error(transparent)]
  BackendError(#[from] tls_client2::BackendError),

  #[error(transparent)]
  VendoredInvalidDnsNameError(#[from] tls_core::dns::InvalidDnsNameError),

  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  InvalidDnsNameError(#[from] rustls::pki_types::InvalidDnsNameError),

  #[error(transparent)]
  Error(#[from] tls_client2::Error),

  #[error("Other error: {0}")]
  Other(String),

  #[error(transparent)]
  Canceled(#[from] futures::channel::oneshot::Canceled),

  #[error("Missing setup data")]
  MissingSetupData,

  #[error("Manifest missing")]
  ManifestMissingError,

  #[error(transparent)]
  WitnessGeneratorError(#[from] web_proof_circuits_witness_generator::WitnessGeneratorError),

  #[error("TEE proof missing")]
  TeeProofMissing,
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for ClientErrors {
  fn from(val: wasm_bindgen::JsValue) -> ClientErrors {
    ClientErrors::JsValueAsError(serde_wasm_bindgen::from_value::<String>(val).unwrap())
  }
}
