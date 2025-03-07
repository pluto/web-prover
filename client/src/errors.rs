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
  FromUtf8(#[from] std::string::FromUtf8Error),

  #[error(transparent)]
  Reqwest(#[from] reqwest::Error),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),

  #[error(transparent)]
  Hyper(#[from] hyper::Error),

  #[error(transparent)]
  Http(#[from] hyper::http::Error),

  #[error(transparent)]
  Join(#[from] tokio::task::JoinError),

  #[error(transparent)]
  Utf8(#[from] std::str::Utf8Error),

  #[error(transparent)]
  UrlParse(#[from] url::ParseError),

  #[error(transparent)]
  InvalidHeaderName(#[from] hyper::header::InvalidHeaderName),

  #[error(transparent)]
  InvalidHeaderValue(#[from] hyper::header::InvalidHeaderValue),

  #[error(transparent)]
  Base64Decode(#[from] base64::DecodeError),

  #[error(transparent)]
  HexDecode(#[from] hex::FromHexError),

  #[error(transparent)]
  InvalidDnsNameError(#[from] rustls::pki_types::InvalidDnsNameError),

  #[error(transparent)]
  Canceled(#[from] futures::channel::oneshot::Canceled),

  #[error("Manifest missing")]
  ManifestMissingError,

  #[error("Other error: {0}")]
  Other(String),

  #[error("TEE proof missing")]
  TeeProofMissing,
}
