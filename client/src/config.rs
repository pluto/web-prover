use std::collections::HashMap;

use base64::prelude::*;
use http_body_util::Full;
use hyper::{
  body::Bytes,
  header::{HeaderName, HeaderValue},
  Request,
};
use proofs::program::manifest::Manifest;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::errors::ClientErrors;

/// Notary can run in multiple modes depending on the use case, each with its own trust assumptions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotaryMode {
  /// Origo proxy mode
  Origo,
  /// TLS notary MPC-TLS mode
  TLSN,
}

/// Proving data containing [`Manifest`] and serialized witnesses used for WASM
#[derive(Deserialize, Clone, Debug)]
pub struct ProvingData {
  pub witnesses: Option<Vec<Vec<u8>>>,
  pub manifest:  Option<Manifest>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub mode:                NotaryMode,
  pub notary_host:         String,
  pub notary_port:         u16,
  pub target_method:       String,
  pub target_url:          String,
  pub target_headers:      HashMap<String, String>,
  pub target_body:         String,
  pub websocket_proxy_url: Option<String>, // if set, use websocket proxy

  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,

  pub proving: ProvingData,

  #[serde(skip)]
  pub session_id: String,
}

impl Config {
  pub fn session_id(&mut self) -> String {
    if self.session_id.is_empty() {
      self.session_id = uuid::Uuid::new_v4().to_string();
    }
    self.session_id.clone()
  }

  pub fn target_host(&self) -> Result<String, ClientErrors> {
    let target_url = Url::parse(&self.target_url)?;
    let host = target_url
      .host_str()
      .ok_or_else(|| ClientErrors::Other("Host not found in target URL".to_owned()))?
      .to_string();
    Ok(host)
  }

  pub fn target_port(&self) -> Result<u16, ClientErrors> {
    let target_url = Url::parse(&self.target_url)?;
    let port = target_url
      .port_or_known_default()
      .ok_or_else(|| ClientErrors::Other("Port not found in target URL".to_owned()))?;
    Ok(port)
  }

  pub fn target_is_https(&self) -> Result<bool, ClientErrors> {
    let target_url = Url::parse(&self.target_url)?;
    Ok(target_url.scheme() == "https")
  }

  pub fn to_request(&self) -> Result<Request<Full<Bytes>>, ClientErrors> {
    let mut request =
      Request::builder().method(self.target_method.as_str()).uri(self.target_url.clone());

    let h = request
      .headers_mut()
      .ok_or_else(|| ClientErrors::Other("Failed to get headers".to_string()))?;

    for (key, value) in &self.target_headers {
      let header_name = HeaderName::from_bytes(key.as_bytes())?;
      let header_value = value.parse()?;
      h.append(header_name, header_value);
    }

    let host = self.target_host()?.parse()?;
    h.insert("Host", host);
    h.insert("Accept-Encoding", "identity".parse()?);
    h.insert("Connection", "close".parse()?);

    if h.get("Accept").is_none() {
      h.insert("Accept", "*/*".parse()?);
    }

    let body = if self.target_body.is_empty() {
      Full::default()
    } else {
      let body = BASE64_STANDARD.decode(&self.target_body)?;
      h.insert("Content-Length", HeaderValue::from(body.len()));
      Full::from(body)
    };

    Ok(request.body(body)?)
  }
}
