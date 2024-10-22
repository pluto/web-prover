use std::collections::HashMap;

use base64::prelude::*;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use proofs::program::manifest::Manifest;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotaryMode {
  Origo,
  TLSN,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Witness {
  #[serde(with = "serde_bytes")]
  pub val: Vec<u8>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ProvingData {
  #[serde(with = "serde_bytes")]
  pub r1cs:          Vec<u8>,
  pub witnesses:     Vec<Witness>,
  #[serde(with = "serde_bytes")]
  pub serialized_pp: Vec<u8>,
  pub manifest:      Manifest,
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
  session_id: String,
}

impl Config {
  pub fn session_id(&mut self) -> String {
    if self.session_id.is_empty() {
      self.session_id = uuid::Uuid::new_v4().to_string();
    }
    self.session_id.clone()
  }

  pub fn target_host(&self) -> String {
    let target_url = Url::parse(&self.target_url).unwrap();
    target_url.host_str().unwrap().to_string()
  }

  pub fn target_port(&self) -> u16 {
    let target_url = Url::parse(&self.target_url).unwrap();
    target_url.port_or_known_default().unwrap()
  }

  pub fn target_is_https(&self) -> bool {
    let target_url = Url::parse(&self.target_url).unwrap();
    target_url.scheme() == "https"
  }

  pub fn to_request(&self) -> Request<Full<Bytes>> {
    let mut request =
      Request::builder().method(self.target_method.as_str()).uri(self.target_url.clone());

    let h = request.headers_mut().unwrap();

    for (key, value) in &self.target_headers {
      h.append(
        hyper::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
        value.parse().unwrap(),
      );
    }

    h.insert("Host", self.target_host().parse().unwrap());
    // Using "identity" instructs the Server not to use compression for its HTTP response.
    // TLSNotary tooling does not support compression.
    h.insert("Accept-Encoding", "identity".parse().unwrap());
    h.insert("Connection", "close".parse().unwrap());

    if h.get("Accept").is_none() {
      h.insert("Accept", "*/*".parse().unwrap());
    }

    let body = if self.target_body.is_empty() {
      Full::default()
    } else {
      let body = BASE64_STANDARD.decode(&self.target_body).unwrap();
      h.insert("Content-Length", body.len().into());
      Full::from(body)
    };

    request.body(body).unwrap()
  }
}
