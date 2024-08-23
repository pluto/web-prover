use std::collections::HashMap;

use base64::prelude::*;
use hyper::Request;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotaryMode {
  Origo,
  TLSN,
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

  pub fn to_request(&self) -> Request<hyper::Body> {
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
      hyper::Body::empty()
    } else {
      hyper::Body::from(BASE64_STANDARD.decode(&self.target_body).unwrap())
    };

    request.body(body).unwrap()
  }
}
