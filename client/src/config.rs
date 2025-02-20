use std::collections::HashMap;

use base64::prelude::*;
use http_body_util::Full;
use hyper::{
  body::Bytes,
  header::{HeaderName, HeaderValue},
  Request,
};
use serde::{Deserialize, Serialize};
use serde_with::{
  base64::{Base64, Standard},
  formats::Padded,
  serde_as,
};
use url::Url;
use web_prover_core::manifest::Manifest;

use crate::errors::ClientErrors;

/// Notary can run in multiple modes depending on the use case, each with its own trust assumptions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotaryMode {
  /// Origo proxy mode
  Origo,
  /// TLS notary MPC-TLS mode
  TLSN,
  // TEE proxy mode
  TEE,
  // Plain Proxy mode
  Proxy,
}

/// Proving data containing [`Manifest`] and serialized witnesses used for WASM
#[derive(Deserialize, Clone, Debug)]
pub struct ProvingData {
  pub manifest: Option<Manifest>, // TODO: Why is it optional?
}

#[serde_as]
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub mode:                NotaryMode,
  pub notary_host:         String,
  pub notary_port:         u16,
  // optionally pass notary's ca cert to be trusted,
  // this is helpful for local debugging with self-signed certs
  #[serde_as(as = "Option<Base64<Standard, Padded>>")]
  pub notary_ca_cert:      Option<Vec<u8>>,
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
  /// Sets the session ID for the configuration.
  ///
  /// If the `session_id` field is empty, this function generates a new UUID and assigns it to the
  /// `session_id` field. It then returns the session ID.
  ///
  /// # Returns
  /// - `String`: The session ID, either newly generated or existing.
  pub fn set_session_id(&mut self) -> String {
    if self.session_id.is_empty() {
      self.session_id = uuid::Uuid::new_v4().to_string();
    }
    self.session_id.clone()
  }

  /// Extracts the host from the target URL.
  ///
  /// Parses the `target_url` field of the `Config` struct and extracts the host component.
  ///
  /// # Returns
  /// - `Ok(String)`: The host as a string if it is found in the target URL.
  /// - `Err(ClientErrors)`: An error if the URL is invalid or the host is not found.
  ///
  /// # Errors
  /// - Returns `ClientErrors::Other` if the host is not found in the target URL.
  pub fn target_host(&self) -> Result<String, ClientErrors> {
    let target_url = Url::parse(&self.target_url)?;
    let host = target_url
      .host_str()
      .ok_or_else(|| ClientErrors::Other("Host not found in target URL".to_owned()))?
      .to_string();
    Ok(host)
  }

  /// Extracts the port from the target URL.
  ///
  /// Parses the `target_url` field of the `Config` struct and extracts the port component.
  /// If the port is not explicitly specified in the URL, it returns the default port for the scheme
  /// (e.g., 80 for HTTP, 443 for HTTPS).
  ///
  /// # Returns
  /// - `Ok(u16)`: The port as a u16 if it is found or known for the target URL.
  /// - `Err(ClientErrors)`: An error if the URL is invalid or the port is not found.
  ///
  /// # Errors
  /// - Returns `ClientErrors::Other` if the port is not found in the target URL.
  pub fn target_port(&self) -> Result<u16, ClientErrors> {
    let target_url = Url::parse(&self.target_url)?;
    let port = target_url
      .port_or_known_default()
      .ok_or_else(|| ClientErrors::Other("Port not found in target URL".to_owned()))?;
    Ok(port)
  }

  /// Checks if the target URL uses HTTPS.
  ///
  /// Parses the `target_url` field of the `Config` struct and checks if the scheme is HTTPS.
  ///
  /// # Returns
  /// - `Ok(bool)`: `true` if the scheme is HTTPS, `false` otherwise.
  /// - `Err(ClientErrors)`: An error if the URL is invalid.
  ///
  /// # Errors
  /// - Returns `ClientErrors::Other` if the URL is invalid.
  pub fn target_is_https(&self) -> Result<bool, ClientErrors> {
    let target_url = Url::parse(&self.target_url)?;
    Ok(target_url.scheme() == "https")
  }

  /// Converts the configuration into an HTTP request.
  ///
  /// This function constructs an HTTP request using the method, URL, headers, and body
  /// specified in the configuration. It ensures that necessary headers like "Host",
  /// "Accept-Encoding", "Connection", and "Accept" are set appropriately.
  ///
  /// # Returns
  /// - `Ok(Request<Full<Bytes>>)` if the request is successfully constructed.
  /// - `Err(ClientErrors)` if there is an error in constructing the request, such as invalid
  ///   headers or body encoding issues.
  ///
  /// # Errors
  /// - Returns `ClientErrors::Other` if headers cannot be retrieved or set.
  /// - Returns `ClientErrors::Other` if the host cannot be parsed.
  /// - Returns `ClientErrors::Other` if the body cannot be decoded from base64.
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
