use std::collections::HashMap;
use serde::Deserialize;
use serde_with::{
  base64::{Base64, Standard},
  formats::Padded,
  serde_as,
};
use url::Url;
use web_prover_core::manifest::Manifest;

use crate::errors::ClientErrors;

/// Proving data containing [`Manifest`] and serialized witnesses used for WASM
#[derive(Deserialize, Clone, Debug)]
pub struct ProvingData {
  pub manifest: Option<Manifest>, // TODO(#515)
}

#[serde_as]
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
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
}
