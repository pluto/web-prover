// logic common to wasm32 and native
use serde::Serialize;
use serde_json::json;
use tls_client2::{origo::WitnessData, CipherSuite, ProtocolVersion};
use tls_core::msgs::{base::Payload, enums::ContentType, message::OpaqueMessage};
use tracing::debug;

use crate::errors;

#[derive(Serialize)]
pub struct SignBody {
  pub handshake_server_aes_iv:    String,
  pub handshake_server_aes_key:   String,
}

pub async fn sign(
  config: crate::config::Config,
  session_id: String,
  sb: SignBody,
) -> Result<Vec<u8>, crate::errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/origo/sign?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let client = reqwest::ClientBuilder::new().build()?;

  #[cfg(feature = "notary_ca_cert")]
  // TODO: recheck use of rustls backend
  let client = reqwest::ClientBuilder::new()
    .add_root_certificate(reqwest::tls::Certificate::from_der(
      &crate::tls::NOTARY_CA_CERT.to_vec(),
    )?)
    .use_rustls_tls()
    .build()?;

  let response = client.post(url).json(&sb).send().await?;
  assert!(response.status() == hyper::StatusCode::OK);

  // TODO: Actually use this input in the proofs.
  let sign_response = response.bytes().await?.to_vec();
  debug!("\n{}\n\n", String::from_utf8(sign_response.clone())?);

  Ok(sign_response)
}
