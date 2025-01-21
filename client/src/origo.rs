// logic common to wasm32 and native
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::OrigoProof;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignBody {
  pub handshake_server_iv:  String,
  pub handshake_server_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyBody {
  pub session_id:  String,
  pub origo_proof: OrigoProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyReply {
  pub valid: bool,
  // TODO: need a signature
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

  #[allow(unused_variables)]
  let client: reqwest::Client = reqwest::ClientBuilder::new().build()?;

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

pub async fn verify(
  config: crate::config::Config,
  verify_body: VerifyBody,
) -> Result<VerifyReply, crate::errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/origo/verify",
    config.notary_host.clone(),
    config.notary_port.clone(),
  );

  #[allow(unused_variables)]
  let client = reqwest::ClientBuilder::new().build()?;

  #[cfg(feature = "notary_ca_cert")]
  let client = reqwest::ClientBuilder::new()
    .add_root_certificate(reqwest::tls::Certificate::from_der(
      &crate::tls::NOTARY_CA_CERT.to_vec(),
    )?)
    .use_rustls_tls()
    .build()?;

  let response = client.post(url).json(&verify_body).send().await?;
  assert!(response.status() == hyper::StatusCode::OK);
  let verify_response = response.json::<VerifyReply>().await?;

  debug!("\n{:?}\n\n", verify_response.clone());

  Ok(verify_response)
}
