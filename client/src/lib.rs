extern crate core;

pub mod tlsn;
pub mod proxy;
pub mod config;
pub mod errors;

mod tls;
use std::collections::HashMap;

// use proofs::{
//   circuits::{construct_setup_data_from_fs, CIRCUIT_SIZE_512},
//   program::data::UninitializedSetup,
// };
use serde::{Deserialize, Serialize};
// use tlsn::{TlsnProof, TlsnVerifyBody};
// use tlsn_common::config::ProtocolConfig;
// pub use tlsn_core::attestation::Attestation;
// use tlsn_prover::ProverConfig;
use tracing::{debug, info};
use web_prover_core::{
  manifest::Manifest,
  proof::{SignedVerificationReply, TeeProof},
};

use crate::errors::ClientErrors;

#[derive(Debug, Serialize)]
pub enum Proof {
  TEE(TeeProof),
}

pub fn get_web_prover_circuits_version() -> String {
  env!("WEB_PROVER_CIRCUITS_VERSION").to_string()
}

pub async fn prover_inner_tee(mut config: config::Config) -> Result<Proof, ClientErrors> {
  let session_id = config.set_session_id();

  // TEE mode uses Origo networking stack with minimal changes
  let tee_proof = proxy::proxy(config, session_id).await?;

  Ok(Proof::TEE(tee_proof.unwrap()))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyConfig {
  pub target_method:  String,
  pub target_url:     String,
  pub target_headers: HashMap<String, String>,
  pub target_body:    String,
  pub manifest:       Manifest,
}

pub async fn prover_inner_proxy(config: config::Config) -> Result<Proof, ClientErrors> {
  let session_id = config.session_id.clone();

  let url = format!(
    "https://{}:{}/v1/proxy?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let proxy_config = ProxyConfig {
    target_method:  config.target_method,
    target_url:     config.target_url,
    target_headers: config.target_headers,
    target_body:    config.target_body,
    manifest:       config.proving.manifest.unwrap(),
  };

  // TODO reqwest uses browsers fetch API for WASM target? if true, can't add trust anchors
  #[cfg(target_arch = "wasm32")]
  let client = reqwest::ClientBuilder::new().build()?;

  #[cfg(not(target_arch = "wasm32"))]
  let client = {
    let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Some(cert) = config.notary_ca_cert {
      client_builder =
        client_builder.add_root_certificate(reqwest::tls::Certificate::from_der(&cert)?);
    }
    client_builder.build()?
  };

  let response = client.post(url).json(&proxy_config).send().await?;
  assert_eq!(response.status(), hyper::StatusCode::OK);
  let tee_proof = response.json::<TeeProof>().await?;
  Ok(Proof::TEE(tee_proof))
}

pub async fn verify<T: Serialize>(
  config: crate::config::Config,
  verify_body: T,
) -> Result<SignedVerificationReply, errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/{}/verify",
    config.notary_host.clone(),
    config.notary_port.clone(),
    "tee",
  );

  // TODO reqwest uses browsers fetch API for WASM target? if true, can't add trust anchors
  #[cfg(target_arch = "wasm32")]
  let client = reqwest::ClientBuilder::new().build()?;

  #[cfg(not(target_arch = "wasm32"))]
  let client = {
    let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Some(cert) = config.notary_ca_cert {
      client_builder =
        client_builder.add_root_certificate(reqwest::tls::Certificate::from_der(&cert)?);
    }
    client_builder.build()?
  };

  let response = client.post(url).json(&verify_body).send().await?;
  assert!(response.status() == hyper::StatusCode::OK, "response={:?}", response);
  let verify_response = response.json::<SignedVerificationReply>().await?;

  debug!("\n{:?}\n\n", verify_response.clone());

  Ok(verify_response)
}
