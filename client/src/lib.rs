extern crate core;

pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

pub mod config;
pub mod errors;
mod proof;
mod tls;

pub mod tls_client_async2;
use std::collections::HashMap;

use origo::OrigoProof;
use proofs::{
  circuits::{construct_setup_data_from_fs, CIRCUIT_SIZE_512},
  program::data::UninitializedSetup,
};
use serde::{Deserialize, Serialize};
use tlsn::{TlsnProof, TlsnVerifyBody};
use tlsn_common::config::ProtocolConfig;
pub use tlsn_core::attestation::Attestation;
use tlsn_prover::ProverConfig;
use tracing::{debug, info};
use web_prover_core::{
  manifest::Manifest,
  proof::{SignedVerificationReply, TeeProof},
};

use crate::errors::ClientErrors;

#[derive(Debug, Serialize)]
pub enum Proof {
  Tlsn(TlsnProof),
  Origo(OrigoProof),
  TEE(TeeProof),
  Proxy(TeeProof),
}

pub fn get_web_prover_circuits_version() -> String {
  env!("WEB_PROVER_CIRCUITS_VERSION").to_string()
}

pub async fn prover_inner(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
  setup_data: Option<UninitializedSetup>,
) -> Result<Proof, ClientErrors> {
  info!("GIT_HASH: {}", env!("GIT_HASH"));
  match config.mode {
    config::NotaryMode::TLSN => prover_inner_tlsn(config).await,
    config::NotaryMode::Origo => prover_inner_origo(config, proving_params, setup_data).await,
    config::NotaryMode::TEE => prover_inner_tee(config).await,
    config::NotaryMode::Proxy => prover_inner_proxy(config).await,
  }
}

pub async fn prover_inner_tlsn(mut config: config::Config) -> Result<Proof, ClientErrors> {
  let max_sent_data = config
    .max_sent_data
    .ok_or_else(|| ClientErrors::Other("max_sent_data is missing".to_string()))?;
  let max_recv_data = config
    .max_recv_data
    .ok_or_else(|| ClientErrors::Other("max_recv_data is missing".to_string()))?;

  let prover_config = ProverConfig::builder()
    .server_name(config.target_host()?.as_str())
    .protocol_config(
      ProtocolConfig::builder()
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data)
        .build()?,
    )
    .build()?;

  #[cfg(target_arch = "wasm32")]
  let prover = tlsn_wasm32::setup_connection(&mut config, prover_config).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let prover = if config.websocket_proxy_url.is_some() {
    tlsn_native::setup_websocket_connection(&mut config, prover_config).await
  } else {
    tlsn_native::setup_tcp_connection(&mut config, prover_config).await
  };

  let manifest = match config.proving.manifest.clone() {
    Some(m) => m,
    None => return Err(errors::ClientErrors::ManifestMissingError),
  };

  let p = tlsn::notarize(prover, &manifest).await?;

  let verify_response = verify(config, TlsnVerifyBody { manifest, proof: p.clone() }).await?;

  debug!("proof.verify_reply: {:?}", verify_response);

  Ok(Proof::Tlsn(TlsnProof { proof: p, sign_reply: Some(verify_response) }))
}

#[allow(unused_variables)]
pub async fn prover_inner_origo(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
  setup_data: Option<UninitializedSetup>,
) -> Result<Proof, ClientErrors> {
  let session_id = config.session_id.clone();

  let setup_data = if let Some(setup_data) = setup_data {
    Ok(setup_data)
  } else if !cfg!(target_os = "ios") && !cfg!(target_arch = "wasm32") {
    // TODO: How do we decide which CIRCUIT_SIZE_* to use here?
    construct_setup_data_from_fs::<{ CIRCUIT_SIZE_512 }>()
      .map_err(|e| ClientErrors::Other(e.to_string()))
  } else {
    Err(ClientErrors::MissingSetupData)
  }?;

  let mut proof =
    origo::proxy_and_sign_and_generate_proof(config.clone(), proving_params, setup_data).await?;

  let manifest = config.proving.manifest.clone().ok_or(ClientErrors::ManifestMissingError)?;

  debug!("sending proof to proxy for verification");
  let verify_response = verify(config, origo::VerifyBody {
    session_id,
    origo_proof: proof.clone(),
    manifest: manifest.into(),
  })
  .await?;
  proof.sign_reply = Some(verify_response);

  debug!("proof.value: {:?}\nproof.verify_reply: {:?}", proof.value, proof.sign_reply);

  // TODO: This is where we should output richer proof data, the verify response has the hash of
  // the target value now. Since this is in the client, we can use the private variables here. We
  // just need to get out the value.
  Ok(Proof::Origo(proof))
}

pub async fn prover_inner_tee(mut config: config::Config) -> Result<Proof, ClientErrors> {
  let session_id = config.set_session_id();

  // TEE mode uses Origo networking stack with minimal changes

  #[cfg(target_arch = "wasm32")]
  let (_origo_conn, tee_proof) = origo_wasm32::proxy(config, session_id).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let (_origo_conn, tee_proof) = origo_native::proxy(config, session_id).await?;

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
  Ok(Proof::Proxy(tee_proof))
}

pub async fn verify<T: Serialize>(
  config: crate::config::Config,
  verify_body: T,
) -> Result<SignedVerificationReply, errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/{}/verify",
    config.notary_host.clone(),
    config.notary_port.clone(),
    config.mode,
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
