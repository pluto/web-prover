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

use origo::SignedVerificationReply;
use proofs::{
  program::manifest::{Manifest, NIVCRom},
  proof::FoldingProof,
};
use serde::{Deserialize, Serialize};
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::{debug, info};

use crate::errors::ClientErrors;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OrigoProof {
  pub proof:             FoldingProof<Vec<u8>, String>,
  pub rom:               NIVCRom,
  pub ciphertext_digest: [u8; 32],
  pub sign_reply:        Option<SignedVerificationReply>,
  pub value:             Option<String>,
}

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(Box<TlsProof>),
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
) -> Result<Proof, errors::ClientErrors> {
  info!("GIT_HASH: {}", env!("GIT_HASH"));
  match config.mode {
    config::NotaryMode::TLSN => prover_inner_tlsn(config).await,
    config::NotaryMode::Origo => prover_inner_origo(config, proving_params).await,
    config::NotaryMode::TEE => prover_inner_tee(config).await,
    config::NotaryMode::Proxy => prover_inner_proxy(config).await,
  }
}

pub async fn prover_inner_tlsn(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let root_store =
    crate::tls::tls_client_default_root_store(config.notary_ca_cert.clone().map(|c| vec![c]));

  let max_sent_data = config
    .max_sent_data
    .ok_or_else(|| ClientErrors::Other("max_sent_data is missing".to_string()))?;
  let max_recv_data = config
    .max_recv_data
    .ok_or_else(|| ClientErrors::Other("max_recv_data is missing".to_string()))?;

  let prover_config = ProverConfig::builder()
    .id(config.session_id.clone())
    .root_cert_store(root_store)
    .server_dns(config.target_host()?)
    .max_transcript_size(max_sent_data + max_recv_data)
    .build()
    .map_err(|e| ClientErrors::Other(e.to_string()))?;

  #[cfg(target_arch = "wasm32")]
  let prover = tlsn_wasm32::setup_connection(&mut config, prover_config).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let prover = if config.websocket_proxy_url.is_some() {
    tlsn_native::setup_websocket_connection(&mut config, prover_config).await
  } else {
    tlsn_native::setup_tcp_connection(&mut config, prover_config).await
  };

  let p = tlsn::notarize(prover).await?;
  Ok(Proof::TLSN(Box::new(p)))
}

#[allow(unused_variables)]
pub async fn prover_inner_origo(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id.clone();

  let mut proof = origo::proxy_and_sign_and_generate_proof(config.clone(), proving_params).await?;

  let manifest =
    config.proving.manifest.clone().ok_or(errors::ClientErrors::ManifestMissingError)?;

  debug!("sending proof to proxy for verification");
  let verify_response =
    origo::verify(config, origo::VerifyBody { session_id, origo_proof: proof.clone(), manifest })
      .await?;
  // Note: The above `?` will push out the `ProofError::VerifyFailed` from the `origo::verify`
  // method now. We no longer return an inner bool here, we just use the Result enum itself

  proof.sign_reply = Some(verify_response);

  debug!("proof.value: {:?}\nproof.verify_reply: {:?}", proof.value, proof.sign_reply);

  // TODO: This is where we should output richer proof data, the verikfy response has the hash of
  // the target value now. Since this is in the client, we can use the private variables here. We
  // just need to get out the value.
  Ok(Proof::Origo(proof))
}

pub async fn prover_inner_tee(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
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

pub async fn prover_inner_proxy(config: config::Config) -> Result<Proof, errors::ClientErrors> {
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeeProof {
  pub data:      TeeProofData,
  pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeeProofData {
  pub manifest_hash: Vec<u8>,
}

impl TeeProof {
  pub fn to_bytes(&self) -> serde_json::Result<Vec<u8>> { serde_json::to_vec(&self) }

  fn from_bytes(bytes: &[u8]) -> serde_json::Result<TeeProof> { serde_json::from_slice(bytes) }
}
