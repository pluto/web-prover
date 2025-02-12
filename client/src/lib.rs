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

use proofs::{
  errors::ProofError,
  program::manifest::{Manifest, NIVCRom},
  proof::FoldingProof,
};
use serde::{Deserialize, Serialize};
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::{debug, info};

use crate::errors::ClientErrors;

// TODO: We should put the following in here:
// - Value that was to be found in the JSON
// - Hash of manifest, maybe?
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OrigoProof {
  pub proof:             FoldingProof<Vec<u8>, String>,
  pub rom:               NIVCRom,
  pub ciphertext_digest: [u8; 32],
  // TODO: This likely doesn't need to be an option, but this makes it so I can set it later.
  pub verify_reply:      Option<VerifyReply>,
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

  proof.verify_reply = Some(verify_response);

  debug!("proof.value: {:?}\nproof.verify_reply: {:?}", proof.value, proof.verify_reply);

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
  assert!(response.status() == hyper::StatusCode::OK);
  let tee_proof = response.json::<TeeProof>().await?;
  Ok(Proof::Proxy(tee_proof))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OrigoProof {
  pub proof:             FoldingProof<Vec<u8>, String>,
  pub ciphertext_digest: [u8; 32],
  pub rom:               NIVCRom,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeeProof {
  pub data:      TeeProofData,
  pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeeProofData {
  pub manifest_hash: String,
}

impl TeeProof {
  pub fn to_write_bytes(&self) -> Vec<u8> {
    let serialized = self.to_bytes();
    let length = serialized.len() as u32;
    let mut wire_data = length.to_le_bytes().to_vec();
    wire_data.extend(serialized);
    wire_data
  }

  pub fn from_wire_bytes(buffer: &[u8]) -> Self {
    // Confirm the buffer is at least large enough to contain the "header"
    if buffer.len() < 4 {
      panic!("Unexpected buffer length: {} < 4", buffer.len());
    }

    // Extract the first 4 bytes as the length prefix
    let length_bytes = &buffer[..4];
    let length = u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;

    // Ensure the buffer contains enough data for the length specified
    if buffer.len() < 4 + length {
      panic!("Unexpected buffer length: {} < {} + 4", buffer.len(), length);
    }

    // Extract the serialized data from the buffer
    let serialized_data = &buffer[4..4 + length];
    Self::from_bytes(serialized_data)
  }

  fn to_bytes(&self) -> Vec<u8> { serde_json::to_vec(&self).unwrap() }

  fn from_bytes(bytes: &[u8]) -> TeeProof { serde_json::from_slice(bytes).unwrap() }
}
