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
use proofs::{errors::ProofError, program::manifest::NIVCRom, proof::FoldingProof};
use serde::{Deserialize, Serialize};
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::{debug, info};

use crate::errors::ClientErrors;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OrigoProof {
  pub proof: FoldingProof<Vec<u8>, String>,
  pub rom:   NIVCRom,
}

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(Box<TlsProof>),
  Origo(OrigoProof),
  TEE(), // TODO
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
  }
}

pub async fn prover_inner_tlsn(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let root_store = crate::tls::tls_client_default_root_store();

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

  let proof = origo::proxy_and_sign_and_generate_proof(config.clone(), proving_params).await?;

  debug!("sending proof to proxy for verification");
  let verify_response =
    origo::verify(config, origo::VerifyBody { session_id, origo_proof: proof.clone() }).await?;

  if !verify_response.valid {
    Err(ProofError::VerifyFailed().into())
  } else {
    Ok(Proof::Origo(proof))
  }
}

pub async fn prover_inner_tee(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.set_session_id();

  // TEE mode uses Origo networking stack with minimal changes

  #[cfg(target_arch = "wasm32")]
  let _origo_conn = origo_wasm32::proxy(config, session_id).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let _origo_conn = origo_native::proxy(config, session_id).await?;

  // TODO proof
  Ok(Proof::TEE())
}
