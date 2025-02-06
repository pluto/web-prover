pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

pub mod circuits;
pub mod config;
pub mod errors;
mod proof;
mod tls;

pub mod tls_client_async2;
use proofs::{errors::ProofError, proof::FoldingProof};
use serde::{Deserialize, Serialize};
use tlsn_common::config::ProtocolConfig;
pub use tlsn_core::attestation::Attestation;
use tlsn_core::presentation::Presentation;
use tlsn_prover::ProverConfig;
use tracing::{debug, info};

use crate::errors::ClientErrors;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OrigoProof {
  pub request:  FoldingProof<Vec<u8>, String>,
  pub response: FoldingProof<Vec<u8>, String>,
}

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(Box<Presentation>),
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

  let p = tlsn::notarize(prover).await?;

  // TODO(WJ 2025-02-04): We might want to return an presentation instead of an attestation here, no
  // sure yet. The thought process here is that the verify api on TLSN takes a presentation, not
  // an attestation.
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
