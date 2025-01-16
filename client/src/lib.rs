pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

pub mod circuits;
pub mod config;
pub mod errors;
mod tls;
pub mod tls_client_async2;
use proofs::{errors::ProofError, proof::FoldingProof};
use serde::Serialize;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::info;

use crate::errors::ClientErrors;

#[derive(Debug, Serialize)]
pub struct OrigoProof {
  request:  FoldingProof<Vec<u8>, String>,
  response: Option<FoldingProof<Vec<u8>, String>>,
}

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(Box<TlsProof>),
  Origo(OrigoProof),
}

pub async fn prover_inner(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<Proof, errors::ClientErrors> {
  info!("GIT_HASH: {}", env!("GIT_HASH"));
  match config.mode {
    config::NotaryMode::TLSN => prover_inner_tlsn(config).await,
    config::NotaryMode::Origo => prover_inner_origo(config, proving_params).await,
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
  #[cfg(target_arch = "wasm32")]
  let proof =
    origo_wasm32::proxy_and_sign_and_generate_proof(config.clone(), proving_params).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let proof =
    origo_native::proxy_and_sign_and_generate_proof(config.clone(), proving_params).await?;

  let verify_response = origo::verify(config, origo::VerifyBody {
    request_proof: proof.request.proof.clone(),
    response_proof: Vec::new(),
    session_id,
    request_verifier_digest: proof.request.verifier_digest.clone(),
  })
  .await?;

  if !verify_response.valid {
    Err(ProofError::VerifyFailed().into())
  } else {
    Ok(Proof::Origo(proof))
  }
}
