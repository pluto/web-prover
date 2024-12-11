pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

mod circuits;
pub mod config;
pub mod errors;
mod tls;
pub mod tls_client_async2;
use serde::Serialize;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::info;

use crate::errors::ClientErrors;

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(TlsProof),
  Origo((Vec<u8>, Vec<u8>)),
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
    .id(config.session_id())
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
  Ok(Proof::TLSN(p))
}

#[allow(unused_variables)]
pub async fn prover_inner_origo(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<Proof, errors::ClientErrors> {
  #[cfg(target_arch = "wasm32")]
  let proof = origo_wasm32::proxy_and_sign_and_generate_proof(config.clone(), proving_params).await;

  #[cfg(not(target_arch = "wasm32"))]
  let proof = origo_native::proxy_and_sign_and_generate_proof(config.clone()).await;

  let r = proof.unwrap();
  let real_proof = match &r {
    Proof::Origo(proof) => proof.0.clone(),
    _ => Vec::new(),
  };

  // TODO: Actually propagate errors up to the client
  let verify_response = origo::verify(config, origo::VerifyBody{
    proof: real_proof,
  }).await.unwrap();

  // TODO: Don't assert?
  assert!(verify_response.valid);

  Ok(r)
}
