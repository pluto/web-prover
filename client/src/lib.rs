pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

pub mod config;
pub mod errors;
mod tls;

use serde::Serialize;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::info;
use arecibo::{provider::Bn256EngineKZG, supernova::RecursiveSNARK};


type OrigoProof<Bn256EngineKZG> = RecursiveSNARK<Bn256EngineKZG>;

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(TlsProof),
  Origo(),
  // Origo(OrigoProof<Bn256EngineKZG>),
}

pub async fn prover_inner(config: config::Config) -> Result<Proof, errors::ClientErrors> {
  info!("GIT_HASH: {}", env!("GIT_HASH"));
  match config.mode {
    config::NotaryMode::TLSN => prover_inner_tlsn(config).await,
    config::NotaryMode::Origo => prover_inner_origo(config).await,
  }
}

pub async fn prover_inner_tlsn(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let root_store = crate::tls::tls_client_default_root_store();

  let prover_config = ProverConfig::builder()
    .id(config.session_id())
    .root_cert_store(root_store)
    .server_dns(config.target_host())
    .max_transcript_size(config.max_sent_data.unwrap() + config.max_recv_data.unwrap())
    .build()
    .unwrap();

  #[cfg(target_arch = "wasm32")]
  let prover = tlsn_wasm32::setup_connection(&mut config, prover_config).await;

  #[cfg(not(target_arch = "wasm32"))]
  let prover = if config.websocket_proxy_url.is_some() {
    tlsn_native::setup_websocket_connection(&mut config, prover_config).await
  } else {
    tlsn_native::setup_tcp_connection(&mut config, prover_config).await
  };

  let p = tlsn::notarize(prover).await.unwrap();
  Ok(Proof::TLSN(p))
}

pub async fn prover_inner_origo(config: config::Config) -> Result<Proof, errors::ClientErrors> {
  #[cfg(target_arch = "wasm32")]
  return origo_wasm32::proxy_and_sign(config).await;

  #[cfg(not(target_arch = "wasm32"))]
  return origo_native::proxy_and_sign(config).await;
}
