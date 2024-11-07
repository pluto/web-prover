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

use serde::Serialize;
pub use tlsn_core::{attestation::Attestation, Secrets};
use tlsn_prover::ProverConfig;
use tracing::info;

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(Attestation, Secrets),
  Origo(Vec<u8>),
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

  let prover_config = ProverConfig::builder().build().unwrap();
    // .root_cert_store(root_store)
    // .server_dns(config.target_host())
    // .max_transcript_size(config.max_sent_data.unwrap() + config.max_recv_data.unwrap())
    // .build()
    // .unwrap();

  #[cfg(target_arch = "wasm32")]
  let prover = tlsn_wasm32::setup_connection(&mut config, prover_config).await;

  #[cfg(not(target_arch = "wasm32"))]
  let prover = if config.websocket_proxy_url.is_some() {
    tlsn_native::setup_websocket_connection(&mut config, prover_config).await
  } else {
    tlsn_native::setup_tcp_connection(&mut config, prover_config).await
  };

  let (a, s ) = tlsn::notarize(prover).await.unwrap();
  Ok(Proof::TLSN(a, s))
}

pub async fn prover_inner_origo(config: config::Config) -> Result<Proof, errors::ClientErrors> {
  #[cfg(target_arch = "wasm32")]
  return origo_wasm32::proxy_and_sign(config).await;

  #[cfg(not(target_arch = "wasm32"))]
  return origo_native::proxy_and_sign(config).await;
}
