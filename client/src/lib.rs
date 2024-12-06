pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

mod circuits;
pub mod config;
pub mod errors;
mod tee;
mod tls;
pub mod tls_client_async2;
use serde::{Serialize, Deserialize};
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::ProverConfig;
use tracing::info;

use crate::errors::ClientErrors;

#[derive(Debug, Serialize)]
pub enum Proof {
  TLSN(TlsProof),
  Origo((Vec<u8>, Vec<u8>)),
  TEE(Vec<u8>),
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

pub async fn prover_inner_origo(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<Proof, errors::ClientErrors> {
  #[cfg(target_arch = "wasm32")]
  return origo_wasm32::proxy_and_sign(config, proving_params).await;

  #[cfg(not(target_arch = "wasm32"))]
  return origo_native::proxy_and_sign(config).await;
}

// #[derive(Deserialize, Debug, Clone)]
// pub struct AttestationBody {
//   handshake_server_aes_iv:    String,
//   handshake_server_aes_key:   String,
//   application_client_aes_iv:  String,
//   application_client_aes_key: String,
//   application_server_aes_iv:  String,
//   application_server_aes_key: String,
// }

pub async fn prover_inner_tee(config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.clone().session_id();
  // let manifest = config.proving.manifest; // TODO

  // We are re-using origo networking for TEE

  #[cfg(target_arch = "wasm32")]
  let origo_conn = origo_wasm32::proxy(config, session_id, true).await;

  #[cfg(not(target_arch = "wasm32"))]
  let origo_conn = origo_native::proxy(config, session_id, true).await;

  // let ab = AttestationBody {
  //   handshake_server_aes_iv:    hex::encode(
  //     origo_conn.secret_map.get("Handshake:server_aes_iv").unwrap().clone().to_vec(),
  //   ),
  //   handshake_server_aes_key:   hex::encode(
  //     origo_conn.secret_map.get("Handshake:server_aes_key").unwrap().clone().to_vec(),
  //   ),
  //   application_client_aes_iv:  hex::encode(
  //     origo_conn.secret_map.get("Application:client_aes_iv").unwrap().clone().to_vec(),
  //   ),
  //   application_client_aes_key: hex::encode(
  //     origo_conn.secret_map.get("Application:client_aes_key").unwrap().clone().to_vec(),
  //   ),
  //   application_server_aes_iv:  hex::encode(
  //     origo_conn.secret_map.get("Application:server_aes_iv").unwrap().clone().to_vec(),
  //   ),
  //   application_server_aes_key: hex::encode(
  //     origo_conn.secret_map.get("Application:server_aes_key").unwrap().clone().to_vec(),
  //   ),
  // };

  todo!("reached TEE end")
}
