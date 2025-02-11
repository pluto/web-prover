// logic common to wasm32 and native
use std::collections::HashMap;

use proofs::{
  circuits::construct_setup_data,
  program::{
    data::{Offline, SetupParams},
    manifest::{EncryptionInput, Manifest, TLSEncryption},
  },
  F, G1, G2,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
  config::{self},
  errors::ClientErrors,
  tls::decrypt_tls_ciphertext,
  OrigoProof,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignBody {
  pub handshake_server_iv:  String,
  pub handshake_server_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyBody {
  pub session_id:  String,
  pub origo_proof: OrigoProof,
  pub manifest:    Manifest,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyReply {
  pub valid: bool,
  // TODO: need a signature
}

pub async fn sign(
  config: crate::config::Config,
  session_id: String,
  sb: SignBody,
) -> Result<Vec<u8>, crate::errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/origo/sign?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
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

  let response = client.post(url).json(&sb).send().await?;
  assert!(response.status() == hyper::StatusCode::OK, "response={:?}", response);

  // TODO: Actually use this input in the proofs.
  let sign_response = response.bytes().await?.to_vec();
  debug!("\n{}\n\n", String::from_utf8(sign_response.clone())?);

  Ok(sign_response)
}

pub async fn verify(
  config: crate::config::Config,
  verify_body: VerifyBody,
) -> Result<VerifyReply, crate::errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/origo/verify",
    config.notary_host.clone(),
    config.notary_port.clone(),
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
  let verify_response = response.json::<VerifyReply>().await?;

  debug!("\n{:?}\n\n", verify_response.clone());

  Ok(verify_response)
}

pub(crate) async fn proxy_and_sign_and_generate_proof(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<OrigoProof, ClientErrors> {
  let session_id = config.session_id.clone();

  #[cfg(not(target_arch = "wasm32"))]
  let mut origo_conn = crate::origo_native::proxy(config.clone(), session_id.clone()).await?;
  #[cfg(target_arch = "wasm32")]
  let mut origo_conn = crate::origo_wasm32::proxy(config.clone(), session_id.clone()).await?;

  let sb = SignBody {
    handshake_server_iv:  hex::encode(
      origo_conn.secret_map.get("Handshake:server_iv").unwrap().clone(),
    ),
    handshake_server_key: hex::encode(
      origo_conn.secret_map.get("Handshake:server_key").unwrap().clone(),
    ),
  };

  let _sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb).await;

  debug!("generating program data!");
  let witness = origo_conn.to_witness_data();

  // decrypt TLS ciphertext for request and response and create NIVC inputs
  let TLSEncryption { request: request_inputs, response: response_inputs } =
    decrypt_tls_ciphertext(&witness)?;

  // generate NIVC proofs for request and response
  let manifest = config.proving.manifest.unwrap();

  let proof =
    generate_proof(manifest, proving_params.unwrap(), request_inputs, response_inputs).await?;

  Ok(proof)
}

pub(crate) async fn generate_proof(
  manifest: Manifest,
  proving_params: Vec<u8>,
  request_inputs: EncryptionInput,
  response_inputs: EncryptionInput,
) -> Result<OrigoProof, ClientErrors> {
  let setup_data = construct_setup_data::<{ proofs::circuits::CIRCUIT_SIZE_512 }>()?;
  let program_data = SetupParams::<Offline> {
    public_params: proving_params,
    vk_digest_primary: F::<G1>::from(0), // These need to be right.
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom_data: HashMap::new(),
  }
  .into_online()?;

  let vk_digest_primary = program_data.vk_digest_primary;
  let vk_digest_secondary = program_data.vk_digest_secondary;
  crate::proof::construct_program_data_and_proof::<{ proofs::circuits::CIRCUIT_SIZE_512 }>(
    manifest,
    request_inputs,
    response_inputs,
    (vk_digest_primary, vk_digest_secondary),
    program_data.public_params,
    program_data.setup_data,
  )
  .await

  // return Ok(OrigoProof(proof));
}
