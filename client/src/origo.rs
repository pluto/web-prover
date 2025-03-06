// logic common to wasm32 and native
use std::collections::HashMap;

use proofs::{
  program::{
    data::{Offline, SetupParams, UninitializedSetup},
    manifest::{EncryptionInput, NIVCRom, OrigoManifest, TLSEncryption},
  },
  proof::FoldingProof,
  F, G1, G2,
};
use serde::{Deserialize, Serialize};
use tls_client2::origo::OrigoConnection;
use tracing::debug;
use web_proof_circuits_witness_generator::{
  http::{compute_http_witness, HttpMaskType},
  json::json_value_digest,
};
use web_prover_core::proof::SignedVerificationReply;

use crate::{
  config::{self},
  errors::ClientErrors,
  tls::decrypt_tls_ciphertext,
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
  pub manifest:    OrigoManifest,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OrigoProof {
  pub proof:             FoldingProof<Vec<u8>, String>,
  pub rom:               NIVCRom,
  pub ciphertext_digest: [u8; 32],
  pub sign_reply:        Option<SignedVerificationReply>,
  pub value:             Option<String>,
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

// TODO: We probably don't need to call this "proxy_and_sign" since we don't sign in here
pub(crate) async fn proxy_and_sign_and_generate_proof(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
  setup_data: UninitializedSetup,
) -> Result<OrigoProof, ClientErrors> {
  let session_id = config.session_id.clone();

  #[cfg(not(target_arch = "wasm32"))]
  let (mut origo_conn, _) = crate::origo_native::proxy(config.clone(), session_id.clone()).await?;
  #[cfg(target_arch = "wasm32")]
  let (mut origo_conn, _) = crate::origo_wasm32::proxy(config.clone(), session_id.clone()).await?;

  let sb = SignBody {
    handshake_server_iv:  hex::encode(
      origo_conn.secret_map.get("Handshake:server_iv").unwrap().clone(),
    ),
    handshake_server_key: hex::encode(
      origo_conn.secret_map.get("Handshake:server_key").unwrap().clone(),
    ),
  };

  let _sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb).await;

  let witness = origo_conn.to_witness_data();

  // decrypt TLS ciphertext for request and response and create NIVC inputs
  let TLSEncryption { request: request_inputs, response: response_inputs } =
    decrypt_tls_ciphertext(&witness)?;

  // generate NIVC proofs for request and response
  let manifest = config.manifest;

  let mut proof = generate_proof(
    &manifest.clone().into(),
    &proving_params.unwrap(),
    &setup_data,
    &request_inputs,
    &response_inputs,
  )
  .await?;
  let flattened_plaintext: Vec<u8> = response_inputs.plaintext.into_iter().flatten().collect();
  let http_body = compute_http_witness(&flattened_plaintext, HttpMaskType::Body);
  let value = json_value_digest::<{ proofs::circuits::MAX_STACK_HEIGHT }>(
    &http_body,
    &manifest.response.body.json_path(),
  )?;

  proof.value = Some(String::from_utf8_lossy(&value).into_owned());

  Ok(proof)
}

pub(crate) async fn generate_proof(
  manifest: &OrigoManifest,
  proving_params: &[u8],
  setup_data: &UninitializedSetup,
  request_inputs: &EncryptionInput,
  response_inputs: &EncryptionInput,
) -> Result<OrigoProof, ClientErrors> {
  let setup_params = SetupParams::<Offline> {
    public_params:       proving_params.to_vec(),
    vk_digest_primary:   F::<G1>::from(0), // These need to be right.
    vk_digest_secondary: F::<G2>::from(0),
    setup_data:          setup_data.clone(),
    rom_data:            HashMap::new(),
  }
  .into_online()?;

  let vk_digest_primary = setup_params.vk_digest_primary;
  let vk_digest_secondary = setup_params.vk_digest_secondary;
  crate::proof::construct_program_data_and_proof::<{ proofs::circuits::CIRCUIT_SIZE_512 }>(
    manifest,
    request_inputs,
    response_inputs,
    (vk_digest_primary, vk_digest_secondary),
    setup_params.public_params,
    setup_params.setup_data,
  )
  .await
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrigoSecrets(HashMap<String, Vec<u8>>);

impl TryFrom<&OrigoSecrets> for Vec<u8> {
  type Error = serde_json::Error;

  fn try_from(secrets: &OrigoSecrets) -> Result<Self, Self::Error> { serde_json::to_vec(secrets) }
}

impl TryFrom<&[u8]> for OrigoSecrets {
  type Error = serde_json::Error;

  fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> { serde_json::from_slice(bytes) }
}

impl OrigoSecrets {
  pub fn handshake_server_iv(&self) -> Option<Vec<u8>> {
    self.0.get("Handshake:server_iv").cloned()
  }

  pub fn handshake_server_key(&self) -> Option<Vec<u8>> {
    self.0.get("Handshake:server_key").cloned()
  }

  pub fn app_server_iv(&self) -> Option<Vec<u8>> { self.0.get("Application:server_iv").cloned() }

  pub fn app_server_key(&self) -> Option<Vec<u8>> { self.0.get("Application:server_key").cloned() }

  pub fn app_client_iv(&self) -> Option<Vec<u8>> { self.0.get("Application:client_iv").cloned() }

  pub fn app_client_key(&self) -> Option<Vec<u8>> { self.0.get("Application:client_key").cloned() }

  pub fn from_origo_conn(origo_conn: &OrigoConnection) -> Self {
    Self(origo_conn.secret_map.clone())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_manifest_serialization() {
    let mut origo_conn = OrigoConnection::new();
    origo_conn.secret_map.insert("Handshake:server_iv".to_string(), vec![1, 2, 3]);
    let origo_secrets = &OrigoSecrets::from_origo_conn(&origo_conn);

    let serialized: Vec<u8> = origo_secrets.try_into().unwrap();
    let deserialized: OrigoSecrets = OrigoSecrets::try_from(serialized.as_ref()).unwrap();
    assert_eq!(*origo_secrets, deserialized);
  }
}
