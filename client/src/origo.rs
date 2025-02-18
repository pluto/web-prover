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
use tls_client2::origo::OrigoConnection;
use tracing::debug;
use web_proof_circuits_witness_generator::{
  http::{compute_http_witness, HttpMaskType},
  json::json_value_digest,
};

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedVerificationReply {
  pub merkle_leaves: Vec<String>,
  pub digest:        String,
  pub signature:     String,
  pub signature_r:   String,
  pub signature_s:   String,
  pub signature_v:   u8,
  pub signer:        String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyBody {
  pub session_id:  String,
  pub origo_proof: OrigoProof,
  pub manifest:    Manifest,
}

// TODO: Okay, right now we just want to take what's in here and actually just produce a signature
// as the reply instead. So pretend this is signed content for now and not actual raw values.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyReply {
  pub value:    String,
  pub manifest: Manifest,
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
) -> Result<SignedVerificationReply, crate::errors::ClientErrors> {
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
  let verify_response = response.json::<SignedVerificationReply>().await?;

  debug!("\n{:?}\n\n", verify_response.clone());

  Ok(verify_response)
}

// TODO: We probably don't need to call this "proxy_and_sign" since we don't sign in here
pub(crate) async fn proxy_and_sign_and_generate_proof(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
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

  debug!("generating program data!");
  let witness = origo_conn.to_witness_data();

  // decrypt TLS ciphertext for request and response and create NIVC inputs
  let TLSEncryption { request: request_inputs, response: response_inputs } =
    decrypt_tls_ciphertext(&witness)?;

  // generate NIVC proofs for request and response
  let manifest = config.proving.manifest.unwrap();

  let mut proof = generate_proof(
    manifest.clone(),
    proving_params.unwrap(),
    request_inputs,
    response_inputs.clone(),
  )
  .await?;
  let flattened_plaintext: Vec<u8> = response_inputs.plaintext.into_iter().flatten().collect();
  let http_body = compute_http_witness(&flattened_plaintext, HttpMaskType::Body);
  let value = json_value_digest::<{ proofs::circuits::MAX_STACK_HEIGHT }>(
    &http_body,
    &manifest.response.body.json,
  )?;

  proof.value = Some(String::from_utf8_lossy(&value).into_owned());

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrigoSecrets(HashMap<String, Vec<u8>>);

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

  pub fn to_bytes(&self) -> serde_json::Result<Vec<u8>> { serde_json::to_vec(&self) }

  pub fn from_bytes(bytes: &[u8]) -> serde_json::Result<Self> { serde_json::from_slice(bytes) }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_manifest_serialization() {
    let mut origo_conn = OrigoConnection::new();
    origo_conn.secret_map.insert("Handshake:server_iv".to_string(), vec![1, 2, 3]);
    let origo_secrets = OrigoSecrets::from_origo_conn(&origo_conn);

    let serialized = origo_secrets.to_bytes().unwrap();
    let deserialized: OrigoSecrets = OrigoSecrets::from_bytes(&serialized).unwrap();
    assert_eq!(origo_secrets, deserialized);

    let wire_serialized = origo_secrets.to_bytes().unwrap();
    let wire_deserialized: OrigoSecrets = OrigoSecrets::from_bytes(&wire_serialized).unwrap();
    assert_eq!(origo_secrets, wire_deserialized);
  }
}
