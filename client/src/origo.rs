// logic common to wasm32 and native
use std::collections::HashMap;

use futures::AsyncReadExt;
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
  data_hasher, field_element_to_base10_string,
  http::{
    compute_http_witness, headers_to_bytes, parser::parse as http_parse, HttpMaskType,
    RawHttpMachine,
  },
  json::{json_value_digest, parser::parse, JsonKey, RawJsonMachine},
  polynomial_digest, poseidon, ByteOrPad,
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
  let flattened_plaintext: Vec<u8> =
    response_inputs.plaintext.into_iter().flat_map(|x| x).collect();
  let http_body = compute_http_witness(&flattened_plaintext, HttpMaskType::Body);
  let value = json_value_digest::<{ proofs::program::manifest::MAX_STACK_HEIGHT }>(
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

  /// Serializes the `OrigoSecrets` into a length-prefixed byte array.
  pub fn to_wire_bytes(&self) -> Vec<u8> {
    let serialized = self.to_bytes();
    let length = serialized.len() as u32;
    // Create the "header" with the length (as little-endian bytes)
    let mut wire_data = length.to_le_bytes().to_vec();
    wire_data.extend(serialized);
    wire_data
  }

  /// Deserializes a `OrigoSecrets` from a length-prefixed byte buffer.
  ///
  /// Expects a buffer with a 4-byte little-endian "header" followed by the serialized data.
  pub fn from_wire_bytes(buffer: &[u8]) -> Self {
    // Confirm the buffer is at least large enough to contain the "header"
    if buffer.len() < 4 {
      panic!("Unexpected buffer length: {} < 4", buffer.len());
    }

    // Extract the first 4 bytes as the length prefix
    let length_bytes = &buffer[..4];
    let length = u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;

    // Ensure the buffer contains enough data for the length specified
    if buffer.len() < 4 + length {
      panic!("Unexpected buffer length: {} < {} + 4", buffer.len(), length);
    }

    // Extract the serialized data from the buffer
    let serialized_data = &buffer[4..4 + length];
    Self::from_bytes(serialized_data).unwrap()
  }

  fn to_bytes(&self) -> Vec<u8> { serde_json::to_vec(&self).unwrap() }

  fn from_bytes(bytes: &[u8]) -> Result<Self, ClientErrors> {
    let secrets: HashMap<String, Vec<u8>> = serde_json::from_slice(bytes)?;
    Ok(Self(secrets))
  }
}

// TODO: Refactor into struct helpers/trait
pub(crate) async fn read_wire_struct<R: AsyncReadExt + Unpin>(stream: &mut R) -> Vec<u8> {
  // Buffer to store the "header" (4 bytes, indicating the length of the struct)
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf).await.unwrap();
  // dbg!(format!("len_buf={:?}", len_buf));

  // Deserialize the length prefix (convert from little-endian to usize)
  let body_len = u32::from_le_bytes(len_buf) as usize;
  // dbg!(format!("body_len={body_len}"));

  // Allocate a buffer to hold only the bytes needed for the struct
  let mut body_buf = vec![0u8; body_len];
  stream.read_exact(&mut body_buf).await.unwrap();
  // dbg!(format!("manifest_buf={:?}", manifest_buf));

  // Prepend len_buf to manifest_buf
  let mut wire_struct_buf = len_buf.to_vec();
  wire_struct_buf.extend(body_buf);

  wire_struct_buf
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_manifest_serialization() {
    let mut origo_conn = OrigoConnection::new();
    origo_conn.secret_map.insert("Handshake:server_iv".to_string(), vec![1, 2, 3]);
    let origo_secrets = OrigoSecrets::from_origo_conn(&origo_conn);

    let serialized = origo_secrets.to_bytes();
    let deserialized: OrigoSecrets = OrigoSecrets::from_bytes(&serialized).unwrap();
    assert_eq!(origo_secrets, deserialized);

    let wire_serialized = origo_secrets.to_wire_bytes();
    let wire_deserialized: OrigoSecrets = OrigoSecrets::from_wire_bytes(&wire_serialized);
    assert_eq!(origo_secrets, wire_deserialized);
  }
}
