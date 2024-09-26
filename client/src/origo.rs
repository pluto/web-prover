// logic common to wasm32 and native

use serde::Serialize;
use tls_proxy2::WitnessData;
use tracing::debug;
use proofs::{ProgramData, program, WitnessGeneratorType};
use std::path::PathBuf;
use std::collections::HashMap;
use tls_client2::{Decrypter2, ProtocolVersion, CipherSuite};
use tls_core::msgs::{base::Payload, codec::Codec, enums::ContentType, message::OpaqueMessage};
use arecibo::supernova::RecursiveSNARK;
use arecibo::provider::Bn256EngineKZG;

use crate::errors;

const AES_GCM_FOLD_R1CS: &str = "proofs/examples/circuit_data/aes-gcm-fold.r1cs"; 

const AES_GCM_FOLD_WASM: &str = "proofs/examples/circuit_data/aes-gcm-fold_js/aes-gcm-fold.wasm";
const AES_GCM_FOLD_WTNS: &str = "witness.wtns";

#[derive(Serialize)]
pub struct SignBody {
  pub hs_server_aes_iv:  String,
  pub hs_server_aes_key: String,
}

pub async fn sign(
  config: crate::config::Config,
  session_id: String,
  sb: SignBody,
  witness: WitnessData,
) -> Result<crate::Proof, crate::errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/origo/sign?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let client = reqwest::ClientBuilder::new().build().unwrap();

  #[cfg(feature = "notary_ca_cert")]
  // TODO: recheck use of rustls backend
  let client = reqwest::ClientBuilder::new()
    .add_root_certificate(
      reqwest::tls::Certificate::from_der(&crate::tls::NOTARY_CA_CERT.to_vec()).unwrap(),
    )
    .use_rustls_tls()
    .build()
    .unwrap();

  let response = client.post(url).json(&sb).send().await.unwrap();
  assert!(response.status() == hyper::StatusCode::OK);

  // TODO remove debug log line
  println!("\n{}\n\n", String::from_utf8(response.bytes().await.unwrap().to_vec()).unwrap());

  let r = generate_proof(witness).await.unwrap();

  Ok(crate::Proof::Origo(r))
}

pub async fn generate_proof(witness: WitnessData) -> Result<RecursiveSNARK<Bn256EngineKZG>, errors::ClientErrors> {

  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: &[u8] = &witness.request.aes_key;
  let iv: &[u8] = &witness.request.aes_iv;

  let mut private_input = HashMap::new();

  let ct: &[u8] = witness.request.ciphertext.as_bytes();
  let sized_key: [u8; 16] = key[..16].try_into().unwrap();
  let sized_iv: [u8; 12] = iv[..12].try_into().unwrap();

  private_input.insert("key".to_string(), serde_json::to_value(&sized_key).unwrap());
  private_input.insert("iv".to_string(), serde_json::to_value(&sized_iv).unwrap());

  let dec = Decrypter2::new(sized_key, sized_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = dec.decrypt_tls13_aes(&OpaqueMessage{
      typ: ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_3,
      payload:  Payload::new(hex::decode(ct).unwrap())
  }, 0).unwrap();
  let pt = plaintext.payload.0.to_vec();
  let aad = meta.additional_data.as_str().to_owned();

  // this somehow needs to be nested in this hashmap of values to be under another key called "fold_input"
  private_input.insert("plainText".to_string(), serde_json::to_value(&pt).unwrap());
  private_input.insert("aad".to_string(), serde_json::to_value(&aad).unwrap());

  let program_data = ProgramData {
    r1cs_paths: vec![PathBuf::from(AES_GCM_FOLD_R1CS)],
    witness_generator_types: vec![WitnessGeneratorType::Wasm{path: AES_GCM_FOLD_WASM.to_string(), wtns_path: AES_GCM_FOLD_WTNS.to_string()}],
    rom: vec![0; 64],
    initial_public_input: vec![0; 64],
    private_input,
  };

  let (params, proof) = program::run(&program_data);
  debug!("data={:?}", proof);

  Ok(proof)
}