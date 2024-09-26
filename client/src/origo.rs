// logic common to wasm32 and native

use serde::Serialize;
use tls_proxy2::WitnessData;
use tracing::debug;
use proofs::{ProgramData, program, WitnessGeneratorType};
use std::path::PathBuf;
use std::collections::HashMap;

use crate::errors;

const AES_GCM_FOLD_R1CS: &str = "examples/circuit_data/aes-gcm-fold.r1cs"; 

const AES_GCM_FOLD_WASM: &str = "examples/circuit_data/aes-gcm-fold_js/aes-gcm-fold.wasm";
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

  Ok(crate::Proof::Origo(crate::OrigoProof {})) // TODO
}

pub async fn generate_proof(witness: WitnessData) -> Result<(), errors::ClientErrors> {

  // let thing = witness.request;
  // let thing2 = witness.response;

  let mut private_input = HashMap::new();
  private_input.insert("key".to_string(), serde_json::Value::String(witness.request.aes_key.clone()));
  private_input.insert("iv".to_string(), serde_json::Value::String(witness.request.aes_iv.clone()));
  // private_input.insert("aad".to_string(), witness.request.aad.clone());
  // TODO(WJ 2024-09-26): to get the aad i need to grab it from the origo connection struct.

  let program_data = ProgramData {
    r1cs_paths: vec![PathBuf::from(AES_GCM_FOLD_R1CS)],
    witness_generator_types: vec![WitnessGeneratorType::Wasm{path: AES_GCM_FOLD_WASM.to_string(), wtns_path: AES_GCM_FOLD_WTNS.to_string()}],
    rom: vec![0; 64],
    initial_public_input: vec![0; 64],
    private_input,
  };
  // private input is the key and iv, and the fold input: plaintext, and aad.
  // initial public inpute in the example file is a vec of 64 0s.

  program::run(&program_data);
  debug!("data={:?}", witness);

  Ok(())
}

// pub fn witness_to_raw(witness: WitnessData) -> Vec<u8> {
//   let mut buf = Vec::new();
//   witness.write(&mut buf).unwrap();
//   buf
// }
