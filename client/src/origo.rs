// logic common to wasm32 and native
use arecibo::{provider::Bn256EngineKZG, supernova::RecursiveSNARK};
use proofs::program;
use serde::Serialize;
use serde_json::json;
use tls_client2::{origo::WitnessData, CipherSuite, Decrypter2, ProtocolVersion};
use tls_core::msgs::{base::Payload, enums::ContentType, message::OpaqueMessage};
use tracing::debug;

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
  witness: &WitnessData,
) -> Result<Vec<u8>, crate::errors::ClientErrors> {
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

  // TODO: Actually use this input in the proofs. 
  let sign_response = response.bytes().await.unwrap().to_vec();
  println!("\n{}\n\n", String::from_utf8(sign_response.clone()).unwrap());

  Ok(sign_response)
}
