// logic common to wasm32 and native

use std::{collections::HashMap, path::PathBuf};

use arecibo::{provider::Bn256EngineKZG, supernova::RecursiveSNARK};
use proofs::{program, ProgramData, WitnessGeneratorType};
use serde::Serialize;
use serde_json::json;
use tls_client2::{CipherSuite, Decrypter2, ProtocolVersion};
use tls_core::msgs::{base::Payload, codec::Codec, enums::ContentType, message::OpaqueMessage};
use tls_proxy2::WitnessData;
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

pub async fn generate_proof(
  witness: WitnessData,
) -> Result<RecursiveSNARK<Bn256EngineKZG>, errors::ClientErrors> {
  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: &[u8] = &witness.request.aes_key;
  let iv: &[u8] = &witness.request.aes_iv;

  let ct: &[u8] = witness.request.ciphertext.as_bytes();
  let sized_key: [u8; 16] = key[..16].try_into().unwrap();
  let sized_iv: [u8; 12] = iv[..12].try_into().unwrap();

  let dec = Decrypter2::new(sized_key, sized_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = dec
    .decrypt_tls13_aes(
      &OpaqueMessage {
        typ:     ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(hex::decode(ct).unwrap()),
      },
      0,
    )
    .unwrap();
  let pt = plaintext.payload.0.to_vec();
  let mut aad = hex::decode(meta.additional_data).unwrap();
  aad.resize(16, 0);
  let rom_len = pt.len() / 16;

  let private_input = json!({
    "private_input": {
      "key": sized_key,
      "iv": sized_iv,
      "fold_input": {
        "plainText": pt,
      },
      "aad": aad
    },
    "r1cs_paths": [AES_GCM_FOLD_R1CS],
    "witness_generator_types": [
      {
          "wasm": {
              "path": AES_GCM_FOLD_WASM,
              "wtns_path": "witness.wtns"
          }
      }
    ],
    "rom": vec![0; rom_len],
    "initial_public_input": vec![0; 48],
  });

  let program_data = serde_json::from_value(private_input).unwrap();
  let (params, proof) = program::run(&program_data);
  Ok(proof)
}
