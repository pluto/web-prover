// logic common to wasm32 and native

use tls_proxy2::WitnessData;
use serde::Serialize;
use tracing::debug;
use crate::errors;

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
  // let sb = SignBody {
  //   server_aes_iv:  String::from_utf8(server_aes_iv.to_vec()).unwrap(),
  //   server_aes_key: String::from_utf8(server_aes_key.to_vec()).unwrap(),
  // };

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
  debug!("data={:?}", witness);

  Ok(())
}