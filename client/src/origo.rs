// logic common to wasm32 and native

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use serde::Serialize;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

pub async fn sign(
  config: crate::config::Config,
  session_id: String,
  server_aes_key: Vec<u8>,
  server_aes_iv: Vec<u8>,
) -> Result<crate::Proof, crate::errors::ClientErrors> {
  #[derive(Serialize)]
  struct SignBody {
    server_aes_iv:  String,
    server_aes_key: String,
  }

  let sb = SignBody {
    server_aes_iv:  String::from_utf8(server_aes_iv.to_vec()).unwrap(),
    server_aes_key: String::from_utf8(server_aes_key.to_vec()).unwrap(),
  };

  let url = format!(
    "https://{}:{}/v1/origo/sign?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let client = reqwest::ClientBuilder::new().build().unwrap();

  #[cfg(feature = "notary_ca_cert")]
  let client = reqwest::ClientBuilder::new()
    .add_root_certificate(
      reqwest::tls::Certificate::from_der(&crate::tls::NOTARY_CA_CERT.to_vec()).unwrap(),
    )
    .build()
    .unwrap();

  let response = client.post(url).json(&sb).send().await.unwrap();
  assert!(response.status() == hyper::StatusCode::OK);

  // TODO remove debug log line
  println!("\n{}\n\n", String::from_utf8(response.bytes().await.unwrap().to_vec()).unwrap());

  Ok(crate::Proof::Origo(crate::OrigoProof {})) // TODO
}
