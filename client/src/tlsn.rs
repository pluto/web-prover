// logic common to wasm32 and native
use std::{clone, time::Duration};
use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use tlsn_core::{
  presentation::{Presentation, PresentationOutput}, 
  {attestation::Attestation, Secrets}, 
  signing::VerifyingKey, 
  CryptoProvider, 
  request::RequestConfig,
  transcript::TranscriptCommitConfig,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{state::Closed, Prover};
use tracing::debug;

use crate::errors::{self, ClientErrors};

pub async fn notarize(prover: Prover<Closed>) -> Result<(Attestation, Secrets), errors::ClientErrors> {
  // copied from https://github.com/tlsnotary/tlsn/blob/main/crates/examples/attestation/prove.rs
  // Prepare for notarization.
  let mut prover = prover.start_notarize();

  // Parse the HTTP transcript.
  let transcript = HttpTranscript::parse(prover.transcript())?;

  // Commit to the transcript.
  let mut builder = TranscriptCommitConfig::builder(prover.transcript());

  DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

  prover.transcript_commit(builder.build()?);

  // Request an attestation.
  let config = RequestConfig::default();

  let (attestation, secrets) = prover.finalize(&config).await?;

  Ok((attestation, secrets))
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

pub async fn verify(proof: Presentation, notary_pubkey_str: &str) -> Result<PresentationOutput, ClientErrors> {

  let provider = CryptoProvider::default();

  let VerifyingKey {
      alg,
      data: key_data,
  } = proof.verifying_key();

  println!(
      "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
      hex::encode(key_data)
  );

  // Verify the presentation.
  let pres = proof.verify(&provider).unwrap();

  // The time at which the connection was started.
  let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(pres.connection_info.time);
  let server_name = pres.server_name.as_ref().unwrap();
  let mut partial_transcript = pres.transcript.clone().unwrap();
  // Set the unauthenticated bytes so they are distinguishable.
  partial_transcript.set_unauthed(b'X');
  let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe());
  let recv = String::from_utf8_lossy(partial_transcript.received_unsafe());

  println!("-------------------------------------------------------------------");
  println!(
      "Successfully verified that the data below came from a session with {server_name} at {time}.",
  );
  println!("Note that the data which the Prover chose not to disclose are shown as X.\n");
  println!("Data sent:\n");
  println!("{}\n", sent);
  println!("Data received:\n");
  println!("{}\n", recv);
  println!("-------------------------------------------------------------------");
  Ok(pres)
}

pub async fn send_request(
  mut request_sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>,
  request: Request<http_body_util::Full<Bytes>>,
) {
  // TODO: Clean up this logging and error handling
  match request_sender.send_request(request).await {
    Ok(response) => {
      let status = response.status();
      let headers = response.headers().clone();
      debug!(
        "Response with status code {:?}:\nHeaders: {:?}\n\nBody:\n{}",
        status,
        headers,
        body_to_string(response).await
      );
      assert!(status.is_success()); // status is 200-299
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO is this safe to ignore */
    Err(e) => panic!("{:?}", e),
  };
}

async fn body_to_string(res: hyper::Response<hyper::body::Incoming>) -> String {
  let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
  String::from_utf8(body_bytes.to_vec()).unwrap()
}

fn get_notary_pubkey(pubkey: &str) -> p256::PublicKey {
  p256::PublicKey::from_public_key_pem(pubkey).unwrap()
}
