// logic common to wasm32 and native

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
pub use tlsn_core::attestation::Attestation;
use tlsn_core::{
  presentation::{Presentation, PresentationOutput},
  request::RequestConfig,
  signing::VerifyingKey,
  transcript::TranscriptCommitConfig,
  CryptoProvider, Secrets,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{state::Closed, Prover};
use tracing::debug;

use crate::errors;

pub async fn notarize(prover: Prover<Closed>) -> Result<Attestation, errors::ClientErrors> {
  let mut prover = prover.start_notarize();
  let transcript = HttpTranscript::parse(prover.transcript())?;

  // Commit to the transcript.
  let mut builder = TranscriptCommitConfig::builder(prover.transcript());
  DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
  prover.transcript_commit(builder.build()?);

  // Request an attestation.
  let config = RequestConfig::default();
  let (attestation, _secrets) = prover.finalize(&config).await?;

  Ok(attestation)
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

pub async fn present(
  attestation: Attestation,
  secrets: Secrets,
) -> Result<Presentation, errors::ClientErrors> {
  // Parse the HTTP transcript.
  let transcript = HttpTranscript::parse(secrets.transcript())?;

  // Build a transcript proof.
  let mut builder = secrets.transcript_proof_builder();
  let request = &transcript.requests[0];
  // Reveal the structure of the request without the headers or body.
  builder.reveal_sent(&request.without_data())?;
  // Reveal the request target.
  builder.reveal_sent(&request.request.target)?;
  // Reveal all headers except the value of the User-Agent header.
  for header in &request.headers {
    if !header.name.as_str().eq_ignore_ascii_case("User-Agent") {
      builder.reveal_sent(header)?;
    } else {
      builder.reveal_sent(&header.without_value())?;
    }
  }
  // Reveal the entire response.
  builder.reveal_recv(&transcript.responses[0])?;

  let transcript_proof = builder.build()?;

  // Use default crypto provider to build the presentation.
  let provider = CryptoProvider::default();

  let mut builder = attestation.presentation_builder(&provider);

  builder.identity_proof(secrets.identity_proof()).transcript_proof(transcript_proof);

  let presentation: Presentation = builder.build()?;

  Ok(presentation)
}

pub async fn verify(presentation: Presentation) -> Result<(), errors::ClientErrors> {
  let provider = CryptoProvider::default();

  let VerifyingKey { alg, data: key_data } = presentation.verifying_key();

  println!(
    "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
    hex::encode(key_data)
  );

  // Verify the presentation.
  let PresentationOutput { server_name, connection_info, transcript, .. } =
    presentation.verify(&provider).unwrap();

  // The time at which the connection was started.
  let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
  let server_name = server_name.unwrap();
  let mut partial_transcript = transcript.unwrap();
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

  Ok(())
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

// fn get_notary_pubkey(pubkey: &str) -> p256::PublicKey {
//   p256::PublicKey::from_public_key_pem(pubkey).unwrap()
// }
