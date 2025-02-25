// logic common to wasm32 and native

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use proofs::program::manifest::Manifest;
use serde::{Deserialize, Serialize};
use spansy::{
  json::{parse, JsonValue},
  Spanned,
};
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
use utils::range::ToRangeSet;
use web_proof_circuits_witness_generator::json::JsonKey;

use crate::errors;

pub async fn notarize(
  prover: Prover<Closed>,
  manifest: &Option<Manifest>,
) -> Result<Presentation, errors::ClientErrors> {
  let manifest = match manifest {
    Some(manifest) => manifest,
    None => return Err(errors::ClientErrors::Other("Manifest is missing".to_string())),
  };

  let mut prover = prover.start_notarize();
  let transcript = HttpTranscript::parse(prover.transcript())?;

  // Commit to the transcript.
  dbg!(&transcript);
  let mut builder = TranscriptCommitConfig::builder(prover.transcript());
  DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
  dbg!(&builder);

  // Reveal the response start line and headers.
  let response = &transcript.responses[0];

  let response_body = match &response.body {
    Some(body) => body,
    None => return Err(errors::ClientErrors::Other("Response body is missing".to_string())),
  };

  let body_span = response_body.span();
  dbg!(&body_span);

  // reveal keys specified in manifest
  // reveal values specified in manifest

  let content_span = response_body.content.span();
  let initial_index = match content_span.indices().min() {
    Some(index) => index,
    None => return Err(errors::ClientErrors::Other("Content span is empty".to_string())),
  };
  dbg!(initial_index);

  let mut content_value = parse(content_span.clone().to_bytes()).unwrap();
  content_value.offset(initial_index);
  dbg!(&content_value);

  for key in manifest.response.body.json.iter() {
    let key = match key {
      JsonKey::String(s) => s.clone(),
      JsonKey::Num(n) => n.to_string(),
    };

    match content_value {
      JsonValue::Object(ref v) => {
        // reveal object without pairs
        // builder.reveal_recv(&v.without_pairs())?;
        builder.commit_recv(&v.without_pairs())?;

        for kv in v.elems.iter() {
          if key.as_str() == kv.key {
            // reveal key
            builder.commit_recv(&kv.key.to_range_set())?;
          }
        }
      },
      JsonValue::Array(ref v) => {
        // reveal array without elements
        builder.commit_recv(&v.without_values())?;
      },
      _ => {},
    };
    let key_span = content_value.get(key.as_str());
    match key_span {
      Some(key_span) => {
        content_value = key_span.clone();
      },
      None =>
        return Err(errors::ClientErrors::Other(format!("Key {} not found in response body", key))),
    }
  }

  dbg!(&content_value);
  builder.commit_recv(&content_value.to_range_set())?;
  // builder.reveal_recv(&content_value.to_range_set())?;

  prover.transcript_commit(builder.build()?);

  dbg!(&prover);
  // Request an attestation.
  let config = RequestConfig::default();
  let (attestation, secrets) = prover.finalize(&config).await?;

  let presentation = present(&Some(manifest.clone()), attestation, secrets).await?;
  Ok(presentation)
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

pub async fn present(
  manifest: &Option<Manifest>,
  attestation: Attestation,
  secrets: Secrets,
) -> Result<Presentation, errors::ClientErrors> {
  // get the manifest
  let manifest = match manifest {
    Some(manifest) => manifest,
    None => return Err(errors::ClientErrors::Other("Manifest is missing".to_string())),
  };

  // Parse the HTTP transcript.
  let transcript = HttpTranscript::parse(secrets.transcript())?;

  // Build a transcript proof.
  let mut builder = secrets.transcript_proof_builder();

  let request = &transcript.requests[0];
  // Reveal the structure of the request without the headers or body.
  builder.reveal_sent(&request.without_data())?;
  // Reveal the request target.
  builder.reveal_sent(&request.request.target)?;
  // Reveal request headers in manifetst.
  for header in &request.headers {
    if manifest.request.headers.contains_key(header.name.as_str().to_ascii_lowercase().as_str()) {
      builder.reveal_sent(header)?;
    } else {
      builder.reveal_sent(&header.without_value())?;
    }
  }

  // Reveal the response start line and headers.
  let response = &transcript.responses[0];
  builder.reveal_recv(&response.without_data())?;
  // todo: do we need to reveal target value? isn't it already done in previous line?
  for header in &response.headers {
    if manifest.response.headers.contains_key(header.name.as_str().to_ascii_lowercase().as_str()) {
      builder.reveal_recv(header)?;
    } else {
      builder.reveal_recv(&header.without_value())?;
    }
  }

  let response_body = match &response.body {
    Some(body) => body,
    None => return Err(errors::ClientErrors::Other("Response body is missing".to_string())),
  };

  let body_span = response_body.span();
  dbg!(&body_span);

  // reveal keys specified in manifest
  // reveal values specified in manifest

  let content_span = response_body.content.span();
  let initial_index = match content_span.indices().min() {
    Some(index) => index,
    None => return Err(errors::ClientErrors::Other("Content span is empty".to_string())),
  };
  dbg!(initial_index);

  let mut content_value = parse(content_span.clone().to_bytes()).unwrap();
  content_value.offset(initial_index);
  dbg!(&content_value);

  for key in manifest.response.body.json.iter() {
    let key = match key {
      JsonKey::String(s) => s.clone(),
      JsonKey::Num(n) => n.to_string(),
    };

    match content_value {
      JsonValue::Object(ref v) => {
        // reveal object without pairs
        builder.reveal_recv(&v.without_pairs())?;

        for kv in v.elems.iter() {
          if key.as_str() == kv.key {
            // reveal key
            builder.reveal_recv(&kv.key.to_range_set())?;
          }
        }
      },
      JsonValue::Array(ref v) => {
        // reveal array without elements
        builder.reveal_recv(&v.without_values())?;
      },
      _ => {},
    };
    let key_span = content_value.get(key.as_str());
    match key_span {
      Some(key_span) => {
        content_value = key_span.clone();
      },
      None =>
        return Err(errors::ClientErrors::Other(format!("Key {} not found in response body", key))),
    }
  }

  dbg!(&content_value);
  builder.reveal_recv(&content_value.to_range_set())?;

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
