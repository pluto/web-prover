// logic common to wasm32 and native

use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use serde::{Deserialize, Serialize};
use spansy::{
  http::Response,
  json::{parse, JsonValue},
  Spanned,
};
pub use tlsn_core::attestation::Attestation;
use tlsn_core::{
  presentation::Presentation, request::RequestConfig, transcript::TranscriptCommitConfig,
  CryptoProvider, Secrets,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{state::Closed, Prover};
use tracing::debug;
use utils::range::{RangeSet, ToRangeSet};
use web_proof_circuits_witness_generator::json::JsonKey;
use web_prover_core::manifest::Manifest;

use crate::{errors, SignedVerificationReply};

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsnProof {
  pub proof:      Presentation,
  pub sign_reply: Option<SignedVerificationReply>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsnVerifyBody {
  pub proof:    Presentation,
  pub manifest: Manifest,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

/// compute range set for masking based on json path from manifest
/// # Arguments
/// - `response`: response from the server
/// - `keys`: json path from manifest
/// # Returns
/// - range set for masking
/// # Errors
/// - if response body is missing
/// - if content span is empty
/// - if key is not found in response body
fn compute_json_mask_range_set(
  response: &Response,
  keys: &[JsonKey],
) -> Result<Vec<RangeSet<usize>>, errors::ClientErrors> {
  let response_body = match &response.body {
    Some(body) => body,
    None => return Err(errors::ClientErrors::Other("Response body is missing".to_string())),
  };

  // commit to keys specified in manifest
  // commit values specified in manifest

  let content_span = response_body.content.span();
  let initial_index = match content_span.indices().min() {
    Some(index) => index,
    None => return Err(errors::ClientErrors::Other("Content span is empty".to_string())),
  };

  let mut content_value = parse(content_span.clone().to_bytes())?;
  content_value.offset(initial_index);

  let mut range_sets = Vec::new();
  for key in keys {
    let key = match key {
      JsonKey::String(s) => s.clone(),
      JsonKey::Num(n) => n.to_string(),
    };

    match content_value {
      JsonValue::Object(ref v) =>
        for kv in v.elems.iter() {
          if key.as_str() == kv.key {
            range_sets.push(kv.key.to_range_set());
          }
        },
      JsonValue::Array(ref v) => {
        range_sets.push(v.without_values());
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
  range_sets.push(content_value.to_range_set());
  Ok(range_sets)
}

pub async fn notarize(
  prover: Prover<Closed>,
  manifest: &Manifest,
) -> Result<Presentation, errors::ClientErrors> {
  let mut prover = prover.start_notarize();
  let transcript = HttpTranscript::parse(prover.transcript())?;

  // Commit to the transcript.
  let mut builder = TranscriptCommitConfig::builder(prover.transcript());
  DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

  let range_sets =
    compute_json_mask_range_set(&transcript.responses[0], &manifest.response.body.json_path())?;
  for range_set in range_sets.iter() {
    builder.commit_recv(range_set)?;
  }

  prover.transcript_commit(builder.build()?);

  // Request an attestation.
  let config = RequestConfig::default();
  let (attestation, secrets) = prover.finalize(&config).await?;

  let presentation = present(&Some(manifest.clone()), attestation, secrets, &range_sets).await?;
  Ok(presentation)
}

pub async fn present(
  manifest: &Option<Manifest>,
  attestation: Attestation,
  secrets: Secrets,
  json_mask_range_set: &[RangeSet<usize>],
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

  for range_set in json_mask_range_set {
    builder.reveal_recv(range_set)?;
  }

  let transcript_proof = builder.build()?;

  // Use default crypto provider to build the presentation.
  let provider = CryptoProvider::default();

  let mut builder = attestation.presentation_builder(&provider);

  builder.identity_proof(secrets.identity_proof()).transcript_proof(transcript_proof);

  let presentation: Presentation = builder.build()?;

  Ok(presentation)
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
