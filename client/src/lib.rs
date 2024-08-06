#[cfg(not(target_arch = "wasm32"))] mod prover;
#[cfg(not(target_arch = "wasm32"))]
use prover::setup_connection;

#[cfg(target_arch = "wasm32")] mod prover_wasm32;
#[cfg(target_arch = "wasm32")]
use prover_wasm32::setup_connection;

pub mod errors;

use std::collections::HashMap;

use base64::prelude::*;
use http_body_util::Full;
// use hyper::{body::Bytes, client::conn::http1::SendRequest, Request};
use hyper::{body::Bytes, Request};
use serde::{Deserialize, Serialize};
use tlsn_core::commitment::CommitmentKind;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::Closed, Prover, ProverConfig};
use tracing::{debug, info, trace};
use url::Url;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub notary_host:                  String,
  pub notary_port:                  u16,
  pub target_method:                String,
  pub target_url:                   String,
  pub target_headers:               HashMap<String, String>,
  pub target_body:                  String,
  #[cfg(feature = "websocket")]
  pub websocket_proxy_url:          String,
  pub notarization_session_request: NotarizationSessionRequest, /* TODO rename to something
                                                                 * better */

  #[serde(skip)]
  session_id: String,
}

impl Config {
  fn session_id(&mut self) -> String {
    if self.session_id.is_empty() {
      self.session_id = uuid::Uuid::new_v4().to_string();
    }
    self.session_id.clone()
  }

  fn target_host(&self) -> String {
    let target_url = Url::parse(&self.target_url).unwrap();
    target_url.host_str().unwrap().to_string()
  }

  fn target_port(&self) -> u16 {
    let target_url = Url::parse(&self.target_url).unwrap();
    target_url.port_or_known_default().unwrap()
  }

  fn target_is_https(&self) -> bool {
    let target_url = Url::parse(&self.target_url).unwrap();
    target_url.scheme() == "https"
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizationSessionRequest {
  pub client_type:   ClientType, // TODO depends on feature = websocket
  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
  /// Client that has access to the transport layer
  Tcp,
  /// Client that cannot directly access transport layer, e.g. browser extension
  Websocket,
}

pub async fn prover_inner(mut config: Config) -> Result<TlsProof, errors::ClientErrors> {
  //   let target_url = Url::parse(&config.target_url)?;
  //   info!("target: {}", target_url);
  //   let target_host = target_url.host_str().expect("Invalid `target_url` host!");
  //   assert!(target_url.scheme() == "https");
  //   let target_port = target_url.port_or_known_default().expect("Target has an unknown port!");

  //   let session_id = uuid::Uuid::new_v4().to_string();
  //   info!("session_id: {}", session_id);

  // TODO lot of memory allocation happening here.
  // maybe add this to shared state?
  //   let root_store = default_root_store();

  //   let mut prover_config = ProverConfig::builder();
  //   prover_config.id(session_id.clone()).server_dns(target_host).root_cert_store(root_store);
  //   prover_config.max_transcript_size(
  //     config.notarization_session_request.max_sent_data.unwrap()
  //       + config.notarization_session_request.max_recv_data.unwrap(),
  //   ); // TODO unwrap
  //   let prover_config = prover_config.build()?;

  //   let request = build_request(
  //     config.target_method,
  //     config.target_url,
  //     config.target_headers,
  //     config.target_body,
  //   );

  // setup_connection is based on arch (wasm32 vs non-wasm)
  let prover = setup_connection(&mut config).await;
  notarize(prover).await
}

async fn notarize(prover: Prover<Closed>) -> Result<TlsProof, errors::ClientErrors> {
  let mut prover = prover.to_http()?.start_notarize();

  // TODO: unwrap for now as we need to bring in `tlsn_formats`
  // Commit to the transcript with the default committer, which will commit using BLAKE3.
  prover.commit().unwrap();

  let notarized_session = prover.finalize().await?;

  debug!("Notarization complete");

  let session_proof = notarized_session.session_proof();

  let mut proof_builder = notarized_session.session().data().build_substrings_proof();

  // Prove the request, while redacting the secrets from it.
  let request = &notarized_session.transcript().requests[0];

  proof_builder.reveal_sent(&request.without_data(), CommitmentKind::Blake3)?;

  proof_builder.reveal_sent(&request.request.target, CommitmentKind::Blake3)?;

  for header in &request.headers {
    // Only reveal the host header
    if header.name.as_str().eq_ignore_ascii_case("Host") {
      proof_builder.reveal_sent(header, CommitmentKind::Blake3)?;
    } else {
      proof_builder.reveal_sent(&header.without_value(), CommitmentKind::Blake3)?;
    }
  }

  // Prove the entire response, as we don't need to redact anything
  let response = &notarized_session.transcript().responses[0];

  proof_builder.reveal_recv(response, CommitmentKind::Blake3)?;

  // Build the proof
  let substrings_proof = proof_builder.build()?;

  Ok(TlsProof { session: session_proof, substrings: substrings_proof })
}

async fn send_request(
  mut request_sender: hyper::client::conn::SendRequest<hyper::Body>,
  method: String,
  url: String,
  headers: HashMap<String, String>,
  body: String,
) {
  let request = build_request(method, url, headers, body);

  // TODO: Clean up this logging and error handling
  match request_sender.send_request(request).await {
    Ok(response) => {
      let status = response.status();
      let _payload = response.into_body();
      debug!("Response:\n{:?}", _payload);
      debug!("Response Status:\n{:?}", status);
      assert!(status.is_success()); // status is 200-299
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO */
    Err(e) => panic!("{:?}", e),
  };
}

fn build_request(
  method: String,
  url: String,
  headers: HashMap<String, String>,
  body: String,
) -> Request<hyper::Body> {
  let u = Url::parse(&url).unwrap();
  let target_host = u.host_str().expect("Invalid `target_url` host!");
  assert!(u.scheme() == "https");

  let mut request = Request::builder().method(method.as_str()).uri(url);

  // The following `unwrap()` should be safe since we just created the `Request` above
  let h = request.headers_mut().unwrap();
  // TODO: This could be a source of error as the mapping now just holds a single string, so I will
  // leave commented out code here.
  for (key, value) in headers {
    //   for (key, values) in config.target_headers {
    // for value in values {
    //   headers.append(
    //     hyper::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
    //     value.parse().unwrap(),
    //   );
    // }
    h.append(
      hyper::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
      value.parse().unwrap(),
    );
  }

  h.insert("Host", target_host.parse().unwrap());
  // Using "identity" instructs the Server not to use compression for its HTTP response.
  // TLSNotary tooling does not support compression.
  h.insert("Accept-Encoding", "identity".parse().unwrap());
  h.insert("Connection", "close".parse().unwrap());

  if h.get("Accept").is_none() {
    h.insert("Accept", "*/*".parse().unwrap());
  }

  let body = if body.is_empty() {
    hyper::Body::empty()
    // Full::new(Bytes::from(vec![])) // TODO Empty::<Bytes>::new()
  } else {
    hyper::Body::from(BASE64_STANDARD.decode(body).unwrap())
    // Full::new(Bytes::from(BASE64_STANDARD.decode(body).unwrap()))
  };

  request.body(body).unwrap()
}

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

/// Default root store using mozilla certs.
fn default_root_store() -> tls_client::RootCertStore {
  let mut root_store = tls_client::RootCertStore::empty();
  root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
      ta.subject.as_ref(),
      ta.subject_public_key_info.as_ref(),
      ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
    )
  }));

  #[cfg(feature = "notary_ca_cert")]
  {
    debug!("notary_ca_cert feature enabled");
    let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
    let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
    assert_eq!(added, 1); // TODO there is probably a better way
  }

  root_store
}
