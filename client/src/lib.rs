#[cfg(not(target_arch = "wasm32"))] mod prover;
#[cfg(target_arch = "wasm32")] mod prover_wasm32;

pub mod config;
pub mod errors;

use config::ClientType;
use hyper::Request;
use tlsn_core::commitment::CommitmentKind;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::Closed, Prover, ProverConfig};
use tracing::{debug, info};

pub async fn prover_inner(mut config: config::Config) -> Result<TlsProof, errors::ClientErrors> {
  info!("GIT_HASH: {}", env!("GIT_HASH"));

  let root_store = default_root_store();

  let prover_config = ProverConfig::builder()
    .id(config.session_id())
    .root_cert_store(root_store)
    .server_dns(config.target_host())
    .max_transcript_size(
      config.notarization_session_request.max_sent_data.unwrap()
        + config.notarization_session_request.max_recv_data.unwrap(),
    )
    .build()
    .unwrap();

  #[cfg(target_arch = "wasm32")]
  let prover = prover_wasm32::setup_connection(&mut config, prover_config).await;

  #[cfg(not(target_arch = "wasm32"))]
  let prover = match config.notarization_session_request.client_type {
    ClientType::Tcp => prover::setup_tcp_connection(&mut config, prover_config).await,
    ClientType::Websocket => prover::setup_websocket_connection(&mut config, prover_config).await,
  };

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
  request: Request<hyper::Body>,
) {
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

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

// TODO default_root_store is duplicated in prover.rs because of
// tls_client::RootCertStore vs rustls::RootCertStore

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
