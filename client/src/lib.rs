#[cfg(not(target_arch = "wasm32"))] mod prover;
#[cfg(target_arch = "wasm32")] mod prover_wasm32;

pub mod config;
pub mod errors;

use config::ClientType;
use hyper::Request;
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
  // copied from https://github.com/tlsnotary/tlsn/blob/3554db83e17b2e5fc98293b397a2907b7f023496/tlsn/examples/simple/simple_prover.rs#L145C1-L169C2
  let mut prover = prover.start_notarize();

  let sent_len = prover.sent_transcript().data().len();
  let recv_len = prover.recv_transcript().data().len();

  let builder = prover.commitment_builder();
  let sent_commitment = builder.commit_sent(&(0..sent_len)).unwrap();
  let recv_commitment = builder.commit_recv(&(0..recv_len)).unwrap();

  let notarized_session = prover.finalize().await.unwrap();

  let mut proof_builder = notarized_session.data().build_substrings_proof();

  proof_builder.reveal_by_id(sent_commitment).unwrap();
  proof_builder.reveal_by_id(recv_commitment).unwrap();

  let substrings_proof = proof_builder.build().unwrap();

  Ok(TlsProof { session: notarized_session.session_proof(), substrings: substrings_proof })
}

async fn send_request(
  mut request_sender: hyper::client::conn::SendRequest<hyper::Body>,
  request: Request<hyper::Body>,
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

async fn body_to_string(res: hyper::Response<hyper::Body>) -> String {
  let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap(); // TODO fix unwrap
  String::from_utf8(body_bytes.to_vec()).unwrap()
}
