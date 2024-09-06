// logic common to wasm32 and native

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use tlsn_core::proof::SessionProof;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::Closed, Prover};
use tracing::{debug, info};

use crate::errors;

pub async fn notarize(prover: Prover<Closed>) -> Result<TlsProof, errors::ClientErrors> {
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

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

pub async fn verify(proof: TlsProof, notary_pubkey_str: &str) -> VerifyResult {
  let TlsProof {
    // The session proof establishes the identity of the server and the commitments
    // to the TLS transcript.
    session,
    // The substrings proof proves select portions of the transcript, while redacting
    // anything the Prover chose not to disclose.
    substrings,
  } = proof;

  session.verify_with_default_cert_verifier(get_notary_pubkey(notary_pubkey_str)).unwrap();

  let SessionProof { header, session_info, .. } = session;

  let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

  let (mut sent, mut recv) = substrings.verify(&header).unwrap();

  sent.set_redacted(b'X');
  recv.set_redacted(b'X');

  debug!(
    "Successfully verified that the bytes below came from a session with {:?} at {}.",
    session_info.server_name, time
  );
  debug!("Note that the bytes which the Prover chose not to disclose are shown as X.");
  debug!("Bytes sent:");
  debug!("{}", String::from_utf8(sent.data().to_vec()).unwrap());
  debug!("Bytes received:");
  debug!("{}", String::from_utf8(recv.data().to_vec()).unwrap());

  VerifyResult {
    server_name: String::from(session_info.server_name.as_str()),
    time:        header.time(),
    sent:        String::from_utf8(sent.data().to_vec()).unwrap(),
    recv:        String::from_utf8(recv.data().to_vec()).unwrap(),
  }
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

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

// TODO default_root_store is duplicated in prover.rs because of
// tls_client::RootCertStore vs rustls::RootCertStore

/// Default root store using mozilla certs.
pub fn default_root_store() -> tls_client::RootCertStore {
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

async fn body_to_string(res: hyper::Response<hyper::body::Incoming>) -> String {
  let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
  String::from_utf8(body_bytes.to_vec()).unwrap()
}

fn get_notary_pubkey(pubkey: &str) -> p256::PublicKey {
  p256::PublicKey::from_public_key_pem(pubkey).unwrap()
}
