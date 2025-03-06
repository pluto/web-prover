use tls_client::{
  CipherSuite, ProtocolVersion,
};
use tracing::debug;

use crate::errors::ClientErrors;

/// Every encrypted TLS packet includes [TYPE BYTES][AEAD BYTES] appended
/// to the plaintext prior to encryption. The AEAD bytes are for authentication
/// and the type byte is used to indicate the type of message (handshake, app data, etc).
pub const TLS_13_AEAD_BYTES: u8 = 16;
pub const TLS_13_TYPE_BYTES: u8 = 1;

pub fn bytes_to_ascii(bytes: Vec<u8>) -> String {
  bytes
    .iter()
    .map(|&byte| {
      match byte {
        0x0D => "\\r".to_string(),                        // CR
        0x0A => "\\n".to_string(),                        // LF
        0x09 => "\\t".to_string(),                        // Tab
        0x00..=0x1F | 0x7F => format!("\\x{:02x}", byte), // Other control characters
        _ => (byte as char).to_string(),
      }
    })
    .collect()
}
pub struct DecryptedChunk {
  plaintext: Vec<u8>,
  aad:       Vec<u8>,
}

pub fn tls_client2_default_root_store(
  additional_trust_anchors: Option<Vec<Vec<u8>>>,
) -> tls_client::RootCertStore {
  let mut root_store = tls_client::RootCertStore::empty();
  root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
      ta.subject.as_ref(),
      ta.subject_public_key_info.as_ref(),
      ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
    )
  }));

  if let Some(trust_anchors) = additional_trust_anchors {
    for trust_anchor in trust_anchors.iter() {
      let certificate = pki_types::CertificateDer::from(trust_anchor.clone());
      let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
      assert_eq!(added, 1); // TODO there is probably a better way
    }
  }

  root_store
}

#[cfg(not(target_arch = "wasm32"))]
pub fn rustls_default_root_store(
  additional_trust_anchors: Option<Vec<Vec<u8>>>,
) -> rustls::RootCertStore {
  let mut root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.into() };

  if let Some(trust_anchors) = additional_trust_anchors {
    for trust_anchor in trust_anchors.iter() {
      let certificate = pki_types::CertificateDer::from(trust_anchor.clone());
      root_store.add(certificate).unwrap();
    }
  }

  root_store
}


#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod unsafe_tls {
  use std::sync::Arc;

  #[derive(Debug)]
  pub struct SkipServerVerification {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
  }

  impl SkipServerVerification {
    pub fn new() -> std::sync::Arc<Self> {
      std::sync::Arc::new(Self {
        supported_algs: Arc::new(rustls::crypto::CryptoProvider::get_default().unwrap())
          .clone()
          .signature_verification_algorithms,
      })
    }
  }

  impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
      &self,
      _end_entity: &pki_types::CertificateDer<'_>,
      _intermediates: &[pki_types::CertificateDer<'_>],
      _server_name: &pki_types::ServerName<'_>,
      _ocsp_response: &[u8],
      _now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
      Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
      &self,
      _message: &[u8],
      _cert: &pki_types::CertificateDer<'_>,
      _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
      &self,
      _message: &[u8],
      _cert: &pki_types::CertificateDer<'_>,
      _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      self.supported_algs.supported_schemes()
    }
  }
}
