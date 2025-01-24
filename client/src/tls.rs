// TODO many root_stores ... this could use some cleanup where possible
use proofs::program::manifest::{EncryptionInput, TLSEncryption};
use tls_client2::{origo::WitnessData, CipherSuite, CipherSuiteKey, Decrypter, ProtocolVersion};
use tls_core::msgs::{base::Payload, enums::ContentType, message::OpaqueMessage};
use tracing::{debug, trace};

use crate::errors::ClientErrors;

#[cfg(feature = "notary_ca_cert")]
pub const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

pub fn tls_client2_default_root_store() -> tls_client2::RootCertStore {
  let mut root_store = tls_client2::RootCertStore::empty();
  root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    tls_client2::OwnedTrustAnchor::from_subject_spki_name_constraints(
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

#[cfg(not(target_arch = "wasm32"))]
pub fn rustls_default_root_store() -> rustls::RootCertStore {
  let mut root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.into() };

  #[cfg(feature = "notary_ca_cert")]
  {
    debug!("notary_ca_cert feature enabled");
    let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
    root_store.add(certificate).unwrap();
  }

  root_store
}

pub fn tls_client_default_root_store() -> tls_client::RootCertStore {
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

/// Decrypt plaintext from TLS transcript ciphertext using [`WitnessData`]
pub(crate) fn decrypt_tls_ciphertext(witness: &WitnessData) -> Result<TLSEncryption, ClientErrors> {
  // - get AES key, IV, request ciphertext, request plaintext, and AAD -
  let key = parse_cipher_key(&witness.request.aead_key)?;
  let iv: [u8; 12] = witness.request.aead_iv[..12].try_into()?;

  // Get the request ciphertext, request plaintext, and AAD
  let request_ciphertext = hex::decode(witness.request.ciphertext[0].as_bytes())?;

  let (plaintext, meta) = match key {
    CipherSuiteKey::AES128GCM(_) => {
      debug!("Decrypting AES");
      let request_decrypter =
        Decrypter::new(key.clone(), iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
      request_decrypter.decrypt_tls13_aes(
        &OpaqueMessage {
          typ:     ContentType::ApplicationData,
          version: ProtocolVersion::TLSv1_3,
          payload: Payload::new(request_ciphertext.clone()),
        },
        0,
      )?
    },
    CipherSuiteKey::CHACHA20POLY1305(_) => {
      debug!("Decrypting Chacha");
      let request_decrypter =
        Decrypter::new(key.clone(), iv, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
      request_decrypter.decrypt_tls13_chacha20(
        &OpaqueMessage {
          typ:     ContentType::ApplicationData,
          version: ProtocolVersion::TLSv1_3,
          payload: Payload::new(request_ciphertext.clone()),
        },
        0,
      )?
    },
  };

  let aad = hex::decode(&meta.additional_data)?;
  let mut padded_aad = vec![0; 16 - aad.len()];
  padded_aad.extend(aad);

  let request_plaintext = plaintext.payload.0.to_vec();
  let request_ciphertext = request_ciphertext[..request_plaintext.len()].to_vec();
  assert_eq!(request_plaintext.len(), request_ciphertext.len());
  trace!("Raw request plaintext: {:?}", request_plaintext);

  // ----------------------------------------------------------------------------------------------------------------------- //
  // response preparation
  let mut response_plaintext = vec![];
  let mut response_ciphertext = vec![];
  let response_key = parse_cipher_key(&witness.response.aead_key)?;
  let response_iv: [u8; 12] = witness.response.aead_iv[..12].try_into().unwrap();
  for (i, ct_chunk) in witness.response.ciphertext.iter().enumerate() {
    let ct_chunk = hex::decode(ct_chunk)?;

    // decrypt ciphertext
    let (plaintext, meta) = match response_key {
      CipherSuiteKey::AES128GCM(_) => {
        debug!("Decrypting AES");
        let response_dec =
          Decrypter::new(response_key.clone(), response_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
        response_dec.decrypt_tls13_aes(
          &OpaqueMessage {
            typ:     ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(ct_chunk.clone()), /* TODO(WJ 2024-11-23): can we remove this
                                                      * clone */
          },
          (i + 1) as u64,
        )?
      },
      CipherSuiteKey::CHACHA20POLY1305(_) => {
        debug!("Decrypting Chacha");
        let response_dec = Decrypter::new(
          response_key.clone(),
          response_iv,
          CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        );
        response_dec.decrypt_tls13_chacha20(
          &OpaqueMessage {
            typ:     ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(ct_chunk.clone()), /* TODO(WJ 2024-11-23): can we remove this
                                                      * clone */
          },
          (i + 1) as u64,
        )?
      },
    };

    // push ciphertext
    let pt = plaintext.payload.0.to_vec();

    // TODO (tracy): This appears to always trims 17 bytes. Trimming 16 bytes
    // would mean we trim the AEAD. It seems to be a bug to trim this number of bytes.
    // For now, we replicate the logic in the notary so it verifies.
    response_ciphertext.extend_from_slice(&ct_chunk[..pt.len()]);

    response_plaintext.extend(pt);
    let aad = hex::decode(&meta.additional_data)?;
    let mut padded_aad = vec![0; 16 - aad.len()];
    padded_aad.extend(&aad);
  }

  assert_eq!(response_plaintext.len(), response_ciphertext.len());

  Ok(TLSEncryption {
    request:  EncryptionInput {
      key,
      iv,
      aad: padded_aad.clone(),
      plaintext: request_plaintext,
      ciphertext: request_ciphertext,
    },
    response: EncryptionInput {
      key:        response_key,
      iv:         response_iv,
      aad:        padded_aad, // TODO: use response's AAD
      plaintext:  response_plaintext,
      ciphertext: response_ciphertext,
    },
  })
}

fn parse_cipher_key(key: &[u8]) -> Result<CipherSuiteKey, ClientErrors> {
  match key.len() {
    32 => Ok(CipherSuiteKey::CHACHA20POLY1305(
      key[..32].try_into().map_err(|_| ClientErrors::TlsCrypto("Conversion Error".to_owned()))?,
    )),
    16 => Ok(CipherSuiteKey::AES128GCM(
      key[..16].try_into().map_err(|_| ClientErrors::TlsCrypto("Conversion Error".to_owned()))?,
    )),
    len => Err(ClientErrors::TlsCrypto(format!("Unsupported key length: {}", len))),
  }
}

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
