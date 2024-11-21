// TODO many root_stores ... this could use some cleanup where possible
use proofs::program::manifest::AESEncryptionInput;
use tls_client2::{origo::WitnessData, CipherSuite, Decrypter2, EncryptionKey, ProtocolVersion};
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
  let mut root_store = rustls::RootCertStore::empty();
  root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
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
pub(crate) fn decrypt_tls_ciphertext(
  witness: &WitnessData,
) -> Result<(AESEncryptionInput, AESEncryptionInput), ClientErrors> {
  // - get AES key, IV, request ciphertext, request plaintext, and AAD -
  let (key, cipher_suite) = match witness.request.aes_key.len() {
    // chacha has 32 byte keys
    32 => (
      EncryptionKey::CHACHA20POLY1305(witness.request.aes_key[..32].try_into()?),
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ),
    // aes has 16 byte keys
    16 => (
      EncryptionKey::AES128GCM(witness.request.aes_key[..16].try_into()?),
      CipherSuite::TLS13_AES_128_GCM_SHA256,
    ),
    _ => panic!("Unsupported key length"),
  };
  let iv: [u8; 12] = witness.request.aes_iv[..12].try_into()?;

  // Get the request ciphertext, request plaintext, and AAD
  let request_ciphertext = hex::decode(witness.request.ciphertext[0].as_bytes())?;

  let request_decrypter =
    Decrypter2::new(EncryptionKey::AES128GCM(key), iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = request_decrypter.decrypt_tls13_aes(
    &OpaqueMessage {
      typ:     ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_3,
      payload: Payload::new(request_ciphertext.clone()), /* TODO (autoparallel): old way didn't
                                                          * introduce a clone */
    },
    0,
  )?;

  let aad = hex::decode(meta.additional_data.to_owned())?;
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
  let (key, cipher_suite) = match witness.request.aes_key.len() {
    // chacha has 32 byte keys
    32 => (
      EncryptionKey::CHACHA20POLY1305(witness.request.aes_key[..32].try_into()?),
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ),
    // aes has 16 byte keys
    16 => (
      EncryptionKey::AES128GCM(witness.request.aes_key[..16].try_into()?),
      CipherSuite::TLS13_AES_128_GCM_SHA256,
    ),
    _ => panic!("Unsupported key length"),
  };
  let response_iv: [u8; 12] = witness.response.aes_iv[..12].try_into().unwrap();
  let response_dec =
    Decrypter2::new(response_key, response_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);

  for (i, ct_chunk) in witness.response.ciphertext.iter().enumerate() {
    let ct_chunk = hex::decode(ct_chunk).unwrap();

    // decrypt ciphertext
    let (plaintext, meta) = response_dec
      .decrypt_tls13_aes(
        &OpaqueMessage {
          typ:     ContentType::ApplicationData,
          version: ProtocolVersion::TLSv1_3,
          payload: Payload::new(ct_chunk.clone()),
        },
        (i + 1) as u64,
      )
      .unwrap();

    // push ciphertext
    let pt = plaintext.payload.0.to_vec();
    response_ciphertext.extend_from_slice(&ct_chunk[..pt.len()]);

    response_plaintext.extend(pt);
    let aad = hex::decode(meta.additional_data.to_owned()).unwrap();
    let mut padded_aad = vec![0; 16 - aad.len()];
    padded_aad.extend(&aad);
  }
  trace!("response plaintext: {:?}", response_plaintext);
  assert_eq!(response_plaintext.len(), response_ciphertext.len());

  let destructured_key = match key {
    EncryptionKey::AES128GCM(key) => key,
    _ => panic!("Unsupported cipher suite"),
    // EncryptionKey::CHACHA20POLY1305(key) => key,
  };

  let destructured_response_key = match response_key {
    EncryptionKey::AES128GCM(key) => key,
    _ => panic!("Unsupported cipher suite"),
    // EncryptionKey::CHACHA20POLY1305(key) => key,
  };

  Ok((
    AESEncryptionInput {
      key: destructured_key,
      iv,
      aad: padded_aad.clone(),
      plaintext: request_plaintext,
      ciphertext: request_ciphertext,
    },
    AESEncryptionInput {
      key:        destructured_response_key,
      iv:         response_iv,
      aad:        padded_aad, // TODO: use response's AAD
      plaintext:  response_plaintext,
      ciphertext: response_ciphertext,
    },
  ))
}
