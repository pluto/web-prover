// TODO many root_stores ... this could use some cleanup where possible
use proofs::program::manifest::{EncryptionInput, TLSEncryption};
use reqwest::Client;
use tls_client2::{origo::WitnessData, CipherSuite, CipherSuiteKey, Decrypter, ProtocolVersion};
use tls_core::msgs::{base::Payload, enums::ContentType, message::OpaqueMessage};
use tracing::debug;

use crate::errors::ClientErrors;

#[cfg(feature = "notary_ca_cert")]
pub const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

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
  // Request Preparation
  let request_key = parse_cipher_key(&witness.request.aead_key)?;
  let request_iv: [u8; 12] = witness.request.aead_iv[..12].try_into()?;
  let request_seq = 0;
  let request_ct = hex::decode(witness.request.ciphertext[0].as_bytes())?;
  let request_pt = decrypt_chunk(&request_ct, &request_key, request_iv, request_seq)?;
  let trim_bytes: usize = (TLS_13_TYPE_BYTES + TLS_13_AEAD_BYTES) as usize;

  let mut padded_aad = vec![0; 16 - request_pt.aad.len()];
  padded_aad.extend(request_pt.aad);

  // DEBUG: Use this test case to pin the ciphertext, you must also update
  // `src/notary/origo.rs#verify`.
  //
  // let request_key = parse_cipher_key(&hex::decode(
  //   "49d52462989030aabf9c70242ef16cfcc9ce9749758c300e5c13bf41a17f1ba7"
  // ).unwrap())?;
  // let request_iv = hex::decode("1559fbbbd08e54857be8b72c").unwrap().try_into().unwrap();
  // let request_ct = &hex::decode(concat!(
  //   "d5dd2f2e3cc0fd4983f9c09c45912ca0ede814fe87f00edcf23c259d0a71d19b",
  //   "ffe2d4de8b089c321023a30ff35fc68f8904bb67335af7725224aa2e86d9d9d1",
  //   "ef06bb1fd4f961a8a46df95bc9076e208ec836cd6515c5345d6104634a2e9eea",
  //   "2e37ec58187554eb28af9ee3f7d1ee2dfd770542e6f93ed797970a0050756969",
  //   "fc4b2695e37ec18e89e8dd86514974a77042e93e770648feaca06584b28be339",
  //   "5894c8d34bd44f7c68d66d845187334123040ca055616113df006eee1a9bc879",
  //   "28ad1f7ad53c7b24b6c8018f58bf6c36ba36b4a026017459897881f7ec5a6a29",
  //   "e58c28dd86ab585bebd54c546ba0195f567306aa2ad8eaa4a6cfe815fadfd883",
  //   "2c7db2"
  // )).unwrap();

  // TODO (Sambhav): might have to apply similar multi-packet logic for request as well
  // for now, only support a single request chunk.
  let request_plaintext = vec![request_pt.plaintext];
  let request_ciphertext = vec![request_ct[..request_plaintext[0].len()].to_vec()];
  assert_eq!(request_plaintext[0].len(), request_ciphertext[0].len());
  debug!("TLS_DECRYPT (request): plaintext={:?}", bytes_to_ascii(request_plaintext[0].clone()));
  debug!("TLS_DECRYPT (request): ciphertext={:?}", hex::encode(request_ciphertext[0].clone()));
  debug!(
    "TLS_DECRYPT (request): trimmed_bytes={:?}",
    hex::encode(&request_ciphertext[0].clone()[request_ciphertext[0].len() - trim_bytes..])
  );

  // Response Preparation
  let response_key = parse_cipher_key(&witness.response.aead_key)?;
  let response_iv: [u8; 12] = witness.response.aead_iv[..12].try_into().unwrap();
  let response_seq = request_seq + request_plaintext.len() as u64;
  let (response_ciphertext, response_plaintext): (Vec<_>, Vec<_>) = witness
    .response
    .ciphertext
    .iter()
    .enumerate()
    .map(|(i, ct_chunk)| {
      let ct_chunk = hex::decode(ct_chunk)?;
      let pt_chunk = decrypt_chunk(&ct_chunk, &response_key, response_iv, i as u64 + response_seq)?;

      debug!(
        "TLS_DECRYPT (response, chunk={:?}): plaintext={:?}",
        i,
        bytes_to_ascii(pt_chunk.plaintext.clone())
      );
      debug!(
        "TLS_DECRYPT (response, chunk={:?}): ciphertext={:?}",
        i,
        hex::encode(ct_chunk.clone())
      );
      debug!(
        "TLS_DECRYPT (response, chunk={:?}): trimmed_bytes={:?}",
        i,
        hex::encode(&ct_chunk.clone()[ct_chunk.len() - trim_bytes..])
      );

      Ok::<(Vec<u8>, Vec<u8>), ClientErrors>((
        ct_chunk[..pt_chunk.plaintext.len()].to_vec(),
        pt_chunk.plaintext,
      ))
    })
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .unzip();

  Ok(TLSEncryption {
    request:  EncryptionInput {
      key:        request_key,
      iv:         request_iv,
      aad:        padded_aad.clone(),
      plaintext:  request_plaintext,
      ciphertext: request_ciphertext,
      seq:        request_seq,
    },
    response: EncryptionInput {
      key:        response_key,
      iv:         response_iv,
      aad:        padded_aad, // TODO: use response's AAD
      plaintext:  response_plaintext,
      ciphertext: response_ciphertext,
      seq:        response_seq,
    },
  })
}

fn decrypt_chunk(
  ciphertext: &Vec<u8>,
  key: &CipherSuiteKey,
  iv: [u8; 12],
  sequence_number: u64,
) -> Result<DecryptedChunk, ClientErrors> {
  let (decrypted_message, meta) = match key {
    CipherSuiteKey::AES128GCM(_) => {
      let decrypter = Decrypter::new(key.clone(), iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
      decrypter.decrypt_tls13_aes(
        &OpaqueMessage {
          typ:     ContentType::ApplicationData,
          version: ProtocolVersion::TLSv1_3,
          payload: Payload::new(ciphertext.clone()),
        },
        sequence_number,
      )?
    },
    CipherSuiteKey::CHACHA20POLY1305(_) => {
      let decrypter = Decrypter::new(key.clone(), iv, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
      decrypter.decrypt_tls13_chacha20(
        &OpaqueMessage {
          typ:     ContentType::ApplicationData,
          version: ProtocolVersion::TLSv1_3,
          payload: Payload::new(ciphertext.clone()),
        },
        sequence_number,
      )?
    },
  };

  return Ok(DecryptedChunk {
    plaintext: decrypted_message.payload.0.to_vec(),
    aad:       hex::decode(&meta.additional_data)?,
  });
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
