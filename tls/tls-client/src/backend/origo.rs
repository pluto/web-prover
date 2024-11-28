use std::{collections::HashMap, fmt};

use indexmap::IndexMap;
use serde::Serialize;
use strum_macros::Display;
use tls_core::msgs::enums::ContentType;
// Use tls_parser types for convenient display methods
use tls_parser::{TlsHandshakeType, TlsRecordType};

// TODO: Remove this crate and integrate into the client crate & change to crate visibility.

#[derive(Debug, Clone)]
/// TLS transcript message encryption inputs used to decrypt the ciphertext
pub struct DecryptTarget {
  /// AES IV
  pub aead_iv:     Vec<u8>,
  /// AES key
  pub aead_key:    Vec<u8>,
  /// multipe ciphertext chunks each with its own authentication tag
  pub ciphertext: Vec<String>,
}

/// Client's request and Server's response decryption target for a TLS transcript
#[derive(Debug, Clone)]
pub struct WitnessData {
  /// TLS request
  pub request:  DecryptTarget,
  /// TLS response
  pub response: DecryptTarget,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordMeta {
  pub additional_data: String,
  pub payload:         String,
  pub ciphertext:      String,
  pub nonce:           String,
}

impl RecordMeta {
  pub fn new(additional_data: &[u8], payload: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Self {
    Self {
      additional_data: hex::encode(additional_data),
      payload:         hex::encode(payload),
      ciphertext:      hex::encode(ciphertext),
      nonce:           hex::encode(nonce),
    }
  }
}

#[derive(Display, Clone, PartialEq, Eq, Debug)]
pub enum Direction {
  Sent,
  Received,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordKey {
  direction:      Direction,
  content_type:   TlsRecordType,
  handshake_type: Option<TlsHandshakeType>,
  seq:            u64,
}

impl RecordKey {
  pub fn new(d: Direction, ct: ContentType, seq: u64, first_byte: u8) -> Self {
    let hst = if ct == ContentType::Handshake { Some(TlsHandshakeType(first_byte)) } else { None };

    Self { direction: d, content_type: TlsRecordType(ct.get_u8()), handshake_type: hst, seq }
  }
}

impl fmt::Display for RecordKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let handshake_str = match self.handshake_type {
      Some(hs) => hs.to_string(),
      None => "none".to_string(),
    };

    write!(f, "{}.{}.{}.{}", self.direction, self.content_type, handshake_str, self.seq)
  }
}

#[derive(Clone, Default)]
pub struct OrigoConnection {
  pub secret_map: HashMap<String, Vec<u8>>,
  pub record_map: IndexMap<String, RecordMeta>,
}

impl OrigoConnection {
  pub fn new() -> Self { Self::default() }

  pub fn insert_record(&mut self, record_key: RecordKey, record_meta: RecordMeta) {
    self.record_map.insert(record_key.to_string(), record_meta);
  }

  pub fn set_secret(&mut self, name: String, val: Vec<u8>) {
    println!("set_secret: name={}, val={:?}", name, hex::encode(val.clone()));
    self.secret_map.insert(name, val);
  }

  /// TODO: Clean up the secret map keying.
  /// Takes the [`OrigoConnection`] secrets map containing TLS transcript messages and extracts
  /// request and response decryption targets into [`WitnessData`]
  pub fn to_witness_data(&mut self) -> WitnessData {
    let req_key = RecordKey::new(Direction::Sent, ContentType::ApplicationData, 0, 0u8).to_string();

    // loop through all ciphertext chunks and append
    let mut num_ciphertext_chunks = 1;
    let mut ciphertext_chunks = vec![];

    // get response key
    let mut resp_key =
      RecordKey::new(Direction::Received, ContentType::ApplicationData, num_ciphertext_chunks, 0u8)
        .to_string();

    // get all ciphertext chunks sent by the server
    while let Some(record) = self.record_map.get(&resp_key) {
      num_ciphertext_chunks += 1;
      ciphertext_chunks.push(record.ciphertext.clone());
      resp_key = RecordKey::new(
        Direction::Received,
        ContentType::ApplicationData,
        num_ciphertext_chunks,
        0u8,
      )
      .to_string();
    }

    WitnessData {
      request:  DecryptTarget {
        aead_iv:     self.secret_map.get("Application:client_iv").unwrap().to_vec(),
        aead_key:    self.secret_map.get("Application:client_key").unwrap().to_vec(),
        ciphertext: vec![self.record_map.get(&req_key).unwrap().ciphertext.clone()],
      },
      response: DecryptTarget {
        aead_iv:     self.secret_map.get("Application:server_iv").unwrap().to_vec(),
        aead_key:    self.secret_map.get("Application:server_key").unwrap().to_vec(),
        ciphertext: ciphertext_chunks,
      },
    }
  }
}
