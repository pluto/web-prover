use std::collections::HashMap;
use hex;
use serde::Serialize;
// Use tls_parser types for convenient display methods
use tls_parser::{TlsRecordType, TlsHandshakeType};
use tls_core::msgs::enums::ContentType;
use std::fmt;
use strum_macros::Display;
use indexmap::IndexMap;

// TODO: Remove this crate and integrate into the client crate & change to crate visibility.

#[derive(Debug, Clone)]
pub struct DecryptTarget {
  pub aes_iv: Vec<u8>,
  pub aes_key: Vec<u8>,
  pub ciphertext: String,
}
#[derive(Debug, Clone)]
pub struct WitnessData {
  pub request: DecryptTarget,
  pub response: DecryptTarget
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordMeta {
  pub additional_data: String,
  pub payload:         String,
  pub ciphertext:      String,
  pub nonce:           String,
}

impl RecordMeta {
  pub fn new(
    additional_data: &[u8],
    payload: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
  ) -> Self {
    Self {
      additional_data: hex::encode(additional_data),
      payload:         hex::encode(payload),
      ciphertext:      hex::encode(ciphertext),
      nonce:           hex::encode(nonce),
    }
  }
}

#[derive(Display, Clone, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received
}

#[derive(Clone, PartialEq, Eq)]
pub struct RecordKey {
    direction: Direction,
    content_type: TlsRecordType,
    handshake_type: Option<TlsHandshakeType>,
    seq: u64,
}

impl RecordKey {
    pub fn new(d: Direction, ct: ContentType, seq: u64, first_byte: u8) -> RecordKey {
        let hst = if ct == ContentType::Handshake {
            Some(TlsHandshakeType(first_byte))
        } else {
            None
        };
        
        return RecordKey {
            direction: d,
            content_type: TlsRecordType(ct.get_u8()),
            handshake_type: hst,
            seq
        }
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handshake_str = match self.handshake_type {
            Some(hs) => hs.to_string(),
            None => "none".to_string()
        };

        write!(f, "{}.{}.{}.{}", self.direction, self.content_type, handshake_str, self.seq)
    }
}

pub fn hex_bytes_to_string(bytes: Vec<u8>) -> String {
    bytes.iter()
          .map(|b| format!("{:02x}", b))
          .collect()
}

#[derive(Clone)]
pub struct OrigoConnection {
    pub secret_map: HashMap<String, Vec<u8>>,
    pub record_map: IndexMap<String, RecordMeta>,
}

impl OrigoConnection {
    pub fn new() -> OrigoConnection {
        return {
            OrigoConnection {
                secret_map: HashMap::new(),
                record_map: IndexMap::default(),
            }
        };
    }

    pub fn insert_record(&mut self, record_key: RecordKey, record_meta: RecordMeta) {
        self.record_map.insert(record_key.to_string(), record_meta);
    }

    pub fn set_secret(&mut self, name: String, val: Vec<u8>) {
        println!("set_secret: name={}, val={:?}", name, hex::encode(val.clone()));
        self.secret_map.insert(name, val);
    }

    /// TODO: Clean up the secret map keying.
    pub fn to_witness_data(&mut self) -> WitnessData {
        let req_key = RecordKey::new(Direction::Sent, ContentType::ApplicationData, 0, 0u8).to_string();
        let resp_key = RecordKey::new(Direction::Received, ContentType::ApplicationData, 1, 0u8).to_string();

        return WitnessData {
            request: DecryptTarget {
                aes_iv: self.secret_map.get("Application:client_aes_iv").unwrap().to_vec(),
                aes_key: self.secret_map.get("Application:client_aes_key").unwrap().to_vec(),
                ciphertext: self.record_map.get(&req_key).unwrap().ciphertext.clone()
            },
            response: DecryptTarget {
                aes_iv: self.secret_map.get("Application:server_aes_iv").unwrap().to_vec(),
                aes_key: self.secret_map.get("Application:server_aes_key").unwrap().to_vec(),
                ciphertext: self.record_map.get(&resp_key).unwrap().ciphertext.clone()
            }
        }
    }
}
