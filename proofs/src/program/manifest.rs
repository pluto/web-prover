//! proof composition is required to stitch different [`crate::program::RomCircuit`] together to
//! form an NIVC [`crate::program::data::ProgramData`].
//!
//! [`Manifest`] generated by client contains [`Request`] and [`Response`] which is used to create
//! HTTP and JSON circuits. To create the circuits, ROM is prepared containing circuits and private
//! input to each circuit.
//!
//! HTTP circuits consists of:
//! - `PARSE`: parsing raw http bytes
//! - `LOCK_START_LINE`: validating HTTP start line as per request or response
//! - `LOCK_HEADER`: validating any header in the data
//! - `MASK_BODY`: masking body in response for JSON value extraction
//!
//! JSON circuits consists of:
//! - `PARSE`: parsing JSON bytes
//! - `MASK_OBJECT`: masking any object value
//! - `MASK_ARRAY_INDEX`: masking any array index
//! - `EXTRACT_VALUE`: final template that extracts value as output

use std::collections::HashMap;

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

use crate::{
  program::data::{CircuitData, FoldInput, InstructionConfig},
  witness::{compute_http_header_witness, compute_http_witness, compute_json_witness, data_hasher},
};

/// JSON key required to extract particular value from response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Key {
  /// Object key
  String(String),
  /// Array index
  Num(usize),
}

/// JSON keys: `["a", "b", 0, "c"]`
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseBody {
  json: Vec<Key>,
}

/// HTTP Response items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
  /// HTTP response status
  status:  String,
  /// HTTP version
  version: String,
  /// HTTP response message
  message: String,
  /// HTTP headers to lock
  headers: HashMap<String, String>,
  /// HTTP body keys
  body:    ResponseBody,
}

/// HTTP Request items required for circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
  /// HTTP method (GET or POST)
  method:      String,
  /// HTTP request URL
  url:         String,
  /// HTTP version
  version:     String,
  /// Request headers to lock
  pub headers: HashMap<String, String>,
}

/// Manifest containing [`Request`] and [`Response`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
  /// HTTP request lock items
  pub request:  Request,
  /// HTTP response lock items
  pub response: Response,
}

/// AES inputs
const AES_INPUT_LENGTH: usize = 16;
const AES_PLAINTEXT_SIGNAL_NAME: &str = "plainText";
const AES_CIPHERTEXT_SIGNAL_NAME: &str = "cipherText";
const AES_COUNTER_SIGNAL_NAME: &str = "ctr";
const AES_KEY_SIGNAL: &str = "key";
const AES_IV_SIGNAL: &str = "iv";
const AES_AAD_SIGNAL: &str = "aad";

/// HTTP
const DATA_SIGNAL_NAME: &str = "data";
const HTTP_START_LINE_HASH_SIGNAL_NAME: &str = "start_line_hash";
const HTTP_HEADER_HASHES_SIGNAL_NAME: &str = "header_hashes";
const HTTP_BODY_HASH_SIGNAL_NAME: &str = "body_hash";
const JSON_MASK_OBJECT_KEY_NAME: &str = "key";
const JSON_MASK_OBJECT_KEYLEN_NAME: &str = "keyLen";
const JSON_MAX_KEY_LENGTH: usize = 10;
const JSON_MASK_ARRAY_SIGNAL_NAME: &str = "index";

/// generates AES counter for each block
fn generate_aes_counter(plaintext_blocks: usize) -> Vec<u8> {
  let mut ctr = Vec::new();
  for i in 0..plaintext_blocks {
    ctr.append(&mut vec![0, 0, 0, (i + 1) as u8]);
  }
  ctr
}

// TODO(Sambhav): can we remove usage of vec here?
pub struct AESEncryptionInput {
  pub key:        [u8; 16],
  pub iv:         [u8; 12],
  pub aad:        Vec<u8>,
  pub plaintext:  Vec<u8>,
  pub ciphertext: Vec<u8>,
}

fn circuit_size(plaintext_length: usize) -> usize { plaintext_length.next_power_of_two().max(512) }

impl Manifest {
  /// generates [`crate::program::ProgramData::rom_data`] and [`crate::program::ProgramData::rom`]
  /// from [`Manifest::request`]
  pub fn rom_from_request(
    &self,
    inputs: AESEncryptionInput,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>, HashMap<String, FoldInput>) {
    assert_eq!(inputs.plaintext.len(), inputs.ciphertext.len());

    debug!("Padding plaintext and ciphertext to nearest 16...");
    let remainder = inputs.plaintext.len() % 16;
    let mut plaintext = inputs.plaintext.to_vec();
    let mut ciphertext = inputs.ciphertext.to_vec();
    if remainder != 0 {
      let padding = 16 - remainder;
      plaintext.resize(plaintext.len() + padding, 0);
      ciphertext.resize(ciphertext.len() + padding, 0);
    }

    assert_eq!(plaintext.len() % AES_INPUT_LENGTH, 0);

    let aes_instr = String::from("AES_GCM_1");
    let mut rom_data = HashMap::from([(aes_instr.clone(), CircuitData { opcode: 0 })]);
    let aes_rom_opcode_config = InstructionConfig {
      name:          aes_instr.clone(),
      private_input: HashMap::from([
        (String::from(AES_KEY_SIGNAL), json!(inputs.key)),
        (String::from(AES_IV_SIGNAL), json!(inputs.iv)),
        (String::from(AES_AAD_SIGNAL), json!(inputs.aad)),
      ]),
    };
    let rom_len = plaintext.len() / AES_INPUT_LENGTH;
    let mut rom = vec![aes_rom_opcode_config; rom_len];

    // Pad internally the plaintext for using in circuits
    let mut padded_plaintext = plaintext.to_vec();
    padded_plaintext.resize(circuit_size(plaintext.len()), 0);

    // TODO(Sambhav): find a better way to prevent this code duplication for request and response
    // compute hashes http start line and headers signals
    let http_start_line_hash = data_hasher(&compute_http_witness(
      &padded_plaintext,
      crate::witness::HttpMaskType::StartLine,
    ));
    let mut http_header_hashes = vec!["0".to_string(); 5];
    for header_name in self.request.headers.keys() {
      let (index, masked_header) =
        compute_http_header_witness(&padded_plaintext, header_name.as_bytes());
      http_header_hashes[index] =
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &data_hasher(&masked_header).to_bytes())
          .to_str_radix(10);
    }

    let http_body = compute_http_witness(&padded_plaintext, crate::witness::HttpMaskType::Body);
    let http_body_hash = data_hasher(&http_body);

    // initialise rom data and rom
    rom_data.insert(String::from("HTTP_NIVC"), CircuitData { opcode: 1 });
    rom.push(InstructionConfig {
      name:          String::from("HTTP_NIVC"),
      private_input: HashMap::from([
        (String::from(DATA_SIGNAL_NAME), json!(&padded_plaintext.to_vec())),
        (
          String::from(HTTP_START_LINE_HASH_SIGNAL_NAME),
          json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_start_line_hash.to_bytes())
            .to_str_radix(10)]),
        ),
        (String::from(HTTP_HEADER_HASHES_SIGNAL_NAME), json!(http_header_hashes)),
        (
          String::from(HTTP_BODY_HASH_SIGNAL_NAME),
          json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_body_hash.to_bytes())
            .to_str_radix(10),]),
        ),
      ]),
    });

    // Here we can use unpadded plaintext because AES reads in chunks, not a 512b size.
    let fold_inputs = HashMap::from([(aes_instr.clone(), FoldInput {
      value: HashMap::from([
        (
          String::from(AES_PLAINTEXT_SIGNAL_NAME),
          plaintext.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
        (
          String::from(AES_CIPHERTEXT_SIGNAL_NAME),
          ciphertext.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
        (
          String::from(AES_COUNTER_SIGNAL_NAME),
          generate_aes_counter(rom_len).iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
      ]),
    })]);

    (rom_data, rom, fold_inputs)
  }

  /// generates ROM from [`Manifest::response`]
  pub fn rom_from_response(
    &self,
    inputs: AESEncryptionInput,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>, HashMap<String, FoldInput>) {
    assert_eq!(inputs.plaintext.len(), inputs.ciphertext.len());

    debug!("Padding plaintext and ciphertext to nearest 16...");
    let remainder = inputs.plaintext.len() % 16;
    let mut plaintext = inputs.plaintext.to_vec();
    let mut ciphertext = inputs.ciphertext.to_vec();
    if remainder != 0 {
      let padding = 16 - remainder;
      plaintext.resize(plaintext.len() + padding, 0);
      ciphertext.resize(ciphertext.len() + padding, 0);
    }

    assert_eq!(plaintext.len() % AES_INPUT_LENGTH, 0);

    let aes_instr = String::from("AES_GCM_1");
    let mut rom_data = HashMap::from([(aes_instr.clone(), CircuitData { opcode: 0 })]);
    let aes_rom_opcode_config = InstructionConfig {
      name:          aes_instr.clone(),
      private_input: HashMap::from([
        (String::from(AES_KEY_SIGNAL), json!(inputs.key)),
        (String::from(AES_IV_SIGNAL), json!(inputs.iv)),
        (String::from(AES_AAD_SIGNAL), json!(inputs.aad)),
      ]),
    };

    let rom_len = plaintext.len() / AES_INPUT_LENGTH;
    let mut rom = vec![aes_rom_opcode_config; rom_len];

    // Pad internally the plaintext for using in circuits
    let mut padded_plaintext = plaintext.to_vec();
    padded_plaintext.resize(circuit_size(plaintext.len()), 0);

    // compute hashes http start line and headers signals
    let http_start_line_hash = data_hasher(&compute_http_witness(
      &padded_plaintext,
      crate::witness::HttpMaskType::StartLine,
    ));
    let mut http_header_hashes = vec!["0".to_string(); 25];
    for header_name in self.request.headers.keys() {
      let (index, masked_header) =
        compute_http_header_witness(&padded_plaintext, header_name.as_bytes());
      http_header_hashes[index] =
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &data_hasher(&masked_header).to_bytes())
          .to_str_radix(10);
    }
    let http_body = compute_http_witness(&padded_plaintext, crate::witness::HttpMaskType::Body);
    let http_body_hash = data_hasher(&http_body);

    // http parse
    rom_data.insert(String::from("HTTP_NIVC"), CircuitData { opcode: 1 });
    rom.push(InstructionConfig {
      name:          String::from("HTTP_NIVC"),
      private_input: HashMap::from([
        (String::from(DATA_SIGNAL_NAME), json!(padded_plaintext.to_vec())),
        (
          String::from(HTTP_START_LINE_HASH_SIGNAL_NAME),
          json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_start_line_hash.to_bytes())
            .to_str_radix(10)]),
        ),
        (String::from(HTTP_HEADER_HASHES_SIGNAL_NAME), json!(http_header_hashes)),
        (
          String::from(HTTP_BODY_HASH_SIGNAL_NAME),
          json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_body_hash.to_bytes())
            .to_str_radix(10),]),
        ),
      ]),
    });

    // json keys
    let mut masked_body = http_body;
    for (i, key) in self.response.body.json.iter().enumerate() {
      match key {
        Key::String(json_key) => {
          // pad json key
          let mut json_key_padded = [0u8; JSON_MAX_KEY_LENGTH];
          json_key_padded[..json_key.len()].copy_from_slice(json_key.as_bytes());
          rom_data.insert(format!("JSON_MASK_OBJECT_{}", i + 1), CircuitData { opcode: 2 });
          rom.push(InstructionConfig {
            name:          format!("JSON_MASK_OBJECT_{}", i + 1),
            private_input: HashMap::from([
              (String::from("data"), json!(masked_body)),
              (String::from(JSON_MASK_OBJECT_KEY_NAME), json!(json_key_padded)),
              (String::from(JSON_MASK_OBJECT_KEYLEN_NAME), json!([json_key.len()])),
            ]),
          });
          masked_body = compute_json_witness(
            &masked_body,
            crate::witness::JsonMaskType::Object(json_key.as_bytes().to_vec()),
          );
        },
        Key::Num(index) => {
          rom_data.insert(format!("JSON_MASK_ARRAY_{}", i + 1), CircuitData { opcode: 3 });
          rom.push(InstructionConfig {
            name:          format!("JSON_MASK_ARRAY_{}", i + 1),
            private_input: HashMap::from([
              (String::from("data"), json!(masked_body)),
              (String::from(JSON_MASK_ARRAY_SIGNAL_NAME), json!([index])),
            ]),
          });
          masked_body =
            compute_json_witness(&masked_body, crate::witness::JsonMaskType::ArrayIndex(*index))
        },
      }
    }

    // final extraction
    rom_data.insert(String::from("EXTRACT_VALUE"), CircuitData { opcode: 4 });
    rom.push(InstructionConfig {
      name:          String::from("EXTRACT_VALUE"),
      private_input: HashMap::from([(String::from(DATA_SIGNAL_NAME), json!(masked_body))]),
    });

    // fold inputs
    let fold_inputs = HashMap::from([(aes_instr.clone(), FoldInput {
      value: HashMap::from([
        (
          String::from(AES_PLAINTEXT_SIGNAL_NAME),
          plaintext.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
        (
          String::from(AES_CIPHERTEXT_SIGNAL_NAME),
          ciphertext.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
        (
          String::from(AES_COUNTER_SIGNAL_NAME),
          generate_aes_counter(rom_len).iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
      ]),
    })]);

    (rom_data, rom, fold_inputs)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const AES_KEY: (&str, [u8; 16]) =
    ("key", [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]);
  const AES_IV: (&str, [u8; 12]) = ("iv", [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]);
  const AES_AAD: (&str, [u8; 16]) = ("aad", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const TEST_MANIFEST_REQUEST: &[u8] = &[
    71, 69, 84, 32, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 115, 116, 46, 103, 105, 116,
    104, 117, 98, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109, 47, 109,
    97, 116, 116, 101, 115, 47, 50, 51, 101, 54, 52, 102, 97, 97, 100, 98, 53, 102, 100, 52, 98,
    53, 49, 49, 50, 102, 51, 55, 57, 57, 48, 51, 100, 50, 53, 55, 50, 101, 47, 114, 97, 119, 47,
    55, 52, 101, 53, 49, 55, 97, 54, 48, 99, 50, 49, 97, 53, 99, 49, 49, 100, 57, 52, 102, 101, 99,
    56, 98, 53, 55, 50, 102, 54, 56, 97, 100, 100, 102, 97, 100, 101, 51, 57, 47, 101, 120, 97,
    109, 112, 108, 101, 46, 106, 115, 111, 110, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 104,
    111, 115, 116, 58, 32, 103, 105, 115, 116, 46, 103, 105, 116, 104, 117, 98, 117, 115, 101, 114,
    99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109, 13, 10, 97, 99, 99, 101, 112, 116, 45, 101,
    110, 99, 111, 100, 105, 110, 103, 58, 32, 105, 100, 101, 110, 116, 105, 116, 121, 13, 10, 99,
    111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 99, 108, 111, 115, 101, 13, 10, 97, 99, 99,
    101, 112, 116, 58, 32, 42, 47, 42, 0, 0,
  ];
  const TEST_MANIFEST_RESPONSE: &[u8] = &[
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101,
    110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
    47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13,
    10, 99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103,
    122, 105, 112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105,
    110, 103, 58, 32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32,
    34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101,
    109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34,
    65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121,
    108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
  ];
  const TEST_MANIFEST: &str = r#"
  {
      "manifestVersion": "1",
      "id": "reddit-user-karma",
      "title": "Total Reddit Karma",
      "description": "Generate a proof that you have a certain amount of karma",
      "prepareUrl": "https://www.reddit.com/login/",
      "request": {
          "method": "GET",
          "version": "HTTP/1.1",
          "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
          "headers": {
              "host": "gist.githubusercontent.com",
              "connection": "close"
          },
          "body": {
              "userId": "<% userId %>"
          },
          "vars": {
              "userId": {
                  "regex": "[a-z]{,20}+"
              },
              "token": {
                  "type": "base64",
                  "length": 32
              }
          }
      },
      "response": {
          "status": "200",
          "version": "HTTP/1.1",
          "message": "OK",
          "headers": {
              "Content-Type": "application/json"
          },
          "body": {
              "json": [
                  "data",
                  "items",
                  0
              ],
              "contains": "this_string_exists_in_body"
          }
      }
  }
  "#;

  #[test]
  fn test_serialize() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();
    assert_eq!(manifest.request.method, "GET");
  }

  #[test]
  fn generate_rom_from_request() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

    let (rom_data, rom, fold_input) = manifest.rom_from_request(AESEncryptionInput {
      key:        AES_KEY.1,
      iv:         AES_IV.1,
      aad:        AES_AAD.1.to_vec(),
      plaintext:  TEST_MANIFEST_REQUEST.to_vec(),
      ciphertext: TEST_MANIFEST_REQUEST.to_vec(),
    });

    // AES + HTTP parse + HTTP headers length
    assert_eq!(rom_data.len(), 2);
    assert_eq!(rom_data.get(&String::from("HTTP_NIVC")).unwrap().opcode, 1);

    // should contain http parse and http headers
    assert_eq!(rom.len(), TEST_MANIFEST_REQUEST.len() / AES_INPUT_LENGTH + 1);

    // assert http parse inputs
    let http_instruction_len = TEST_MANIFEST_REQUEST.len() / AES_INPUT_LENGTH;
    assert_eq!(rom[http_instruction_len].name, String::from("HTTP_NIVC"));
    assert!(rom[http_instruction_len].private_input.contains_key("start_line_hash"));
    assert!(rom[http_instruction_len].private_input.contains_key("header_hashes"));
    assert!(rom[http_instruction_len].private_input.contains_key("body_hash"));

    let aes_fold_input = fold_input.get(&String::from("AES_GCM_1")).unwrap();
    assert!(aes_fold_input.value.contains_key(AES_PLAINTEXT_SIGNAL_NAME));
    assert!(aes_fold_input.value.contains_key(AES_CIPHERTEXT_SIGNAL_NAME));
    assert!(aes_fold_input.value.contains_key(AES_COUNTER_SIGNAL_NAME));
  }

  #[test]
  fn generate_rom_from_response() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

    let (rom_data, rom, fold_input) = manifest.rom_from_response(AESEncryptionInput {
      key:        AES_KEY.1,
      iv:         AES_IV.1,
      aad:        AES_AAD.1.to_vec(),
      plaintext:  TEST_MANIFEST_RESPONSE.to_vec(),
      ciphertext: TEST_MANIFEST_RESPONSE.to_vec(),
    });

    // AES + http + json mask (object + array) + extract
    assert_eq!(rom_data.len(), 1 + 1 + manifest.response.body.json.len() + 1);
    // HTTP + json keys + extract value
    assert_eq!(
      rom_data.get(&String::from("EXTRACT_VALUE")).unwrap().opcode,
      (1 + manifest.response.body.json.len()) as u64
    );

    assert_eq!(
      rom.len(),
      TEST_MANIFEST_RESPONSE.len() / AES_INPUT_LENGTH + 1 + manifest.response.body.json.len() + 1
    );

    // assert http parse inputs
    let http_instruction_len = TEST_MANIFEST_RESPONSE.len() / AES_INPUT_LENGTH;

    assert_eq!(rom[http_instruction_len].name, String::from("HTTP_NIVC"));
    assert!(rom[http_instruction_len].private_input.contains_key("start_line_hash"));
    assert!(rom[http_instruction_len].private_input.contains_key("header_hashes"));
    assert!(rom[http_instruction_len].private_input.contains_key("body_hash"));

    // check final circuit is extract
    assert_eq!(rom[rom.len() - 1].name, String::from("EXTRACT_VALUE"));
    assert!(rom[rom.len() - 1].private_input.contains_key("data"));

    let aes_fold_input = fold_input.get(&String::from("AES_GCM_1")).unwrap();
    assert!(aes_fold_input.value.contains_key(AES_PLAINTEXT_SIGNAL_NAME));
    assert!(aes_fold_input.value.contains_key(AES_CIPHERTEXT_SIGNAL_NAME));
    assert!(aes_fold_input.value.contains_key(AES_COUNTER_SIGNAL_NAME));
  }
}
