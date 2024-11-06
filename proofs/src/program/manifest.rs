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

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::program::data::{CircuitData, InstructionConfig};

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
  method:  String,
  /// HTTP request URL
  url:     String,
  /// HTTP version
  version: String,
  /// Request headers to lock
  headers: HashMap<String, String>,
}

/// Manifest containing [`Request`] and [`Response`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
  /// HTTP request lock items
  pub request:  Request,
  /// HTTP response lock items
  pub response: Response,
}

const AES_INPUT_LENGTH: usize = 16;
const AES_KEY_SIGNAL: &str = "key";
const AES_IV_SIGNAL: &str = "iv";
const AES_AAD_SIGNAL: &str = "aad";

// Parse and Lock
const HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING: &str = "beginning";
const HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE: &str = "middle";
const HTTP_PARSE_AND_LOCK_START_LINE_FINAL: &str = "final";
const HTTP_BEGINNING_LENGTH_SIGNAL: &str = "beginning_length";
const HTTP_MIDDLE_LENGTH_SIGNAL: &str = "middle_length";
const HTTP_FINAL_LENGTH_SIGNAL: &str = "final_length";

const HTTP_BEGINNING_MAX_LENGTH: usize = 50;
const HTTP_MIDDLE_MAX_LENGTH: usize = 200;
const HTTP_FINAL_MAX_LENGTH: usize = 50;

const HTTP_HEADER_SIGNAL_NAME: &str = "header";
const HTTP_HEADER_SIGNAL_VALUE: &str = "value";
const HTTP_HEADER_MAX_NAME_LENGTH: usize = 50;
const HTTP_HEADER_MAX_VALUE_LENGTH: usize = 100;

const JSON_MASK_OBJECT_KEY_NAME: &str = "key";
const JSON_MASK_OBJECT_KEYLEN_NAME: &str = "keyLen";
const JSON_MAX_KEY_LENGTH: usize = 10;
const JSON_MASK_ARRAY_SIGNAL_NAME: &str = "index";

impl Manifest {
  /// generates [`crate::program::ProgramData::rom_data`] and [`crate::program::ProgramData::rom`]
  /// from [`Manifest::request`]
  pub fn rom_from_request(
    &self,
    aes_key: &[u8],
    aes_iv: &[u8],
    aes_aad: &[u8],
    plaintext_len: usize,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>) {
    assert_eq!(plaintext_len % AES_INPUT_LENGTH, 0);
    // TODO (Sambhav): convert this to nice crate errors
    assert!(self.request.method.len() <= HTTP_BEGINNING_MAX_LENGTH);
    assert!(self.request.url.len() <= HTTP_MIDDLE_MAX_LENGTH);
    assert!(self.request.version.len() <= HTTP_FINAL_MAX_LENGTH);

    let aes_instr = String::from("AES_GCM_1");
    let mut rom_data = HashMap::from([(aes_instr.clone(), CircuitData { opcode: 0 })]);
    let aes_rom_opcode_config = InstructionConfig {
      name:          aes_instr.clone(),
      private_input: HashMap::from([
        (String::from(AES_KEY_SIGNAL), json!(aes_key)),
        (String::from(AES_IV_SIGNAL), json!(aes_iv)),
        (String::from(AES_AAD_SIGNAL), json!(aes_aad)),
      ]),
    };
    let mut rom = vec![aes_rom_opcode_config; plaintext_len / AES_INPUT_LENGTH];

    // TODO(Sambhav): find a better way to prevent this code duplication for request and response
    // pad http parse circuit input signals
    let mut http_parse_beginning_padded = [0u8; HTTP_BEGINNING_MAX_LENGTH];
    http_parse_beginning_padded[..self.request.method.len()]
      .copy_from_slice(self.request.method.as_bytes());
    let mut http_parse_middle_padded = [0u8; HTTP_MIDDLE_MAX_LENGTH];
    http_parse_middle_padded[..self.request.url.len()].copy_from_slice(self.request.url.as_bytes());
    let mut http_parse_final_padded = [0u8; HTTP_FINAL_MAX_LENGTH];
    http_parse_final_padded[..self.request.version.len()]
      .copy_from_slice(self.request.version.as_bytes());

    // initialise rom data and rom
    rom_data.insert(String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData { opcode: 1 });
    rom.push(InstructionConfig {
      name:          String::from("HTTP_PARSE_AND_LOCK_START_LINE"),
      private_input: HashMap::from([
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING),
          json!(http_parse_beginning_padded.to_vec()),
        ),
        (String::from(HTTP_BEGINNING_LENGTH_SIGNAL), json!([self.request.method.len()])),
        // TODO: check how to enter correct url here
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE),
          json!(http_parse_middle_padded.to_vec()),
        ),
        (String::from(HTTP_MIDDLE_LENGTH_SIGNAL), json!([self.request.url.len()])),
        (String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL), json!(http_parse_final_padded.to_vec())),
        (String::from(HTTP_FINAL_LENGTH_SIGNAL), json!([self.request.version.len()])),
      ]),
    });

    // headers
    for (i, (header_name, header_value)) in self.request.headers.iter().enumerate() {
      // pad name and value with zeroes
      let mut header_name_padded = [0u8; HTTP_HEADER_MAX_NAME_LENGTH];
      header_name_padded[..header_name.len()].copy_from_slice(header_name.as_bytes());
      // chore: vec here because serde doesn't support array > 32 in stable. Need const generics.
      let mut header_value_padded = vec![0u8; HTTP_HEADER_MAX_VALUE_LENGTH];
      header_value_padded[..header_value.len()].copy_from_slice(header_value.as_bytes());

      let name = format!("HTTP_LOCK_HEADER_{}", i + 1);
      rom_data.insert(name.clone(), CircuitData { opcode: 2 });
      rom.push(InstructionConfig {
        name,
        private_input: HashMap::from([
          (String::from(HTTP_HEADER_SIGNAL_NAME), json!(header_name_padded.to_vec())),
          (String::from(HTTP_HEADER_SIGNAL_VALUE), json!(header_value_padded.to_vec())),
        ]),
      });
    }

    (rom_data, rom)
  }

  /// generates ROM from [`Manifest::response`]
  pub fn rom_from_response(
    &self,
    aes_key: [u8; 16],
    aes_iv: [u8; 12],
    aes_aad: [u8; 16],
    plaintext_len: usize,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>) {
    assert_eq!(plaintext_len % AES_INPUT_LENGTH, 0);

    // TODO (Sambhav): convert this to nice crate errors
    assert!(self.response.version.len() <= HTTP_BEGINNING_MAX_LENGTH);
    assert!(self.response.status.len() <= HTTP_MIDDLE_MAX_LENGTH);
    assert!(self.response.message.len() <= HTTP_FINAL_MAX_LENGTH);

    let aes_instr = String::from("AES_GCM_1");
    let mut rom_data = HashMap::from([(aes_instr.clone(), CircuitData { opcode: 0 })]);
    let aes_rom_opcode_config = InstructionConfig {
      name:          aes_instr.clone(),
      private_input: HashMap::from([
        (String::from(AES_KEY_SIGNAL), json!(aes_key)),
        (String::from(AES_IV_SIGNAL), json!(aes_iv)),
        (String::from(AES_AAD_SIGNAL), json!(aes_aad)),
      ]),
    };
    let mut rom = vec![aes_rom_opcode_config; plaintext_len / AES_INPUT_LENGTH];

    // pad http parse circuit input signals
    let mut http_parse_beginning_padded = [0u8; HTTP_BEGINNING_MAX_LENGTH];
    http_parse_beginning_padded[..self.response.version.len()]
      .copy_from_slice(self.request.version.as_bytes());
    let mut http_parse_middle_padded = [0u8; HTTP_MIDDLE_MAX_LENGTH];
    http_parse_middle_padded[..self.response.status.len()]
      .copy_from_slice(self.response.status.as_bytes());
    let mut http_parse_final_padded = [0u8; HTTP_FINAL_MAX_LENGTH];
    http_parse_final_padded[..self.response.message.len()]
      .copy_from_slice(self.response.message.as_bytes());

    // http parse
    rom_data.insert(String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData { opcode: 1 });
    rom.push(InstructionConfig {
      name:          String::from("HTTP_PARSE_AND_LOCK_START_LINE"),
      private_input: HashMap::from([
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING),
          json!(http_parse_beginning_padded.to_vec()),
        ),
        (String::from(HTTP_BEGINNING_LENGTH_SIGNAL), json!([self.response.version.len()])),
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE),
          json!(http_parse_middle_padded.to_vec()),
        ),
        (String::from(HTTP_MIDDLE_LENGTH_SIGNAL), json!([self.response.status.len()])),
        (String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL), json!(http_parse_final_padded.to_vec())),
        (String::from(HTTP_FINAL_LENGTH_SIGNAL), json!([self.response.message.len()])),
      ]),
    });

    // headers
    for (i, (header_name, header_value)) in self.response.headers.iter().enumerate() {
      // pad name and value with zeroes
      let mut header_name_padded = [0u8; HTTP_HEADER_MAX_NAME_LENGTH];
      header_name_padded[..header_name.len()].copy_from_slice(header_name.as_bytes());
      let mut header_value_padded = vec![0u8; HTTP_HEADER_MAX_VALUE_LENGTH];
      header_value_padded[..header_value.len()].copy_from_slice(header_value.as_bytes());

      let name = format!("HTTP_LOCK_HEADER_{}", i + 1);
      rom_data.insert(name.clone(), CircuitData { opcode: 2 });
      rom.push(InstructionConfig {
        name,
        private_input: HashMap::from([
          (String::from(HTTP_HEADER_SIGNAL_NAME), json!(header_name_padded.to_vec())),
          (String::from(HTTP_HEADER_SIGNAL_VALUE), json!(header_value_padded.to_vec())),
        ]),
      });
    }

    // http body
    rom_data.insert(String::from("HTTP_BODY_EXTRACT"), CircuitData { opcode: 3 });
    rom.push(InstructionConfig {
      name:          String::from("HTTP_BODY_EXTRACT"),
      private_input: HashMap::new(),
    });

    // json keys
    for (i, key) in self.response.body.json.iter().enumerate() {
      match key {
        Key::String(json_key) => {
          // pad json key
          let mut json_key_padded = [0u8; JSON_MAX_KEY_LENGTH];
          json_key_padded[..json_key.len()].copy_from_slice(json_key.as_bytes());
          rom_data.insert(format!("JSON_MASK_OBJECT_{}", i + 1), CircuitData { opcode: 5 });
          rom.push(InstructionConfig {
            name:          format!("JSON_MASK_OBJECT_{}", i + 1),
            private_input: HashMap::from([
              (String::from(JSON_MASK_OBJECT_KEY_NAME), json!(json_key_padded)),
              (String::from(JSON_MASK_OBJECT_KEYLEN_NAME), json!([json_key.len()])),
            ]),
          });
        },
        Key::Num(index) => {
          rom_data.insert(format!("JSON_MASK_ARRAY_{}", i + 1), CircuitData { opcode: 6 });
          rom.push(InstructionConfig {
            name:          format!("JSON_MASK_ARRAY_{}", i + 1),
            private_input: HashMap::from([(
              String::from(JSON_MASK_ARRAY_SIGNAL_NAME),
              json!([index]),
            )]),
          });
        },
      }
    }

    // final extraction
    rom_data.insert(String::from("EXTRACT_VALUE"), CircuitData { opcode: 7 });
    rom.push(InstructionConfig {
      name:          String::from("EXTRACT_VALUE"),
      private_input: HashMap::new(),
    });

    (rom_data, rom)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const AES_KEY: (&str, [u8; 16]) =
    ("key", [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]);
  const AES_IV: (&str, [u8; 12]) = ("iv", [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]);
  const AES_AAD: (&str, [u8; 16]) = ("aad", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
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
          "url": "https://api.reddit.com/users/<userId>?query=foo",
          "headers": {
              "Content-Type": "application/json",
              "Authentication": "Bearer <% token %>"
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
    let plaintext_len = 16;
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

    let (rom_data, rom) =
      manifest.rom_from_request(&AES_KEY.1, &AES_IV.1, &AES_AAD.1, plaintext_len);

    // AES + HTTP parse + HTTP headers length
    assert_eq!(rom_data.len(), 1 + 1 + manifest.request.headers.len());
    assert_eq!(rom_data.get(&String::from("HTTP_PARSE_AND_LOCK_START_LINE")).unwrap().opcode, 1);

    // should contain http parse and http headers
    assert_eq!(rom.len(), plaintext_len / AES_INPUT_LENGTH + 1 + manifest.request.headers.len());

    // assert http parse inputs
    let http_instruction_len = plaintext_len / AES_INPUT_LENGTH;
    let mut padded_request_method = [0u8; HTTP_BEGINNING_MAX_LENGTH];
    padded_request_method[..manifest.request.method.len()]
      .copy_from_slice(manifest.request.method.as_bytes());
    let mut padded_request_url = [0u8; HTTP_MIDDLE_MAX_LENGTH];
    padded_request_url[..manifest.request.url.len()]
      .copy_from_slice(manifest.request.url.as_bytes());
    let mut padded_request_version = [0u8; HTTP_FINAL_MAX_LENGTH];
    padded_request_version[..manifest.request.version.len()]
      .copy_from_slice(manifest.request.version.as_bytes());
    assert_eq!(
      rom[http_instruction_len]
        .private_input
        .get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING)),
      Some(&json!(padded_request_method)),
    );
    assert_eq!(
      rom[http_instruction_len].private_input.get(&String::from(HTTP_BEGINNING_LENGTH_SIGNAL)),
      Some(&json!([manifest.request.method.len()]))
    );
    assert_eq!(
      rom[http_instruction_len]
        .private_input
        .get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE)),
      Some(&json!(padded_request_url.to_vec()))
    );
    assert_eq!(
      rom[http_instruction_len].private_input.get(&String::from(HTTP_MIDDLE_LENGTH_SIGNAL)),
      Some(&json!([manifest.request.url.len()]))
    );
    assert_eq!(
      rom[http_instruction_len]
        .private_input
        .get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL)),
      Some(&json!(padded_request_version))
    );
    assert_eq!(
      rom[http_instruction_len].private_input.get(&String::from(HTTP_FINAL_LENGTH_SIGNAL)),
      Some(&json!([manifest.request.version.len()]))
    );

    // assert final circuit
    assert_eq!(
      rom[rom.len() - 1].name,
      format!("HTTP_LOCK_HEADER_{}", manifest.request.headers.len())
    );
  }

  #[test]
  fn generate_rom_from_response() {
    let plaintext_length = 160;

    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

    let (rom_data, rom) =
      manifest.rom_from_response(AES_KEY.1, AES_IV.1, AES_AAD.1, plaintext_length);

    // AES + parse http + headers + body mask + json mask (object + array) + extract
    assert_eq!(
      rom_data.len(),
      1 + 1 + manifest.response.headers.len() + 1 + 1 + manifest.response.body.json.len() + 1
    );
    assert_eq!(
      rom_data.get(&String::from("JSON_PARSE")).unwrap().opcode,
      1 + manifest.response.headers.len() as u64 + 1 + 1
    );
    // HTTP parse + headers + body mask + json keys + extract value
    assert_eq!(
      rom_data.get(&String::from("EXTRACT_VALUE")).unwrap().opcode,
      (manifest.response.headers.len() + 1 + 1 + manifest.response.body.json.len() + 1) as u64
    );

    assert_eq!(
      rom.len(),
      plaintext_length / AES_INPUT_LENGTH
        + 1
        + manifest.response.headers.len()
        + 1
        + 1
        + manifest.response.body.json.len()
        + 1
    );

    // assert http parse inputs
    let http_instruction_len = plaintext_length / AES_INPUT_LENGTH;

    let mut padded_response_version = [0u8; HTTP_BEGINNING_MAX_LENGTH];
    padded_response_version[..manifest.response.version.len()]
      .copy_from_slice(manifest.response.version.as_bytes());
    let mut padded_response_status = [0u8; HTTP_MIDDLE_MAX_LENGTH];
    padded_response_status[..manifest.response.status.len()]
      .copy_from_slice(manifest.response.status.as_bytes());
    let mut padded_response_message = [0u8; HTTP_FINAL_MAX_LENGTH];
    padded_response_message[..manifest.response.message.len()]
      .copy_from_slice(manifest.response.message.as_bytes());

    assert_eq!(
      rom[http_instruction_len]
        .private_input
        .get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING)),
      Some(&json!(padded_response_version))
    );
    assert_eq!(
      rom[http_instruction_len]
        .private_input
        .get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE)),
      Some(&json!(padded_response_status.to_vec()))
    );
    assert_eq!(
      rom[http_instruction_len]
        .private_input
        .get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL)),
      Some(&json!(padded_response_message))
    );

    // check final circuit is extract
    assert_eq!(rom[rom.len() - 1].name, String::from("EXTRACT_VALUE"));
    assert_eq!(rom[rom.len() - 1].private_input, HashMap::new());
  }
}
