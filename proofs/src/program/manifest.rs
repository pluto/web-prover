use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::program::data::{CircuitData, InstructionConfig, ProgramData};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Key {
  String(String),
  Num(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseBody {
  json: Vec<Key>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
  status:  String,
  version: String,
  message: String,
  headers: HashMap<String, String>,
  body:    ResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
  method:  String,
  url:     String,
  version: String,
  headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
  pub request:  Request,
  pub response: Response,
}

const HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING: &str = "beginning";
const HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE: &str = "middle";
const HTTP_PARSE_AND_LOCK_START_LINE_FINAL: &str = "final";
const HTTP_HEADER_SIGNAL_NAME: &str = "header";
const HTTP_HEADER_SIGNAL_VALUE: &str = "value";
const HTTP_HEADER_MAX_NAME_LENGTH: usize = 20;
const HTTP_HEADER_MAX_VALUE_LENGTH: usize = 35;
const JSON_MASK_OBJECT_KEY_NAME: &str = "key";
const JSON_MASK_OBEJCT_KEYLEN_NAME: &str = "keyLen";
const JSON_MAX_KEY_LENGTH: usize = 10;
const JSON_MASK_ARRAY_SIGNAL_NAME: &str = "index";

impl Manifest {
  /// generates [`ProgramData::rom_data`] and [`ProgramData::rom`] from [`Request`]
  fn rom_from_request(
    &self,
    opcode_start: u64,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>) {
    let mut rom_data =
      HashMap::from([(String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData {
        opcode: opcode_start + 1,
      })]);
    let mut rom = vec![InstructionConfig {
      name:          String::from("HTTP_PARSE_AND_LOCK_START_LINE"),
      private_input: HashMap::from([
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING),
          json!(self.request.method.as_bytes()),
        ),
        // TODO: check how to enter correct url here
        (String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE), json!(self.request.url.as_bytes())),
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL),
          json!(self.request.version.as_bytes()),
        ),
      ]),
    }];
    for (i, (header_name, header_value)) in self.request.headers.iter().enumerate() {
      // pad name and value with zeroes
      let mut header_name_padded = [0u8; HTTP_HEADER_MAX_NAME_LENGTH];
      header_name_padded[..header_name.len()].copy_from_slice(header_name.as_bytes());
      // chore: vec here because serde doesn't support array > 32 in stable. Need const generics.
      let mut header_value_padded = vec![0u8; HTTP_HEADER_MAX_VALUE_LENGTH];
      header_value_padded[..header_value.len()].copy_from_slice(header_value.as_bytes());

      let name = format!("HTTP_LOCK_HEADER_{}", i + 1);
      rom_data.insert(name.clone(), CircuitData { opcode: opcode_start + 2 });
      rom.push(InstructionConfig {
        name,
        private_input: HashMap::from([
          (String::from(HTTP_HEADER_SIGNAL_NAME), json!(header_name_padded)),
          (String::from(HTTP_HEADER_SIGNAL_VALUE), json!(header_value_padded)),
        ]),
      });
    }

    (rom_data, rom)
  }

  fn rom_from_response(
    &self,
    opcode_start: u64,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>) {
    let mut rom_data =
      HashMap::from([(String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData {
        opcode: opcode_start + 1,
      })]);
    let mut rom = vec![InstructionConfig {
      name:          String::from("HTTP_PARSE_AND_LOCK_START_LINE"),
      private_input: HashMap::from([
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING),
          json!(self.response.version.as_bytes()),
        ),
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE),
          json!(self.response.status.as_bytes()),
        ),
        (
          String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL),
          json!(self.response.message.as_bytes()),
        ),
      ]),
    }];
    for (i, (header_name, header_value)) in self.response.headers.iter().enumerate() {
      // pad name and value with zeroes
      let mut header_name_padded = [0u8; HTTP_HEADER_MAX_NAME_LENGTH];
      header_name_padded[..header_name.len()].copy_from_slice(header_name.as_bytes());
      let mut header_value_padded = vec![0u8; HTTP_HEADER_MAX_VALUE_LENGTH];
      header_value_padded[..header_value.len()].copy_from_slice(header_value.as_bytes());

      let name = format!("HTTP_LOCK_HEADER_{}", i + 1);
      rom_data.insert(name.clone(), CircuitData { opcode: opcode_start + 2 });
      rom.push(InstructionConfig {
        name,
        private_input: HashMap::from([
          (String::from(HTTP_HEADER_SIGNAL_NAME), json!(header_name_padded)),
          (String::from(HTTP_HEADER_SIGNAL_VALUE), json!(header_value_padded)),
        ]),
      });
    }

    rom_data.insert(String::from("HTTP_BODY_EXTRACT"), CircuitData { opcode: opcode_start + 3 });
    rom.push(InstructionConfig {
      name:          String::from("HTTP_BODY_EXTRACT"),
      private_input: HashMap::new(),
    });

    rom_data.insert(String::from("JSON_PARSE"), CircuitData { opcode: opcode_start + 4 });
    rom.push(InstructionConfig {
      name:          String::from("JSON_PARSE"),
      private_input: HashMap::new(),
    });

    for (i, key) in self.response.body.json.iter().enumerate() {
      match key {
        Key::String(json_key) => {
          // pad json key
          let mut json_key_padded = [0u8; JSON_MAX_KEY_LENGTH];
          json_key_padded[..json_key.len()].copy_from_slice(json_key.as_bytes());
          rom_data.insert(format!("JSON_MASK_OBJECT_{}", i + 1), CircuitData {
            opcode: opcode_start + 5,
          });
          rom.push(InstructionConfig {
            name:          format!("JSON_MASK_OBJECT_{}", i + 1),
            private_input: HashMap::from([
              (String::from(JSON_MASK_OBJECT_KEY_NAME), json!(json_key_padded)),
              (String::from(JSON_MASK_OBEJCT_KEYLEN_NAME), json!([json_key.len()])),
            ]),
          });
        },
        Key::Num(index) => {
          rom_data
            .insert(format!("JSON_MASK_ARRAY_{}", i + 1), CircuitData { opcode: opcode_start + 6 });
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

    rom_data.insert(String::from("EXTRACT_VALUE"), CircuitData { opcode: opcode_start + 7 });
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
          "url": "https://api.reddit.com/users/<% userId %>?query=foobar",
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
    dbg!(&manifest);
    assert_eq!(manifest.request.method, "GET");
  }

  #[test]
  fn generate_rom_from_request() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

    let (rom_data, rom) = manifest.rom_from_request(0);

    assert_eq!(rom_data.len(), 1 + manifest.request.headers.len());
    assert_eq!(rom_data.get(&String::from("HTTP_PARSE_AND_LOCK_START_LINE")).unwrap().opcode, 1);

    // should contain http parse and http headers
    assert_eq!(rom.len(), 1 + manifest.request.headers.len());

    // assert http parse inputs
    assert_eq!(
      rom[0].private_input.get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING)),
      Some(&json!(manifest.request.method.as_bytes()))
    );
    assert_eq!(
      rom[0].private_input.get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE)),
      Some(&json!(manifest.request.url.as_bytes()))
    );
    assert_eq!(
      rom[0].private_input.get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL)),
      Some(&json!(manifest.request.version.as_bytes()))
    );

    // assert final circuit
    assert_eq!(
      rom[rom.len() - 1].name,
      format!("HTTP_LOCK_HEADER_{}", manifest.request.headers.len())
    );
  }

  #[test]
  fn generate_rom_from_response() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

    let opcode_start = 1;
    let (rom_data, rom) = manifest.rom_from_response(opcode_start);

    // parse http + headers + body mask + json parse + json mask (object + array) + extract
    assert_eq!(
      rom_data.len(),
      1 + manifest.response.headers.len() + 1 + 1 + manifest.response.body.json.len() + 1
    );
    assert_eq!(
      rom_data.get(&String::from("JSON_PARSE")).unwrap().opcode,
      opcode_start + 1 + manifest.response.headers.len() as u64 + 1 + 1
    );
    assert_eq!(
      rom_data.get(&String::from("EXTRACT_VALUE")).unwrap().opcode,
      (1 + manifest.response.headers.len() + 1 + 1 + manifest.response.body.json.len() + 1) as u64
    );

    assert_eq!(
      rom.len(),
      1 + manifest.response.headers.len() + 1 + 1 + manifest.response.body.json.len() + 1
    );

    // assert http parse inputs
    assert_eq!(
      rom[0].private_input.get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_BEGINNING)),
      Some(&json!(manifest.response.version.as_bytes()))
    );
    assert_eq!(
      rom[0].private_input.get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_MIDDLE)),
      Some(&json!(manifest.response.status.as_bytes()))
    );
    assert_eq!(
      rom[0].private_input.get(&String::from(HTTP_PARSE_AND_LOCK_START_LINE_FINAL)),
      Some(&json!(manifest.response.message.as_bytes()))
    );

    // check final circuit is extract
    assert_eq!(rom[rom.len() - 1].name, String::from("EXTRACT_VALUE"));
    assert_eq!(rom[rom.len() - 1].private_input, HashMap::new());
  }
}
