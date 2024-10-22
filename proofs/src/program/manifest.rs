use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::data::{CircuitData, InstructionConfig, ProgramData};

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

impl Manifest {
  /// generates [`ProgramData::rom_data`] and [`ProgramData::rom`] from [`Request`]
  fn rom_from_request(
    &self,
    opcode_start: u64,
  ) -> (HashMap<String, CircuitData>, Vec<InstructionConfig>) {
    // 1. rom data
    // 2. rom
    // 3. fold input

    let mut rom_data =
      HashMap::from([(String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData {
        opcode: opcode_start + 1,
      })]);
    let mut rom = vec![InstructionConfig {
      name:          String::from("HTTP_PARSE_AND_LOCK_START_LINE"),
      private_input: HashMap::from([
        (String::from("beginning"), json!(self.request.method)),
        // TODO: check how to enter correct url here
        (String::from("middle"), json!(self.request.url)),
        (String::from("end"), json!(self.request.version)),
      ]),
    }];
    for (i, (header_name, header_value)) in self.request.headers.iter().enumerate() {
      let name = format!("HTTP_LOCK_HEADER_{}", i + 1);
      rom_data.insert(name.clone(), CircuitData { opcode: opcode_start + 1 + i as u64 });
      rom.push(InstructionConfig {
        name,
        private_input: HashMap::from([(header_name.clone(), json!(header_value))]),
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
        (String::from("beginning"), json!(self.response.version)),
        // TODO: check how to enter correct url here
        (String::from("middle"), json!(self.response.status)),
        (String::from("end"), json!(self.response.message)),
      ]),
    }];
    for (i, (header_name, header_value)) in self.response.headers.iter().enumerate() {
      let name = format!("HTTP_LOCK_HEADER_{}", i + 1);
      rom_data.insert(name.clone(), CircuitData { opcode: opcode_start + 2 });
      rom.push(InstructionConfig {
        name,
        private_input: HashMap::from([(header_name.clone(), json!(header_value))]),
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

    (rom_data, rom)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const TEST_MANIFEST: &[u8] = include_bytes!("../tests/manifest.json");

  #[test]
  fn test_sense() {
    let manifest: Manifest = serde_json::from_slice(TEST_MANIFEST).unwrap();
    dbg!(&manifest);
    assert_eq!(manifest.request.method, "GET");
  }
}
