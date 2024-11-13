//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use client_side_prover::supernova::RecursiveSNARK;
use program::data::{self, CircuitData, InstructionConfig};
use serde_json::json;

use super::*;
use crate::{
  program::data::{FoldInput, NotExpanded},
  witness::data_hasher,
};

mod witnesscalc;

// const ROM: &[] = &[Fr::ZERO, 1, 2, 0, 1, 2];

const ADD_EXTERNAL_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/add_external.r1cs");
const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/square_zeroth.r1cs");
const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/swap_memory.r1cs");

// const INIT_PUBLIC_INPUT: [u64; 2] = [1, 2];
const EXTERNAL_INPUTS: [[u64; 2]; 2] = [[5, 7], [13, 1]];
const MAX_ROM_LENGTH: usize = 10;

// -----------------------------------------------------------------------------------------------
// JSON Proof Material
const JSON_MAX_ROM_LENGTH: usize = 35;

// Circuit 0
const AES_GCM_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/aes_gctr_nivc_512b.r1cs");
const AES_GCM_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/aes_gctr_nivc_512b.bin");

// Circuit 1
const HTTP_NIVC_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/http_nivc_512b.r1cs");
const HTTP_NIVC_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/http_nivc_512b.bin");

// Circuit 2
const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_mask_object_512b.r1cs");
const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_mask_object_512b.bin");

// Circuit 3
const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_mask_array_index_512b.r1cs");
const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_mask_array_index_512b.bin");

// circuit 4
const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_extract_value_512b.r1cs");
const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_extract_value_512b.bin");

const BYTES_PER_FOLD: usize = 16;
const AES_BYTES: [u8; 50] = [0; 50];

const HTTP_RESPONSE_PLAINTEXT: (&str, [u8; 320]) = ("plainText", [
  72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101, 110,
  116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106,
  115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 99,
  111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105,
  112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58,
  32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32, 34, 100, 97, 116,
  97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
  91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115,
  116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114,
  111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119,
  105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13,
  10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
  10, 32, 32, 32, 125, 13, 10, 125,
]);

const AES_CIPHER_TEXT: (&str, [u8; 320]) = ("cipherText", [
  75, 220, 142, 158, 79, 135, 141, 163, 211, 26, 242, 137, 81, 253, 181, 117, 253, 246, 197, 197,
  61, 46, 55, 87, 218, 137, 240, 143, 241, 177, 225, 129, 80, 114, 125, 72, 45, 18, 224, 179, 79,
  231, 153, 198, 163, 252, 197, 219, 233, 46, 202, 120, 99, 253, 76, 9, 70, 11, 200, 218, 228, 251,
  133, 248, 233, 177, 19, 241, 205, 128, 65, 76, 10, 31, 71, 198, 177, 78, 108, 246, 175, 152, 42,
  97, 255, 182, 157, 245, 123, 95, 130, 101, 129, 138, 236, 146, 47, 22, 22, 13, 125, 1, 109, 158,
  189, 131, 44, 43, 203, 118, 79, 181, 86, 33, 235, 186, 75, 20, 7, 147, 102, 75, 90, 222, 255,
  140, 94, 52, 191, 145, 192, 71, 239, 245, 247, 175, 117, 136, 173, 235, 250, 189, 74, 155, 103,
  25, 164, 187, 22, 26, 39, 37, 113, 248, 170, 146, 73, 75, 45, 208, 125, 49, 101, 11, 120, 215,
  93, 160, 14, 147, 129, 181, 150, 59, 167, 197, 230, 122, 77, 245, 247, 215, 136, 98, 1, 180, 213,
  30, 214, 88, 83, 42, 33, 112, 61, 4, 197, 75, 134, 149, 22, 228, 24, 95, 131, 35, 44, 181, 135,
  31, 173, 36, 23, 192, 177, 127, 156, 199, 167, 212, 66, 235, 194, 102, 61, 144, 121, 59, 187,
  179, 212, 34, 117, 47, 96, 3, 169, 73, 204, 88, 36, 48, 158, 220, 237, 198, 180, 105, 7, 188,
  109, 24, 201, 217, 186, 191, 232, 63, 93, 153, 118, 214, 157, 167, 15, 216, 191, 152, 41, 106,
  24, 127, 8, 144, 78, 218, 133, 125, 89, 97, 10, 246, 8, 244, 112, 169, 190, 206, 14, 217, 109,
  147, 130, 61, 214, 237, 143, 77, 14, 14, 70, 56, 94, 97, 207, 214, 106, 249, 37, 7, 186, 95, 174,
  146, 203, 148, 173, 172, 13, 113,
]);

const AES_COUNTER: (&str, [u8; 80]) = ("ctr", [
  0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8,
  0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0, 12, 0, 0, 0, 13, 0, 0, 0, 14, 0, 0, 0, 15, 0, 0,
  0, 16, 0, 0, 0, 17, 0, 0, 0, 18, 0, 0, 0, 19, 0, 0, 0, 20,
]);

const AES_KEY: (&str, [u8; 16]) = ("key", [0; 16]);
const AES_IV: (&str, [u8; 12]) = ("iv", [0; 12]);
const AES_AAD: (&str, [u8; 16]) = ("aad", [0; 16]);
// const HTTP_LOCK_VERSION: (&str, [u8; 50]) = ("beginning", [
//   72, 84, 84, 80, 47, 49, 46, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// ]);
// const HTTP_BEGINNING_LENGTH: (&str, [u8; 1]) = ("beginning_length", [8]);
// const HTTP_LOCK_STATUS: (&str, [u8; 200]) = ("middle", [
//   50, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//   0, 0, 0, 0, 0, 0, 0, 0, 0,
// ]);
// const HTTP_MIDDLE_LENGTH: (&str, [u8; 1]) = ("middle_length", [3]);
// const HTTP_LOCK_MESSAGE: (&str, [u8; 50]) = ("final", [
//   79, 75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// ]);
// const HTTP_FINAL_LENGTH: (&str, [u8; 1]) = ("final_length", [2]);
// const HTTP_LOCK_HEADER_NAME: (&str, [u8; 50]) = ("header", [
//   99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// ]);
// const HTTP_LOCK_HEADER_NAME_LENGTH: (&str, [u8; 1]) = ("headerNameLength", [12]);
// const HTTP_LOCK_HEADER_VALUE: (&str, [u8; 100]) = ("value", [
//   97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104,
// 97,   114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// ]);
// const HTTP_LOCK_HEADER_VALUE_LENGTH: (&str, [u8; 1]) = ("headerValueLength", [31]);

const JSON_MASK_KEY_DEPTH_1: (&str, [u8; 10]) = ("key", [100, 97, 116, 97, 0, 0, 0, 0, 0, 0]); // "data"
const JSON_MASK_KEYLEN_DEPTH_1: (&str, [u8; 1]) = ("keyLen", [4]);
const JSON_MASK_KEY_DEPTH_2: (&str, [u8; 10]) = ("key", [105, 116, 101, 109, 115, 0, 0, 0, 0, 0]); // "items"
const JSON_MASK_KEYLEN_DEPTH_2: (&str, [u8; 1]) = ("keyLen", [5]);
const JSON_MASK_ARR_DEPTH_3: (&str, [u8; 1]) = ("index", [0]); // array[0]
const JSON_MASK_KEY_DEPTH_4: (&str, [u8; 10]) =
  ("key", [112, 114, 111, 102, 105, 108, 101, 0, 0, 0]); // "profile"
const JSON_MASK_KEYLEN_DEPTH_4: (&str, [u8; 1]) = ("keyLen", [7]);
const JSON_MASK_KEY_DEPTH_5: (&str, [u8; 10]) = ("key", [110, 97, 109, 101, 0, 0, 0, 0, 0, 0]); // "name"
const JSON_MASK_KEYLEN_DEPTH_5: (&str, [u8; 1]) = ("keyLen", [4]);

const TOTAL_BYTES_ACROSS_NIVC: usize = 512 + 4;

#[test]
#[tracing_test::traced_test]
fn test_end_to_end_proofs() {
  // HTTP/1.1 200 OK
  // content-type: application/json; charset=utf-8
  // content-encoding: gzip
  // Transfer-Encoding: chunked
  //
  // {
  //    "data": {
  //        "items": [
  //            {
  //                "data": "Artist",
  //                "profile": {
  //                    "name": "Taylor Swift"
  //                }
  //            }
  //        ]
  //    }
  // }

  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      // R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),

      // R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      // R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      // R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);
  debug!("Creating ROM");
  let rom_data = HashMap::from([
    (String::from("AES_GCM_1"), CircuitData { opcode: 0 }),
    // (String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData { opcode: 1 }),
    // (String::from("HTTP_LOCK_HEADER_1"), CircuitData { opcode: 2 }),
    // (String::from("HTTP_BODY_MASK"), CircuitData { opcode: 3 }),
    // (String::from("JSON_MASK_OBJECT_1"), CircuitData { opcode: 4 }),
    // (String::from("JSON_MASK_OBJECT_2"), CircuitData { opcode: 4 }),
    // (String::from("JSON_MASK_ARRAY_3"), CircuitData { opcode: 5 }),
    // (String::from("JSON_MASK_OBJECT_4"), CircuitData { opcode: 4 }),
    // (String::from("JSON_MASK_OBJECT_5"), CircuitData { opcode: 4 }),
    // (String::from("EXTRACT_VALUE"), CircuitData { opcode: 6 }),
  ]);

  let aes_rom_opcode_config = InstructionConfig {
    name:          String::from("AES_GCM_1"),
    private_input: HashMap::from([
      (String::from(AES_KEY.0), json!(AES_KEY.1)),
      (String::from(AES_IV.0), json!(AES_IV.1)),
      (String::from(AES_AAD.0), json!(AES_AAD.1)),
    ]),
  };

  debug!("Creating `private_inputs`...");
  let mut rom = vec![aes_rom_opcode_config; HTTP_RESPONSE_PLAINTEXT.1.len() / BYTES_PER_FOLD];
  // rom.extend([
  //   InstructionConfig {
  //     name:          String::from("HTTP_NIVC_1"),
  //     private_input: HashMap::new(),
  //   },
  //   InstructionConfig {
  //     name:          String::from("JSON_MASK_OBJECT_1"),
  //     private_input: HashMap::from([
  //       (String::from(JSON_MASK_KEY_DEPTH_1.0), json!(JSON_MASK_KEY_DEPTH_1.1)),
  //       (String::from(JSON_MASK_KEYLEN_DEPTH_1.0), json!(JSON_MASK_KEYLEN_DEPTH_1.1)),
  //     ]),
  //   },
  //   InstructionConfig {
  //     name:          String::from("JSON_MASK_OBJECT_2"),
  //     private_input: HashMap::from([
  //       (String::from(JSON_MASK_KEY_DEPTH_2.0), json!(JSON_MASK_KEY_DEPTH_2.1)),
  //       (String::from(JSON_MASK_KEYLEN_DEPTH_2.0), json!(JSON_MASK_KEYLEN_DEPTH_2.1)),
  //     ]),
  //   },
  //   InstructionConfig {
  //     name:          String::from("JSON_MASK_ARRAY_3"),
  //     private_input: HashMap::from([(
  //       String::from(JSON_MASK_ARR_DEPTH_3.0),
  //       json!(JSON_MASK_ARR_DEPTH_3.1),
  //     )]),
  //   },
  //   InstructionConfig {
  //     name:          String::from("JSON_MASK_OBJECT_4"),
  //     private_input: HashMap::from([
  //       (String::from(JSON_MASK_KEY_DEPTH_4.0), json!(JSON_MASK_KEY_DEPTH_4.1)),
  //       (String::from(JSON_MASK_KEYLEN_DEPTH_4.0), json!(JSON_MASK_KEYLEN_DEPTH_4.1)),
  //     ]),
  //   },
  //   InstructionConfig {
  //     name:          String::from("JSON_MASK_OBJECT_5"),
  //     private_input: HashMap::from([
  //       (String::from(JSON_MASK_KEY_DEPTH_5.0), json!(JSON_MASK_KEY_DEPTH_5.1)),
  //       (String::from(JSON_MASK_KEYLEN_DEPTH_5.0), json!(JSON_MASK_KEYLEN_DEPTH_5.1)),
  //     ]),
  //   },
  //   InstructionConfig {
  //     name:          String::from("EXTRACT_VALUE"),
  //     private_input: HashMap::new(),
  //   },
  // ]);

  // Fold inputs are unique for each fold
  let inputs = HashMap::from([
    // AES_GCM_1 Inputs
    (String::from("AES_GCM_1"), FoldInput {
      value: HashMap::from([
        (
          String::from(HTTP_RESPONSE_PLAINTEXT.0),
          HTTP_RESPONSE_PLAINTEXT.1.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
        (
          String::from(AES_CIPHER_TEXT.0),
          AES_CIPHER_TEXT.1.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
        (
          String::from(AES_COUNTER.0),
          AES_COUNTER.1.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
        ),
      ]),
    }),
    // HTTP_NIVC_1 Inputs
    // (String::from("HTTP_NIVC_1"), FoldInput {
    //   value: HashMap::from([(
    //     String::from(HTTP_RESPONSE_PLAINTEXT.0),
    //     HTTP_RESPONSE_PLAINTEXT.1.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
    //   )]),
    // }),
  ]);

  let mut initial_nivc_input = vec![data_hasher(&HTTP_RESPONSE_PLAINTEXT.1)];
  // let initial_nivc_input = initial_nivc_input.into_iter().map(u64::from).collect();
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom_data,
    rom,
    initial_nivc_input,
    inputs,
    witnesses: vec![],
  }
  .into_expanded()
  .unwrap();
  debug!("program_data.inputs: {:?}, {:?}", program_data.inputs.len(), program_data.inputs[15]);

  let recursive_snark = program::run(&program_data).unwrap();
  // dbg!(recursive_snark.zi_primary());

  let res = data_hasher(&AES_CIPHER_TEXT.1[304..320]);
  // let res = data_hasher("\"Taylor Swift\"".as_bytes());
  // let final_mem =
  //   res.as_bytes().iter().map(|val| F::<G1>::from(*val as u64)).collect::<Vec<F<G1>>>();

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), res); //
}

#[test]
#[tracing_test::traced_test]
#[ignore]
fn test_offline_proofs() {
  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Wasm {
        path:      String::from(
          "../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b_js/aes_gctr_nivc_512b.wasm",
        ),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from(
          "../proofs/web_proof_circuits/target_512b/http_nivc_512b_js/http_nivc_512b.wasm",
        ),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from("../proofs"),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from("../proofs"),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from("../proofs"),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from("../proofs"),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from("../proofs"),
        wtns_path: String::from("witness.wtns"),
      },
    ],
    max_rom_length:          25,
  };
  let public_params = program::setup(&setup_data);

  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom_data: HashMap::new(),
    rom: vec![],
    initial_nivc_input: vec![],
    inputs: HashMap::new(),
    witnesses: vec![vec![F::<G1>::from(0)]],
  };
  let _ = program_data
    .into_offline(PathBuf::from_str("web_proof_circuits/serialized_setup_aes.bin").unwrap());
}
