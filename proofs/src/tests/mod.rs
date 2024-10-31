//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use flate2::write::ZlibEncoder;
use program::data::{CircuitData, InstructionConfig};
use proving_ground::supernova::RecursiveSNARK;
use serde_json::json;

use super::*;
use crate::program::data::{FoldInput, NotExpanded};

mod rustwitness;
mod witnesscalc;

const ROM: &[u64] = &[0, 1, 2, 0, 1, 2];

const ADD_EXTERNAL_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/add_external.r1cs");
const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/square_zeroth.r1cs");
const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/swap_memory.r1cs");

const INIT_PUBLIC_INPUT: [u64; 2] = [1, 2];
const EXTERNAL_INPUTS: [[u64; 2]; 2] = [[5, 7], [13, 1]];
const MAX_ROM_LENGTH: usize = 10; // TODO: This should be able to be longer

// -----------------------------------------------------------------------------------------------
// JSON Proof Material
const JSON_MAX_ROM_LENGTH: usize = 35;

const AES_GCM_FOLD_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/aes_gcm_fold/aes_gcm_fold.r1cs");
// Circuit 0
const AES_GCM_R1CS: &[u8] = include_bytes!("../../web_proof_circuits/aes_gcm/aes_gcm.r1cs");
const AES_GCM_GRAPH: &[u8] = include_bytes!("../../web_proof_circuits/aes_gcm/aes_gcm.bin");

// Circuit 1
const HTTP_PARSE_AND_LOCK_START_LINE_R1CS: &[u8] = include_bytes!(
  "../../web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.r1cs"
);
const HTTP_PARSE_AND_LOCK_START_LINE_WASM: &str =
  "../../web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line_js/\
   http_parse_and_lock_start_line.wasm";
const HTTP_PARSE_AND_LOCK_START_LINE_GRAPH: &[u8] = include_bytes!(
  "../../web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.bin"
);

// Circuit 2
const HTTP_LOCK_HEADER_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/http_lock_header/http_lock_header.r1cs");
const HTTP_LOCK_HEADER_WASM: &str =
  "../../web_proof_circuits/http_lock_header/http_lock_header_js/http_lock_header.wasm";
const HTTP_LOCK_HEADER_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/http_lock_header/http_lock_header.bin");

// Circuit 3
const HTTP_BODY_MASK_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/http_body_mask/http_body_mask.r1cs");
const HTTP_BODY_MASK_WASM: &str =
  "../../web_proof_circuits/http_body_mask/http_body_mask_js/http_body_mask.wasm";

const HTTP_BODY_MASK_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/http_body_mask/http_body_mask.bin");

// Circuit 4
const JSON_PARSE_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/json_parse/json_parse.r1cs");
const JSON_PARSE_WASM: &str = "../../web_proof_circuits/json_parse/json_parse_js/json_parse.wasm";
const JSON_PARSE_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/json_parse/json_parse.bin");

// Circuit 5
const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_object/json_mask_object.r1cs");
const JSON_MASK_OBJECT_WASM: &str =
  "../../web_proof_circuits/json_mask_object/json_mask_object_js/json_mask_object.wasm";
const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_object/json_mask_object.bin");

// Circuit 6
const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_array_index/json_mask_array_index.r1cs");
const JSON_MASK_ARRAY_WASM: &str =
  "../../web_proof_circuits/json_mask_array/json_mask_array_js/json_mask_array.wasm";
const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_array_index/json_mask_array_index.bin");

// circuit 7
const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/extract_value/extract_value.r1cs");
const EXTRACT_VALUE_WASM: &str =
  "../../web_proof_circuits/extract_value/extract_value_js/extract_value.wasm";
const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/extract_value/extract_value.bin");

const BYTES_PER_FOLD: usize = 16;
const AES_BYTES: [u8; 50] = [0; 50];

const AES_PLAINTEXT: (&str, [u8; 320]) = ("plainText", [
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

const AES_KEY: (&str, [u8; 16]) =
  ("key", [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]);
const AES_IV: (&str, [u8; 12]) = ("iv", [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49]);
const AES_AAD: (&str, [u8; 16]) = ("aad", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const HTTP_LOCK_VERSION: (&str, [u8; 8]) = ("beginning", [72, 84, 84, 80, 47, 49, 46, 49]);
const HTTP_LOCK_STATUS: (&str, [u8; 3]) = ("middle", [50, 48, 48]);
const HTTP_LOCK_MESSAGE: (&str, [u8; 2]) = ("final", [79, 75]);
const HTTP_LOCK_HEADER_NAME: (&str, [u8; 12]) =
  ("header", [99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101]);
const HTTP_LOCK_HEADER_VALUE: (&str, [u8; 31]) = ("value", [
  97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104, 97,
  114, 115, 101, 116, 61, 117, 116, 102, 45, 56,
]);

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

// TODO (Colin): This test requires JSON parse between all the JSON steps. REMOVE THIS REDUNDANCY
// USING NEW CIRCUITS!
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
      R1CSType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_R1CS.to_vec()),
      R1CSType::Raw(HTTP_LOCK_HEADER_R1CS.to_vec()),
      R1CSType::Raw(HTTP_BODY_MASK_R1CS.to_vec()),
      R1CSType::Raw(JSON_PARSE_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      // WitnessGeneratorType::Wasm {
      //   path:      String::from("../proofs/web_proof_circuits/aes_gcm/aes_gcm_js/aes_gcm.wasm"),
      //   wtns_path: String::from("witness.wtns"),
      // },
      WitnessGeneratorType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_LOCK_HEADER_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_BODY_MASK_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_PARSE_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);

  // Dealloc the R1CSWithArity vec
  let (_, aux_params) = public_params.into_parts();
  let public_params = PublicParams::from_parts_unchecked(vec![], aux_params);

  // Check size of PP
  // let serialized = bincode::serialize(&public_params).unwrap();
  // let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
  // encoder.write_all(&serialized).unwrap();
  // let compressed = encoder.finish().unwrap();
  // debug!("Length of serialized PP: {:?}", compressed.len());

  debug!("Creating ROM");
  let rom_data = HashMap::from([
    (String::from("AES_GCM_1"), CircuitData { opcode: 0 }),
    (String::from("HTTP_PARSE_AND_LOCK_START_LINE"), CircuitData { opcode: 1 }),
    (String::from("HTTP_LOCK_HEADER_1"), CircuitData { opcode: 2 }),
    (String::from("HTTP_BODY_EXTRACT"), CircuitData { opcode: 3 }),
    (String::from("JSON_PARSE"), CircuitData { opcode: 4 }),
    (String::from("JSON_MASK_OBJECT_1"), CircuitData { opcode: 5 }),
    (String::from("JSON_MASK_OBJECT_2"), CircuitData { opcode: 5 }),
    (String::from("JSON_MASK_ARRAY_3"), CircuitData { opcode: 6 }),
    (String::from("JSON_MASK_OBJECT_4"), CircuitData { opcode: 5 }),
    (String::from("JSON_MASK_OBJECT_5"), CircuitData { opcode: 5 }),
    (String::from("EXTRACT_VALUE"), CircuitData { opcode: 7 }),
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
  let mut rom = vec![aes_rom_opcode_config; AES_PLAINTEXT.1.len() / BYTES_PER_FOLD];
  rom.extend([
    // let rom = vec![
    InstructionConfig {
      name:          String::from("HTTP_PARSE_AND_LOCK_START_LINE"),
      private_input: HashMap::from([
        (String::from(HTTP_LOCK_VERSION.0), json!(HTTP_LOCK_VERSION.1)),
        (String::from(HTTP_LOCK_MESSAGE.0), json!(HTTP_LOCK_MESSAGE.1)),
        (String::from(HTTP_LOCK_STATUS.0), json!(HTTP_LOCK_STATUS.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("HTTP_LOCK_HEADER_1"),
      private_input: HashMap::from([
        (String::from(HTTP_LOCK_HEADER_NAME.0), json!(HTTP_LOCK_HEADER_NAME.1)),
        (String::from(HTTP_LOCK_HEADER_VALUE.0), json!(HTTP_LOCK_HEADER_VALUE.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("HTTP_BODY_EXTRACT"),
      private_input: HashMap::new(),
    },
    InstructionConfig { name: String::from("JSON_PARSE"), private_input: HashMap::new() },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_1"),
      private_input: HashMap::from([
        (String::from(JSON_MASK_KEY_DEPTH_1.0), json!(JSON_MASK_KEY_DEPTH_1.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_1.0), json!(JSON_MASK_KEYLEN_DEPTH_1.1)),
      ]),
    },
    InstructionConfig { name: String::from("JSON_PARSE"), private_input: HashMap::new() },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_2"),
      private_input: HashMap::from([
        (String::from(JSON_MASK_KEY_DEPTH_2.0), json!(JSON_MASK_KEY_DEPTH_2.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_2.0), json!(JSON_MASK_KEYLEN_DEPTH_2.1)),
      ]),
    },
    InstructionConfig { name: String::from("JSON_PARSE"), private_input: HashMap::new() },
    InstructionConfig {
      name:          String::from("JSON_MASK_ARRAY_3"),
      private_input: HashMap::from([(
        String::from(JSON_MASK_ARR_DEPTH_3.0),
        json!(JSON_MASK_ARR_DEPTH_3.1),
      )]),
    },
    InstructionConfig { name: String::from("JSON_PARSE"), private_input: HashMap::new() },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_4"),
      private_input: HashMap::from([
        (String::from(JSON_MASK_KEY_DEPTH_4.0), json!(JSON_MASK_KEY_DEPTH_4.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_4.0), json!(JSON_MASK_KEYLEN_DEPTH_4.1)),
      ]),
    },
    InstructionConfig { name: String::from("JSON_PARSE"), private_input: HashMap::new() },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_5"),
      private_input: HashMap::from([
        (String::from(JSON_MASK_KEY_DEPTH_5.0), json!(JSON_MASK_KEY_DEPTH_5.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_5.0), json!(JSON_MASK_KEYLEN_DEPTH_5.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("EXTRACT_VALUE"),
      private_input: HashMap::new(),
    },
  ]);

  let inputs = HashMap::from([(String::from("AES_GCM_1"), FoldInput {
    value: HashMap::from([(
      String::from(AES_PLAINTEXT.0),
      AES_PLAINTEXT.1.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
    )]),
  })]);

  let mut initial_nivc_input = AES_BYTES.to_vec();
  initial_nivc_input.extend(AES_PLAINTEXT.1.iter());
  initial_nivc_input.resize(4160, 0); // TODO: This is currently the `TOTAL_BYTES` used in circuits
  let initial_nivc_input = initial_nivc_input.into_iter().map(u64::from).collect();
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom_data,
    rom,
    initial_nivc_input,
    inputs,
    witnesses: vec![],
  }
  .into_expanded();
  debug!("program_data.inputs: {:?}, {:?}", program_data.inputs.len(), program_data.inputs[15]);

  let recursive_snark = program::run(&program_data);
  // dbg!(recursive_snark.zi_primary());

  let res = "\"Taylor Swift\"";
  let final_mem =
    res.as_bytes().iter().map(|val| F::<G1>::from(*val as u64)).collect::<Vec<F<G1>>>();

  assert_eq!(recursive_snark.zi_primary()[..res.len()], final_mem);
}

#[test]
#[tracing_test::traced_test]
#[ignore]
fn test_offline_proofs() {
  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_FOLD_R1CS.to_vec()),
      // R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      // R1CSType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_R1CS.to_vec()),
      // R1CSType::Raw(HTTP_LOCK_HEADER_R1CS.to_vec()),
      // R1CSType::Raw(HTTP_BODY_MASK_R1CS.to_vec()),
      // R1CSType::Raw(JSON_PARSE_R1CS.to_vec()),
      // R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      // R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      // R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Wasm {
        path:      String::from(
          "../proofs/web_proof_circuits/aes_gcm_fold/aes_gcm_fold_js/aes_gcm_fold.wasm",
        ),
        wtns_path: "witness.wtns".to_string(),
      },
      // WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      // WitnessGeneratorType::Wasm {
      //   path:      String::from("../proofs/web_proof_circuits/aes_gcm/aes_gcm_js/aes_gcm.wasm"),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_GRAPH.to_vec()),
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(HTTP_PARSE_AND_LOCK_START_LINE_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(HTTP_LOCK_HEADER_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(HTTP_BODY_MASK_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(JSON_PARSE_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(JSON_MASK_OBJECT_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(JSON_MASK_ARRAY_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Wasm {
      //   path:      String::from(EXTRACT_VALUE_WASM),
      //   wtns_path: String::from("witness.wtns"),
      // },
      // WitnessGeneratorType::Raw(HTTP_LOCK_HEADER_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(HTTP_BODY_MASK_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_PARSE_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          10,
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
  program_data
    .into_offline(PathBuf::from_str("web_proof_circuits/serialized_setup_no_aes.bin").unwrap());
} // #[test]// fn manifest(
