//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

use proving_ground::supernova::RecursiveSNARK;
use serde_json::json;

use super::*;
use crate::program::data::{Input, NotExpanded};

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
// // JSON Proof Material
const JSON_ROM: [u8; 9] = [0, 1, 2, 3, 4, 4, 5, 4, 4];
const JSON_MAX_ROM_LENGTH: usize = 9;

// Circuit 0
const HTTP_PARSE_AND_LOCK_START_LINE_R1CS: &[u8] = include_bytes!(
  "../../web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.r1cs"
);
const HTTP_PARSE_AND_LOCK_START_LINE_GRAPH: &[u8] = include_bytes!(
  "../../web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.bin"
);

// Circuit 1
const HTTP_LOCK_HEADER_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/http_lock_header/http_lock_header.r1cs");
const HTTP_LOCK_HEADER_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/http_lock_header/http_lock_header.bin");

// Circuit 2
const HTTP_BODY_MASK_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/http_body_mask/http_body_mask.r1cs");
const HTTP_BODY_MASK_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/http_body_mask/http_body_mask.bin");

// Circuit 3
const JSON_PARSE_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/json_parse/json_parse.r1cs");
const JSON_PARSE_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/json_parse/json_parse.bin");

// Circuit 4
const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_object/json_mask_object.r1cs");
const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_object/json_mask_object.bin");

// Circuit 5
const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_array_index/json_mask_array_index.r1cs");
const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/json_mask_array_index/json_mask_array_index.bin");

const AES_BYTES: [u8; 50] = [0; 50];

const PLAIN_TEXT: [u8; 320] = [
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
];

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
      R1CSType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_R1CS.to_vec()),
      R1CSType::Raw(HTTP_LOCK_HEADER_R1CS.to_vec()),
      R1CSType::Raw(HTTP_BODY_MASK_R1CS.to_vec()),
      R1CSType::Raw(JSON_PARSE_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_LOCK_HEADER_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_BODY_MASK_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_PARSE_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);

  // Check size of PP
  // let serialized = bincode::serialize(&public_params).unwrap();
  // let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
  // encoder.write_all(&serialized).unwrap();
  // let compressed = encoder.finish().unwrap();
  // debug!("Length of serialized PP: {:?}", compressed.len());

  debug!("Creating `private_inputs`...");
  let mut private_inputs = HashMap::new();
  // Lock start line information
  private_inputs.insert(HTTP_LOCK_VERSION.0.to_owned(), Input {
    start_index: 0,
    end_index:   0,
    value:       HTTP_LOCK_VERSION.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(HTTP_LOCK_STATUS.0.to_owned(), Input {
    start_index: 0,
    end_index:   0,
    value:       HTTP_LOCK_STATUS.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(HTTP_LOCK_MESSAGE.0.to_owned(), Input {
    start_index: 0,
    end_index:   0,
    value:       HTTP_LOCK_MESSAGE.1.iter().map(|x| json!(x)).collect(),
  });

  // Lock header information
  private_inputs.insert(HTTP_LOCK_HEADER_NAME.0.to_owned(), Input {
    start_index: 1,
    end_index:   1,
    value:       HTTP_LOCK_HEADER_NAME.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(HTTP_LOCK_HEADER_VALUE.0.to_owned(), Input {
    start_index: 1,
    end_index:   1,
    value:       HTTP_LOCK_HEADER_VALUE.1.iter().map(|x| json!(x)).collect(),
  });

  // JSON Mask KV 1
  private_inputs.insert(JSON_MASK_KEY_DEPTH_1.0.to_owned(), Input {
    start_index: 4,
    end_index:   4,
    value:       JSON_MASK_KEY_DEPTH_1.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(JSON_MASK_KEYLEN_DEPTH_1.0.to_owned(), Input {
    start_index: 4,
    end_index:   4,
    value:       JSON_MASK_KEYLEN_DEPTH_1.1.iter().map(|x| json!(x)).collect(),
  });

  // JSON Mask KV 2
  private_inputs.insert(JSON_MASK_KEY_DEPTH_2.0.to_owned(), Input {
    start_index: 5,
    end_index:   5,
    value:       JSON_MASK_KEY_DEPTH_2.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(JSON_MASK_KEYLEN_DEPTH_2.0.to_owned(), Input {
    start_index: 5,
    end_index:   5,
    value:       JSON_MASK_KEYLEN_DEPTH_2.1.iter().map(|x| json!(x)).collect(),
  });

  // JSON Mask array index 0 depth 3
  private_inputs.insert(JSON_MASK_ARR_DEPTH_3.0.to_owned(), Input {
    start_index: 6,
    end_index:   6,
    value:       JSON_MASK_ARR_DEPTH_3.1.iter().map(|x| json!(x)).collect(),
  });

  // JSON Mask KV 4
  private_inputs.insert(JSON_MASK_KEY_DEPTH_4.0.to_owned(), Input {
    start_index: 7,
    end_index:   7,
    value:       JSON_MASK_KEY_DEPTH_4.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(JSON_MASK_KEYLEN_DEPTH_4.0.to_owned(), Input {
    start_index: 7,
    end_index:   7,
    value:       JSON_MASK_KEYLEN_DEPTH_4.1.iter().map(|x| json!(x)).collect(),
  });

  // JSON Mask KV 5
  private_inputs.insert(JSON_MASK_KEY_DEPTH_5.0.to_owned(), Input {
    start_index: 8,
    end_index:   8,
    value:       JSON_MASK_KEY_DEPTH_5.1.iter().map(|x| json!(x)).collect(),
  });
  private_inputs.insert(JSON_MASK_KEYLEN_DEPTH_5.0.to_owned(), Input {
    start_index: 8,
    end_index:   8,
    value:       JSON_MASK_KEYLEN_DEPTH_5.1.iter().map(|x| json!(x)).collect(),
  });

  let mut initial_nivc_input = AES_BYTES.to_vec();
  initial_nivc_input.extend(PLAIN_TEXT.iter());
  initial_nivc_input.resize(4160, 0); // TODO: This is currently the `TOTAL_BYTES` used in circuits
  let initial_nivc_input = initial_nivc_input.into_iter().map(u64::from).collect();
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom: JSON_ROM.into_iter().map(u64::from).collect(),
    initial_nivc_input,
    private_inputs,
    witnesses: vec![],
  }
  .into_expanded();
  let recursive_snark = program::run(&program_data);
  dbg!(recursive_snark.zi_primary());

  // let res = "\"Taylor Swift\"";
  // let final_mem =
  //   res.as_bytes().into_iter().map(|val| F::<G1>::from(*val as u64)).collect::<Vec<F<G1>>>();

  // assert_eq!(recursive_snark.zi_primary()[..res.len()], final_mem);
}
