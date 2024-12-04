//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use chacha20poly1305::{
  aead::{Aead, Payload},
  ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use client_side_prover::supernova::RecursiveSNARK;
use halo2curves::bn256::Fr;
use program::data::{CircuitData, InstructionConfig};
use serde_json::json;
use witness::{compute_http_witness, compute_json_witness};

use super::*;
use crate::{program::data::NotExpanded, witness::data_hasher};

mod witnesscalc;

const ADD_EXTERNAL_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/add_external.r1cs");
const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/square_zeroth.r1cs");
const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/swap_memory.r1cs");

const EXTERNAL_INPUTS: [[u64; 2]; 2] = [[5, 7], [13, 1]];
const MAX_ROM_LENGTH: usize = 10;

// -----------------------------------------------------------------------------------------------
// JSON Proof Material
const JSON_MAX_ROM_LENGTH: usize = 45;

// Circuit 0
const CHACHA20_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/chacha20_nivc_512b.r1cs");
const CHACHA20_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/chacha20_nivc_512b.bin");

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

// these should be the same for both AES and CHACHA20 since they are both AEADs
const AEAD_IV: (&str, [u8; 12]) = ("iv", [0; 12]);
const AEAD_AAD: (&str, [u8; 16]) = ("aad", [0; 16]);

const CHACHA20_CIPHERTEXT: (&str, [u8; 320]) = ("cipherText", [
  2, 125, 219, 141, 140, 93, 49, 129, 95, 178, 135, 109, 48, 36, 194, 46, 239, 155, 160, 70, 208,
  147, 37, 212, 17, 195, 149, 190, 38, 215, 23, 241, 84, 204, 167, 184, 179, 172, 187, 145, 38, 75,
  123, 96, 81, 6, 149, 36, 135, 227, 226, 254, 177, 90, 241, 159, 0, 230, 183, 163, 210, 88, 133,
  176, 9, 122, 225, 83, 171, 157, 185, 85, 122, 4, 110, 52, 2, 90, 36, 189, 145, 63, 122, 75, 94,
  21, 163, 24, 77, 85, 110, 90, 228, 157, 103, 41, 59, 128, 233, 149, 57, 175, 121, 163, 185, 144,
  162, 100, 17, 34, 9, 252, 162, 223, 59, 221, 106, 127, 104, 11, 121, 129, 154, 49, 66, 220, 65,
  130, 171, 165, 43, 8, 21, 248, 12, 214, 33, 6, 109, 3, 144, 52, 124, 225, 206, 223, 213, 86, 186,
  93, 170, 146, 141, 145, 140, 57, 152, 226, 218, 57, 30, 4, 131, 161, 0, 248, 172, 49, 206, 181,
  47, 231, 87, 72, 96, 139, 145, 117, 45, 77, 134, 249, 71, 87, 178, 239, 30, 244, 156, 70, 118,
  180, 176, 90, 92, 80, 221, 177, 86, 120, 222, 223, 244, 109, 150, 226, 142, 97, 171, 210, 38,
  117, 143, 163, 204, 25, 223, 238, 209, 58, 59, 100, 1, 86, 241, 103, 152, 228, 37, 187, 79, 36,
  136, 133, 171, 41, 184, 145, 146, 45, 192, 173, 219, 146, 133, 12, 246, 190, 5, 54, 99, 155, 8,
  198, 156, 174, 99, 12, 210, 95, 5, 128, 166, 118, 50, 66, 26, 20, 3, 129, 232, 1, 192, 104, 23,
  152, 212, 94, 97, 138, 162, 90, 185, 108, 221, 211, 247, 184, 253, 15, 16, 24, 32, 240, 240, 3,
  148, 89, 30, 54, 161, 131, 230, 161, 217, 29, 229, 251, 33, 220, 230, 102, 131, 245, 27, 141,
  220, 67, 16, 26,
]);
const CHACHA20_KEY: (&str, [u8; 32]) = ("key", [0; 32]);
const CHACHA20_NONCE: (&str, [u8; 12]) = ("nonce", [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]);

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
const MAX_VALUE_LENGTH: usize = 48;

use crate::program::manifest::{make_nonce, to_chacha_input};

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
      R1CSType::Raw(CHACHA20_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(CHACHA20_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_NIVC_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);
  debug!("Creating ROM");
  let rom_data = HashMap::from([
    (String::from("CHACHA20"), CircuitData { opcode: 0 }),
    (String::from("HTTP_NIVC"), CircuitData { opcode: 1 }),
    (String::from("JSON_MASK_OBJECT_1"), CircuitData { opcode: 2 }),
    (String::from("JSON_MASK_OBJECT_2"), CircuitData { opcode: 2 }),
    (String::from("JSON_MASK_ARRAY_3"), CircuitData { opcode: 3 }),
    (String::from("JSON_MASK_OBJECT_4"), CircuitData { opcode: 2 }),
    (String::from("JSON_MASK_OBJECT_5"), CircuitData { opcode: 2 }),
    (String::from("EXTRACT_VALUE"), CircuitData { opcode: 4 }),
  ]);

  debug!("Creating `private_inputs`...");

  let mut padded_plaintext = HTTP_RESPONSE_PLAINTEXT.1.to_vec();
  padded_plaintext.extend(std::iter::repeat(0).take(512 - HTTP_RESPONSE_PLAINTEXT.1.len()));
  assert_eq!(padded_plaintext.len(), 512);

  let write_key = Key::from_slice(&CHACHA20_KEY.1);
  let cipher = ChaCha20Poly1305::new(write_key);
  let nonce = make_nonce(AEAD_IV.1, 0);
  let init_nonce = Nonce::from(nonce.clone());
  let payload = Payload { msg: &padded_plaintext, aad: &AEAD_AAD.1 };
  let ct = cipher.encrypt(&init_nonce, payload).unwrap();

  let tag_begins = ct.len() - 16;
  let sliced_ct = &ct[..tag_begins];

  assert!(padded_plaintext.len() == sliced_ct.len());
  assert_eq!(sliced_ct.len(), 512);
  assert_eq!(nonce.len(), 12);

  let chacha_rom_opcode_config = InstructionConfig {
    name:          String::from("CHACHA20"),
    private_input: HashMap::from([
      (String::from(CHACHA20_KEY.0), json!(to_chacha_input(&CHACHA20_KEY.1))),
      (String::from(CHACHA20_NONCE.0), json!(to_chacha_input(&nonce))),
      (String::from("counter"), json!(to_chacha_input(&[1]))),
      (String::from(CHACHA20_CIPHERTEXT.0), json!(to_chacha_input(sliced_ct))),
      (String::from(HTTP_RESPONSE_PLAINTEXT.0), json!(to_chacha_input(&padded_plaintext))),
    ]),
  };
  let mut rom = vec![chacha_rom_opcode_config];

  // After setting the encryption config for the ROM, pad the plaintext to match what http_nivc_512b
  // requires

  let http_start_line_hash =
    data_hasher(&compute_http_witness(&padded_plaintext, witness::HttpMaskType::StartLine));
  let http_header_1_hash =
    data_hasher(&compute_http_witness(&padded_plaintext, witness::HttpMaskType::Header(1)));
  let http_body = compute_http_witness(&padded_plaintext, witness::HttpMaskType::Body);
  let http_body_hash = data_hasher(&http_body);

  let masked_json_key_1 =
    compute_json_witness(&http_body, witness::JsonMaskType::Object("data".as_bytes().to_vec()));
  let masked_json_key_2 = compute_json_witness(
    &masked_json_key_1,
    witness::JsonMaskType::Object("items".as_bytes().to_vec()),
  );
  let masked_json_key_3 =
    compute_json_witness(&masked_json_key_2, witness::JsonMaskType::ArrayIndex(0));
  let masked_json_key_4 = compute_json_witness(
    &masked_json_key_3,
    witness::JsonMaskType::Object("profile".as_bytes().to_vec()),
  );
  let masked_json_key_5 = compute_json_witness(
    &masked_json_key_4,
    witness::JsonMaskType::Object("name".as_bytes().to_vec()),
  );

  rom.extend([
    InstructionConfig {
      name:          String::from("HTTP_NIVC"),
      private_input: HashMap::from([
        (String::from("data"), json!(padded_plaintext)),
        (
          String::from("start_line_hash"),
          json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_start_line_hash.to_bytes())
            .to_str_radix(10)]),
        ),
        (
          String::from("header_hashes"),
          json!([
            "0".to_string(),
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_header_1_hash.to_bytes())
              .to_str_radix(10),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
          ]),
        ),
        (
          String::from("body_hash"),
          json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_body_hash.to_bytes())
            .to_str_radix(10),]),
        ),
      ]),
    },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_1"),
      private_input: HashMap::from([
        (String::from("data"), json!(http_body)),
        (String::from(JSON_MASK_KEY_DEPTH_1.0), json!(JSON_MASK_KEY_DEPTH_1.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_1.0), json!(JSON_MASK_KEYLEN_DEPTH_1.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_2"),
      private_input: HashMap::from([
        (String::from("data"), json!(masked_json_key_1)),
        (String::from(JSON_MASK_KEY_DEPTH_2.0), json!(JSON_MASK_KEY_DEPTH_2.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_2.0), json!(JSON_MASK_KEYLEN_DEPTH_2.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("JSON_MASK_ARRAY_3"),
      private_input: HashMap::from([
        (String::from("data"), json!(masked_json_key_2)),
        (String::from(JSON_MASK_ARR_DEPTH_3.0), json!(JSON_MASK_ARR_DEPTH_3.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_4"),
      private_input: HashMap::from([
        (String::from("data"), json!(masked_json_key_3)),
        (String::from(JSON_MASK_KEY_DEPTH_4.0), json!(JSON_MASK_KEY_DEPTH_4.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_4.0), json!(JSON_MASK_KEYLEN_DEPTH_4.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("JSON_MASK_OBJECT_5"),
      private_input: HashMap::from([
        (String::from("data"), json!(masked_json_key_4)),
        (String::from(JSON_MASK_KEY_DEPTH_5.0), json!(JSON_MASK_KEY_DEPTH_5.1)),
        (String::from(JSON_MASK_KEYLEN_DEPTH_5.0), json!(JSON_MASK_KEYLEN_DEPTH_5.1)),
      ]),
    },
    InstructionConfig {
      name:          String::from("EXTRACT_VALUE"),
      private_input: HashMap::from([(String::from("data"), json!(masked_json_key_5))]),
    },
  ]);

  // should be zero
  let initial_nivc_input = vec![Fr::ZERO];

  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom_data: rom_data.clone(),
    rom: rom.clone(),
    initial_nivc_input,
    inputs: HashMap::new(),
    witnesses: vec![],
  }
  .into_expanded()
  .unwrap();

  let recursive_snark = program::run(&program_data).unwrap();

  let proof = program::compress_proof(&recursive_snark, &program_data.public_params).unwrap();

  let val = "\"Taylor Swift\"".as_bytes();
  let mut final_value = [0; MAX_VALUE_LENGTH];
  final_value[..val.len()].copy_from_slice(val);

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), data_hasher(&final_value));

  // TODO (autoparallel): This is redundant, we call the setup inside compress_proof. We should
  // likely just store the vk and pk
  let (_pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&program_data.public_params).unwrap();

  let (z0_primary, _) = program_data.extend_public_inputs().unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];
  proof.0.verify(&program_data.public_params, &vk, &z0_primary, &z0_secondary).unwrap();
}

#[test]
#[tracing_test::traced_test]
#[ignore]
fn test_offline_proofs() {
  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(CHACHA20_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
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
    max_rom_length:          JSON_MAX_ROM_LENGTH,
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
