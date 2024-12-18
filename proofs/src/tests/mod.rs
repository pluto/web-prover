//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use client_side_prover::supernova::RecursiveSNARK;
use program::manifest::JsonKey;
use serde_json::json;
use witness::{compress_tree_hash, json_tree_hasher, polynomial_digest};

use super::*;
use crate::{
  program::{
    data::{CircuitData, NotExpanded},
    manifest::to_chacha_input,
  },
  witness::{compute_http_witness, data_hasher, ByteOrPad},
};

mod witnesscalc;

const CIRCUIT_SIZE: usize = 1024;
const MAX_ROM_LENGTH: usize = 3;
const MAX_STACK_HEIGHT: usize = 10;
const MAX_HTTP_HEADERS: usize = 25;

// Circuit 0
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_1024b/plaintext_authentication_1024b.r1cs");
const PLAINTEXT_AUTHENTICATION_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_1024b/plaintext_authentication_1024b.bin");

// Circuit 1
const HTTP_VERIFICATION_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_1024b/http_verification_1024b.r1cs");
const HTTP_VERIFICATION_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_1024b/http_verification_1024b.bin");

// Circuit 2
const JSON_EXTRACTION_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_1024b/json_extraction_1024b.r1cs");
const JSON_EXTRACTION_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_1024b/json_extraction_1024b.bin");

const MAX_ROM_LENGTH_512: usize = 3;

// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/plaintext_authentication_512b.r1cs");

// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/http_verification_512b.r1cs");

// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/json_extraction_512b.r1cs");

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
const HTTP_RESPONSE_PLAINTEXT: (&str, [u8; 320]) = ("plaintext", [
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

use crate::program::manifest::{Manifest, Request, Response, ResponseBody};

pub fn mock_manifest() -> Manifest {
  let request = Request {
    method:  "GET".to_string(),
    url:     "spotify.com".to_string(),
    version: "HTTP/1.1".to_string(),
    headers: HashMap::new(),
  };
  let mut headers = HashMap::new();
  headers.insert("content-type".to_string(), "application/json; charset=utf-8".to_string());
  headers.insert("content-encoding".to_string(), "gzip".to_string());
  let body = ResponseBody {
    json: vec![
      JsonKey::String("data".to_string()),
      JsonKey::String("items".to_string()),
      JsonKey::Num(0),
      JsonKey::String("profile".to_string()),
      JsonKey::String("name".to_string()),
    ],
  };
  let response = Response {
    status: "200".to_string(),
    version: "HTTP/1.1".to_string(),
    message: "OK".to_string(),
    headers,
    body,
  };
  Manifest { request, response }
}

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
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_EXTRACTION_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);
  debug!("Creating ROM");
  let rom_data = HashMap::from([
    (String::from("PLAINTEXT_AUTHENTICATION"), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION"), CircuitData { opcode: 1 }),
    (String::from("JSON_EXTRACTION"), CircuitData { opcode: 2 }),
  ]);

  debug!("Creating `private_inputs`...");

  let nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];

  let padded_plaintext = ByteOrPad::from_bytes_with_padding(
    &HTTP_RESPONSE_PLAINTEXT.1,
    1024 - HTTP_RESPONSE_PLAINTEXT.1.len(),
  );

  let padded_ciphertext =
    ByteOrPad::from_bytes_with_padding(&CHACHA20_CIPHERTEXT.1, 1024 - CHACHA20_CIPHERTEXT.1.len());

  assert!(padded_plaintext.len() == padded_ciphertext.len());
  assert_eq!(padded_ciphertext.len(), 1024);

  let (ciphertext_digest, init_nivc_input) = crate::witness::response_initial_digest(
    &mock_manifest().response,
    &padded_ciphertext,
    MAX_STACK_HEIGHT,
  );
  let mut private_inputs = vec![];

  let mut rom = vec![String::from("PLAINTEXT_AUTHENTICATION")];
  private_inputs.push(HashMap::from([
    (String::from(CHACHA20_KEY.0), json!(to_chacha_input(&CHACHA20_KEY.1))),
    (String::from(CHACHA20_NONCE.0), json!(to_chacha_input(&nonce))),
    (String::from("counter"), json!(to_chacha_input(&[1]))),
    (String::from(HTTP_RESPONSE_PLAINTEXT.0), json!(&padded_plaintext)),
  ]));

  let http_start_line = compute_http_witness(&padded_plaintext, witness::HttpMaskType::StartLine);
  let http_start_line_digest =
    polynomial_digest(&ByteOrPad::as_bytes(&http_start_line), ciphertext_digest);
  let http_header_0_digest = polynomial_digest(
    &ByteOrPad::as_bytes(&compute_http_witness(
      &padded_plaintext,
      witness::HttpMaskType::Header(0),
    )),
    ciphertext_digest,
  );
  let http_header_1_digest = polynomial_digest(
    &ByteOrPad::as_bytes(&compute_http_witness(
      &padded_plaintext,
      witness::HttpMaskType::Header(1),
    )),
    ciphertext_digest,
  );

  let mut http_body = compute_http_witness(&padded_plaintext, witness::HttpMaskType::Body);
  http_body.resize(CIRCUIT_SIZE, ByteOrPad::Pad);

  let mut main_digests = vec![
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_start_line_digest.to_bytes())
      .to_str_radix(10),
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_header_0_digest.to_bytes())
      .to_str_radix(10),
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_header_1_digest.to_bytes())
      .to_str_radix(10),
  ];
  main_digests.resize(MAX_HTTP_HEADERS + 1, "0".to_string());

  assert_eq!(main_digests.len(), MAX_HTTP_HEADERS + 1);

  rom.push(String::from("HTTP_VERIFICATION"));
  private_inputs.push(HashMap::from([
    (String::from("data"), json!(&padded_plaintext)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
    (String::from("main_digests"), json!(main_digests)),
  ]));

  let key_sequence = [
    JsonKey::String(String::from("data")),
    JsonKey::String(String::from("items")),
    JsonKey::Num(0),
    JsonKey::String(String::from("profile")),
    JsonKey::String(String::from("name")),
  ];
  let sequence_digest = compress_tree_hash(
    ciphertext_digest,
    json_tree_hasher(ciphertext_digest, &key_sequence, MAX_STACK_HEIGHT),
  );
  let val = "Taylor Swift".as_bytes();
  let value_digest = &polynomial_digest(val, ciphertext_digest);

  rom.push(String::from("JSON_EXTRACTION"));
  private_inputs.push(HashMap::from([
    (String::from("data"), json!(&http_body)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
    (
      String::from("value_digest"),
      json!(
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &value_digest.to_bytes()).to_str_radix(10)
      ),
    ),
    (
      String::from("sequence_digest"),
      json!(
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &sequence_digest.to_bytes()).to_str_radix(10)
      ),
    ),
  ]));

  let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let vk_digest_primary = pk.pk_primary.vk_digest;
  let vk_digest_secondary = pk.pk_secondary.vk_digest;
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    vk_digest_primary,
    vk_digest_secondary,
    setup_data,
    rom_data: rom_data.clone(),
    rom: rom.clone(),
    initial_nivc_input: vec![init_nivc_input],
    inputs: (private_inputs, HashMap::new()),
    witnesses: vec![],
  }
  .into_expanded()
  .unwrap();

  let recursive_snark = program::run(&program_data).unwrap();

  let proof = program::compress_proof_no_setup(
    &recursive_snark,
    &program_data.public_params,
    vk_digest_primary,
    vk_digest_secondary,
  )
  .unwrap();

  // TODO (autoparallel): This is redundant, we call the setup inside compress_proof. We should
  // likely just store the vk and pk
  let (_pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&program_data.public_params).unwrap();

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), *value_digest);

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
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
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
    ],
    max_rom_length:          MAX_ROM_LENGTH_512,
  };
  let public_params = program::setup(&setup_data);
  let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();

  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    vk_digest_primary: pk.pk_primary.vk_digest,
    vk_digest_secondary: pk.pk_secondary.vk_digest,
    rom_data: HashMap::new(),
    rom: vec![],
    initial_nivc_input: vec![],
    inputs: (vec![], HashMap::new()),
    witnesses: vec![vec![F::<G1>::from(0)]],
  };
  let _ = program_data
    .into_offline(PathBuf::from_str("web_proof_circuits/serialized_setup.bin").unwrap());
}

#[test]
#[tracing_test::traced_test]
#[ignore]
fn test_compressed_proof_params() {
  let setup_data = SetupData {
    r1cs_types:             vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
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
      }
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  };

  let public_params = program::setup(&setup_data);
  let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    vk_digest_primary: pk.pk_primary.vk_digest,
    vk_digest_secondary: pk.pk_secondary.vk_digest,
    setup_data,
    rom_data: HashMap::new(),
    rom: vec![],
    initial_nivc_input: vec![],
    inputs: (vec![], HashMap::new()),
    witnesses: vec![vec![F::<G1>::from(0)]],
  };
  let _ = program_data
    .into_offline(PathBuf::from_str("web_proof_circuits/serialized_setup_aes.bin").unwrap());
}
