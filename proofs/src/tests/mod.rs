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
    manifest::{
      make_nonce, to_chacha_input, EncryptionInput, Manifest, Request, Response, ResponseBody,
    },
  },
  witness::{compute_http_witness, ByteOrPad},
};

mod witnesscalc;

const CIRCUIT_SIZE: usize = 1024;
const MAX_ROM_LENGTH: usize = 5;
const MAX_STACK_HEIGHT: usize = 10;
const MAX_HTTP_HEADERS: usize = 25;

// Circuit 0
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] = include_bytes!(
  "../../web_proof_circuits/circom-artifacts-1024b-v0.8.0/plaintext_authentication_1024b.r1cs"
);
const PLAINTEXT_AUTHENTICATION_GRAPH: &[u8] = include_bytes!(
  "../../web_proof_circuits/circom-artifacts-1024b-v0.8.0/plaintext_authentication_1024b.bin"
);

// Circuit 1
const HTTP_VERIFICATION_R1CS: &[u8] = include_bytes!(
  "../../web_proof_circuits/circom-artifacts-1024b-v0.8.0/http_verification_1024b.r1cs"
);
const HTTP_VERIFICATION_GRAPH: &[u8] = include_bytes!(
  "../../web_proof_circuits/circom-artifacts-1024b-v0.8.0/http_verification_1024b.bin"
);

// Circuit 2
const JSON_EXTRACTION_R1CS: &[u8] = include_bytes!(
  "../../web_proof_circuits/circom-artifacts-1024b-v0.8.0/json_extraction_1024b.r1cs"
);
const JSON_EXTRACTION_GRAPH: &[u8] = include_bytes!(
  "../../web_proof_circuits/circom-artifacts-1024b-v0.8.0/json_extraction_1024b.bin"
);

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

pub fn mock_manifest() -> Manifest {
  let request = Request {
    method:  "GET".to_string(),
    url:     "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json".to_string(),
    version: "HTTP/1.1".to_string(),
    headers: HashMap::from([
      ("accept-encoding".to_string(), "identity".to_string()),
    ]),
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
fn test_end_to_end_proofs_res() {
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
    &[padded_ciphertext],
    MAX_STACK_HEIGHT,
  );
  let mut private_inputs = vec![];

  debug!("Creating ROM...");
  let mut rom = vec![String::from("PLAINTEXT_AUTHENTICATION")];
  private_inputs.push(HashMap::from([
    (String::from(CHACHA20_KEY.0), json!(to_chacha_input(&CHACHA20_KEY.1))),
    (String::from(CHACHA20_NONCE.0), json!(to_chacha_input(&nonce))),
    (String::from("counter"), json!(to_chacha_input(&[1]))),
    (String::from(HTTP_RESPONSE_PLAINTEXT.0), json!(&padded_plaintext)),
    (String::from("plaintext_index_counter"), json!(0)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
  ]));

  debug!("Creating HTTP verification private inputs...");
  let http_start_line = compute_http_witness(&padded_plaintext, witness::HttpMaskType::StartLine);
  let http_start_line_digest =
    polynomial_digest(&ByteOrPad::as_bytes(&http_start_line), ciphertext_digest, 0);
  let http_header_0_digest = polynomial_digest(
    &ByteOrPad::as_bytes(&compute_http_witness(
      &padded_plaintext,
      witness::HttpMaskType::Header(0),
    )),
    ciphertext_digest,
    0,
  );
  let http_header_1_digest = polynomial_digest(
    &ByteOrPad::as_bytes(&compute_http_witness(
      &padded_plaintext,
      witness::HttpMaskType::Header(1),
    )),
    ciphertext_digest,
    0,
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
  let value_digest = &polynomial_digest(val, ciphertext_digest, 0);

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

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), *value_digest);

  let (z0_primary, _) = program_data.extend_public_inputs(None).unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];
  proof.proof.verify(&program_data.public_params, &vk, &z0_primary, &z0_secondary).unwrap();
}

#[test]
#[tracing_test::traced_test]
fn test_end_to_end_proofs_req() {
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
  ]);

  debug!("Creating `private_inputs`...");

  let inputs = EncryptionInput {
    plaintext:  vec![vec![
      71, 69, 84, 32, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 115, 116, 46, 103, 105, 116,
      104, 117, 98, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109, 47,
      109, 97, 116, 116, 101, 115, 47, 50, 51, 101, 54, 52, 102, 97, 97, 100, 98, 53, 102, 100, 52,
      98, 53, 49, 49, 50, 102, 51, 55, 57, 57, 48, 51, 100, 50, 53, 55, 50, 101, 47, 114, 97, 119,
      47, 55, 52, 101, 53, 49, 55, 97, 54, 48, 99, 50, 49, 97, 53, 99, 49, 49, 100, 57, 52, 102,
      101, 99, 56, 98, 53, 55, 50, 102, 54, 56, 97, 100, 100, 102, 97, 100, 101, 51, 57, 47, 101,
      120, 97, 109, 112, 108, 101, 46, 106, 115, 111, 110, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13,
      10, 104, 111, 115, 116, 58, 32, 103, 105, 115, 116, 46, 103, 105, 116, 104, 117, 98, 117,
      115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109, 13, 10, 97, 99, 99, 101,
      112, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 105, 100, 101, 110, 116, 105,
      116, 121, 13, 10, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 99, 108, 111, 115,
      101, 13, 10, 97, 99, 99, 101, 112, 116, 58, 32, 42, 47, 42, 13, 10, 13, 10,
    ]],
    ciphertext: vec![vec![
      114, 67, 112, 145, 73, 101, 195, 249, 148, 201, 104, 46, 40, 108, 148, 129, 230, 123, 101,
      28, 220, 78, 139, 5, 201, 178, 241, 242, 135, 147, 209, 137, 225, 80, 118, 36, 169, 179, 132,
      189, 74, 34, 29, 142, 122, 215, 129, 144, 142, 136, 41, 73, 154, 17, 78, 60, 30, 252, 184,
      64, 13, 212, 173, 153, 33, 5, 176, 163, 60, 6, 230, 74, 161, 71, 3, 206, 206, 225, 29, 136,
      22, 25, 98, 240, 42, 106, 185, 71, 67, 189, 201, 191, 69, 48, 113, 158, 172, 82, 141, 216,
      64, 97, 244, 183, 52, 250, 131, 212, 151, 198, 113, 157, 13, 89, 134, 219, 71, 122, 68, 188,
      67, 27, 149, 33, 223, 9, 17, 127, 104, 30, 109, 136, 154, 49, 162, 66, 0, 163, 120, 214, 117,
      155, 225, 169, 81, 97, 69, 147, 212, 12, 70, 41, 121, 173, 240, 125, 248, 79, 24, 113, 145,
      234, 134, 222, 141, 148, 238, 38, 209, 151, 159, 30, 238, 157, 198, 204, 112, 216, 74, 50,
      190, 252, 12, 70, 231, 127, 22, 162, 152, 187, 3, 143, 242, 56, 213, 2, 28, 128, 180, 181,
      200, 105, 17, 31, 27, 229, 128, 101, 247, 129, 20, 130, 164, 186, 62, 135, 40, 122, 191, 250,
      177, 83, 114, 91, 242, 61, 4, 184, 83, 241, 194, 82, 96, 68, 102, 86, 142, 212, 252, 178,
      119, 69,
    ]],
    key:        tls_client2::CipherSuiteKey::CHACHA20POLY1305([
      199, 50, 208, 167, 227, 199, 157, 36, 9, 53, 75, 191, 225, 162, 224, 154, 218, 69, 234, 24,
      133, 126, 235, 87, 101, 98, 143, 51, 174, 131, 107, 64,
    ]),
    iv:         [54, 152, 119, 92, 141, 62, 208, 102, 28, 88, 154, 177],
    aad:        vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 3, 3, 1, 3],
    seq:        0,
  };

  let padded_plaintext =
    ByteOrPad::from_bytes_with_padding(&inputs.plaintext[0], 1024 - inputs.plaintext[0].len());

  let padded_ciphertext =
    ByteOrPad::from_bytes_with_padding(&inputs.ciphertext[0], 1024 - inputs.ciphertext[0].len());

  assert!(padded_plaintext.len() == padded_ciphertext.len());
  assert_eq!(padded_ciphertext.len(), 1024);

  let (ciphertext_digest, init_nivc_input) =
    crate::witness::request_initial_digest(&mock_manifest().request, &[padded_ciphertext]);
  let mut private_inputs = vec![];

  debug!("Creating ROM...");
  let mut rom = vec![String::from("PLAINTEXT_AUTHENTICATION")];
  private_inputs.push(HashMap::from([
    (String::from(CHACHA20_KEY.0), json!(to_chacha_input(inputs.key.as_ref()))),
    (String::from(CHACHA20_NONCE.0), json!(to_chacha_input(&make_nonce(inputs.iv, inputs.seq)))),
    (String::from("counter"), json!(to_chacha_input(&[1]))),
    (String::from(HTTP_RESPONSE_PLAINTEXT.0), json!(&padded_plaintext)),
    (String::from("plaintext_index_counter"), json!(0)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
  ]));

  debug!("Creating HTTP verification private inputs...");
  let http_start_line = compute_http_witness(&padded_plaintext, witness::HttpMaskType::StartLine);
  let http_start_line_digest =
    polynomial_digest(&ByteOrPad::as_bytes(&http_start_line), ciphertext_digest, 0);
  let http_header_0_digest = polynomial_digest(
    &ByteOrPad::as_bytes(&compute_http_witness(
      &padded_plaintext,
      witness::HttpMaskType::Header(1),
    )),
    ciphertext_digest,
    0,
  );

  let mut http_body = compute_http_witness(&padded_plaintext, witness::HttpMaskType::Body);
  http_body.resize(CIRCUIT_SIZE, ByteOrPad::Pad);

  let mut main_digests = vec![
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_start_line_digest.to_bytes())
      .to_str_radix(10),
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &http_header_0_digest.to_bytes())
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

  let (z0_primary, _) = program_data.extend_public_inputs(Some(vec![init_nivc_input])).unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];
  proof.proof.verify(&program_data.public_params, &vk, &z0_primary, &z0_secondary).unwrap();
}
