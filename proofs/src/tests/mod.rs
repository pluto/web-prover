//! This test module is effectively testing a static (comptime) circuit dispatch supernova
//! program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use std::sync::Arc;

use client_side_prover::supernova::RecursiveSNARK;
use inputs::{
  complex_manifest, complex_request_inputs, complex_response_inputs, simple_request_inputs,
};
use serde_json::json;
use web_proof_circuits_witness_generator::{
  data_hasher, field_element_to_base10_string,
  http::{compute_http_witness, HttpMaskType, RawHttpMachine},
  json::{JsonKey, RawJsonMachine},
  polynomial_digest, ByteOrPad,
};

use super::*;
use crate::program::{
  data::{CircuitData, NotExpanded, ProofParams, SetupParams, UninitializedSetup},
  initialize_setup_data,
  manifest::{
    make_nonce, to_chacha_input, InitialNIVCInputs, Manifest, NIVCRom, NivcCircuitInputs, Request,
    Response, ResponseBody,
  },
};
pub(crate) mod inputs;
mod witnesscalc;

const MAX_ROM_LENGTH: usize = 100;
const MAX_STACK_HEIGHT: usize = 10;
const CIRCUIT_SIZE: usize = 1024;
const MAX_HTTP_HEADERS: usize = 25;

// const SERIALIZED_SETUP: &[u8] = include_bytes!(
//   "../../web_proof_circuits/circom-artifacts-1024b-v0.9.0/serialized_setup_1024b_rom_length_100.
// bin" );

// Circuit 0
const PLAINTEXT_AUTHENTICATION_256B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_256b.r1cs"
));
const PLAINTEXT_AUTHENTICATION_256B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_256b.bin"
));

// Circuit 1
const HTTP_VERIFICATION_256B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_256b.r1cs"
));
const HTTP_VERIFICATION_256B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_256b.bin"
));

// Circuit 2
const JSON_EXTRACTION_256B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_256b.r1cs"
));
const JSON_EXTRACTION_256B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_256b.bin"
));

const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.r1cs"
));
const PLAINTEXT_AUTHENTICATION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.bin"
));

// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.r1cs"
));
const HTTP_VERIFICATION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.bin"
));

// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.r1cs"
));
const JSON_EXTRACTION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.bin"
));

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
pub const HTTP_RESPONSE_PLAINTEXT: (&str, [u8; 320]) = ("plaintext", [
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

pub const CHACHA20_CIPHERTEXT: (&str, [u8; 320]) = ("cipherText", [
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
pub const CHACHA20_KEY: (&str, [u8; 32]) = ("key", [0; 32]);
pub const CHACHA20_NONCE: (&str, [u8; 12]) = ("nonce", [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]);

#[allow(dead_code)]
fn wasm_witness_generator_type_512b() -> [WitnessGeneratorType; 3] {
  [
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-512b-v{}/plaintext_authentication_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("pa.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-512b-v{}/http_verification_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("hv.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-512b-v{}/json_extraction_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("je.wtns"),
    },
  ]
}
#[allow(dead_code)]
fn wasm_witness_generator_type() -> [WitnessGeneratorType; 3] {
  [
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-1024b-v{}/plaintext_authentication_1024b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("pa.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-1024b-v{}/http_verification_1024b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("hv.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-1024b-v{}/json_extraction_1024b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("je.wtns"),
    },
  ]
}

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

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_simple() {
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

  let setup_data = UninitializedSetup {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_512B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_512B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_EXTRACTION_512B_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);
  debug!("Creating ROM");
  let rom_data = HashMap::from([
    (String::from("PLAINTEXT_AUTHENTICATION_0"), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION_0"), CircuitData { opcode: 1 }),
    (String::from("PLAINTEXT_AUTHENTICATION_1"), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION_1"), CircuitData { opcode: 1 }),
    (String::from("JSON_EXTRACTION_0"), CircuitData { opcode: 2 }),
  ]);

  debug!("Creating `private_inputs`...");

  let request_inputs = simple_request_inputs();

  let padded_request_plaintext = ByteOrPad::from_bytes_with_padding(
    &request_inputs.plaintext[0],
    1024 - request_inputs.plaintext[0].len(),
  );
  let padded_request_ciphertext = ByteOrPad::from_bytes_with_padding(
    &request_inputs.ciphertext[0],
    1024 - request_inputs.ciphertext[0].len(),
  );

  let padded_response_plaintext = ByteOrPad::from_bytes_with_padding(
    &HTTP_RESPONSE_PLAINTEXT.1,
    1024 - HTTP_RESPONSE_PLAINTEXT.1.len(),
  );
  let padded_response_ciphertext =
    ByteOrPad::from_bytes_with_padding(&CHACHA20_CIPHERTEXT.1, 1024 - CHACHA20_CIPHERTEXT.1.len());

  assert_eq!(padded_request_plaintext.len(), padded_request_ciphertext.len());
  assert!(padded_response_plaintext.len() == padded_response_ciphertext.len());
  assert_eq!(padded_response_ciphertext.len(), 1024);

  let manifest = mock_manifest();
  let InitialNIVCInputs { ciphertext_digest, initial_nivc_input, headers_digest } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(&[request_inputs.ciphertext[0].to_vec()], &[
      CHACHA20_CIPHERTEXT.1.to_vec(),
    ])
    .unwrap();

  let mut main_digests =
    headers_digest.iter().map(|h| field_element_to_base10_string(*h)).collect::<Vec<_>>();
  main_digests
    .extend(std::iter::repeat("0".to_string()).take(MAX_HTTP_HEADERS + 1 - headers_digest.len()));

  let mut private_inputs = vec![];

  debug!("Creating ROM and inputs...");

  debug!("Creating request plaintext authentication private inputs...");
  let mut rom = vec![String::from("PLAINTEXT_AUTHENTICATION_0")];
  let request_nonce = make_nonce(request_inputs.iv, request_inputs.seq);
  private_inputs.push(HashMap::from([
    (String::from(CHACHA20_KEY.0), json!(to_chacha_input(request_inputs.key.as_ref()))),
    (String::from(CHACHA20_NONCE.0), json!(to_chacha_input(&request_nonce))),
    (String::from("counter"), json!(to_chacha_input(&[1]))),
    (String::from(HTTP_RESPONSE_PLAINTEXT.0), json!(&padded_request_plaintext)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
  ]));
  let mut part_ciphertext_digest = data_hasher(&padded_request_ciphertext, F::<G1>::ZERO);
  let request_plaintext_digest =
    polynomial_digest(&request_inputs.plaintext[0], ciphertext_digest, 0);
  let plaintext_authentication_step_out =
    initial_nivc_input[0] - part_ciphertext_digest + request_plaintext_digest;
  debug!(
    "plaintext_authentication_step_out: {:?}",
    field_element_to_base10_string(plaintext_authentication_step_out)
  );

  debug!("Creating response http verification private inputs...");
  rom.push(String::from("HTTP_VERIFICATION_0"));
  private_inputs.push(HashMap::from([
    (String::from("data"), json!(&padded_request_plaintext)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
    (String::from("main_digests"), json!(main_digests)),
    (String::from("machine_state"), json!(RawHttpMachine::initial_state())),
  ]));
  let http_verification_step_out = plaintext_authentication_step_out - request_plaintext_digest;
  debug!(
    "http_verification_step_out: {:?}",
    field_element_to_base10_string(http_verification_step_out)
  );

  debug!("Creating response plaintext authentication private inputs...");
  rom.push(String::from("PLAINTEXT_AUTHENTICATION_1"));
  let response_nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
  private_inputs.push(HashMap::from([
    (String::from(CHACHA20_KEY.0), json!(to_chacha_input(&CHACHA20_KEY.1))),
    (String::from(CHACHA20_NONCE.0), json!(to_chacha_input(&response_nonce))),
    (String::from("counter"), json!(to_chacha_input(&[1]))),
    (String::from(HTTP_RESPONSE_PLAINTEXT.0), json!(&padded_response_plaintext)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
  ]));
  part_ciphertext_digest = data_hasher(&padded_response_ciphertext, part_ciphertext_digest);
  let response_plaintext_digest = polynomial_digest(
    &HTTP_RESPONSE_PLAINTEXT.1,
    ciphertext_digest,
    request_inputs.plaintext[0].len() as u64,
  );
  let plaintext_authentication_step_out =
    http_verification_step_out - part_ciphertext_digest + response_plaintext_digest;
  debug!(
    "plaintext_authentication_step_out: {:?}",
    field_element_to_base10_string(plaintext_authentication_step_out)
  );

  debug!("Creating response HTTP verification private inputs...");
  rom.push(String::from("HTTP_VERIFICATION_1"));
  private_inputs.push(HashMap::from([
    (String::from("data"), json!(&padded_response_plaintext)),
    (
      String::from("ciphertext_digest"),
      json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &ciphertext_digest.to_bytes())
        .to_str_radix(10)),
    ),
    (String::from("main_digests"), json!(main_digests)),
    (String::from("machine_state"), json!(RawHttpMachine::initial_state())),
  ]));
  let http_response_body = compute_http_witness(
    &HTTP_RESPONSE_PLAINTEXT.1,
    web_proof_circuits_witness_generator::http::HttpMaskType::Body,
  );
  let body_digest = polynomial_digest(&http_response_body, ciphertext_digest, 0);
  let http_verification_step_out =
    plaintext_authentication_step_out - response_plaintext_digest + body_digest;
  debug!(
    "http_verification_step_out: {:?}",
    field_element_to_base10_string(http_verification_step_out)
  );

  let key_sequence = [
    JsonKey::String(String::from("data")),
    JsonKey::String(String::from("items")),
    JsonKey::Num(0),
    JsonKey::String(String::from("profile")),
    JsonKey::String(String::from("name")),
  ];
  let raw_response_json_machine =
    RawJsonMachine::<MAX_STACK_HEIGHT>::from_chosen_sequence_and_input(
      ciphertext_digest,
      &key_sequence,
    )
    .unwrap();
  let sequence_digest = raw_response_json_machine.compress_tree_hash();

  let val = "Taylor Swift".as_bytes();
  let value_digest = &polynomial_digest(val, ciphertext_digest, 0);

  let json_state = RawJsonMachine::<MAX_STACK_HEIGHT>::initial_state();
  let json_state = json_state
    .flatten()
    .iter()
    .map(|f| field_element_to_base10_string(*f))
    .collect::<Vec<String>>();

  let padded_http_response_body =
    ByteOrPad::from_bytes_with_padding(&http_response_body, 1024 - http_response_body.len());
  rom.push(String::from("JSON_EXTRACTION_0"));
  private_inputs.push(HashMap::from([
    (String::from("data"), json!(&padded_http_response_body)),
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
    (String::from("state"), json!(json_state)),
  ]));
  let json_extraction_step_out = http_verification_step_out - body_digest + value_digest;
  debug!(
    "json_extraction_step_out: {:?}",
    field_element_to_base10_string(json_extraction_step_out)
  );

  let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let vk_digest_primary = pk.pk_primary.vk_digest;
  let vk_digest_secondary = pk.pk_secondary.vk_digest;
  let initialized_setup = initialize_setup_data(&setup_data).unwrap();
  let proof_params = ProofParams { rom: rom.clone() };
  let instance_params = InstanceParams::<NotExpanded> {
    nivc_input:     initial_nivc_input.to_vec(),
    private_inputs: (private_inputs, HashMap::new()),
  }
  .into_expanded(&proof_params)
  .unwrap();
  let setup_params = SetupParams::<Online> {
    public_params: Arc::new(public_params),
    vk_digest_primary,
    vk_digest_secondary,
    setup_data: Arc::new(initialized_setup),
    rom_data: rom_data.clone(),
  };

  let recursive_snark = program::run(&setup_params, &proof_params, &instance_params).await.unwrap();

  let proof = program::compress_proof_no_setup(
    &recursive_snark,
    &setup_params.public_params,
    vk_digest_primary,
    vk_digest_secondary,
  )
  .unwrap();

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), *value_digest);

  let (z0_primary, _) =
    setup_params.extend_public_inputs(&proof_params.rom, &instance_params.nivc_input).unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];
  proof.proof.verify(&setup_params.public_params, &vk, &z0_primary, &z0_secondary).unwrap();
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_complex() {
  let manifest = complex_manifest();
  let request_inputs = complex_request_inputs();
  let response_inputs = complex_response_inputs();

  const CIRCUIT_SIZE: usize = 512;

  let setup_data = UninitializedSetup {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
    ],
    witness_generator_types: wasm_witness_generator_type_512b().to_vec(),
    // vec![
    //   WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_GRAPH.to_vec()),
    //   WitnessGeneratorType::Raw(HTTP_VERIFICATION_GRAPH.to_vec()),
    //   WitnessGeneratorType::Raw(JSON_EXTRACTION_GRAPH.to_vec()),
    // ],
    max_rom_length:          MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);

  debug!("Creating ROM");

  let request_combined = request_inputs.plaintext.iter().fold(vec![], |mut acc, x| {
    acc.extend(x.clone());
    acc
  });

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  let NIVCRom { circuit_data, rom } =
    manifest.build_rom::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);
  let NivcCircuitInputs { mut initial_nivc_input, fold_inputs, private_inputs } =
    manifest.build_inputs::<CIRCUIT_SIZE>(&request_inputs, &response_inputs).unwrap();

  let request_body = compute_http_witness(&request_combined, HttpMaskType::Body);
  let request_body_digest = polynomial_digest(&request_body, ciphertext_digest, 0);
  initial_nivc_input[0] -= request_body_digest; // TODO: this is actually incorrect because we don't have json verification for request

  debug!("rom: {:?}", rom);
  debug!("inputs: {:?}", private_inputs.len());

  let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let vk_digest_primary = pk.pk_primary.vk_digest;
  let vk_digest_secondary = pk.pk_secondary.vk_digest;
  let initialized_setup = initialize_setup_data(&setup_data).unwrap();
  let setup_params = SetupParams::<Online> {
    public_params: Arc::new(public_params),
    vk_digest_primary,
    vk_digest_secondary,
    setup_data: Arc::new(initialized_setup),
    rom_data: circuit_data.clone(),
  };
  let proof_params = ProofParams { rom: rom.clone() };
  let instance_params = InstanceParams::<NotExpanded> {
    nivc_input:     initial_nivc_input.to_vec(),
    private_inputs: (private_inputs, HashMap::new()),
  }
  .into_expanded(&proof_params)
  .unwrap();

  let recursive_snark = program::run(&setup_params, &proof_params, &instance_params).await.unwrap();

  let proof = program::compress_proof_no_setup(
    &recursive_snark,
    &setup_params.public_params,
    setup_params.vk_digest_primary,
    setup_params.vk_digest_secondary,
  )
  .unwrap();

  let target_value = "ord_67890".as_bytes();
  let value_digest = polynomial_digest(target_value, ciphertext_digest, 0);

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), value_digest);

  let (z0_primary, _) =
    setup_params.extend_public_inputs(&proof_params.rom, &initial_nivc_input.to_vec()).unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];

  proof.proof.verify(&setup_params.public_params, &vk, &z0_primary, &z0_secondary).unwrap();
}
