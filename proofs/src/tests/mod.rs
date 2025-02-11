//! This test module is effectively testing a static (comptime) circuit dispatch supernova
//! program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use std::sync::Arc;

use client_side_prover::supernova::RecursiveSNARK;
use inputs::{
  complex_manifest, complex_request_inputs, complex_response_inputs, simple_request_inputs,
  simple_response_inputs, TEST_MANIFEST,
};
use web_proof_circuits_witness_generator::{
  http::{compute_http_witness, HttpMaskType},
  json::JsonKey,
  polynomial_digest,
};

use super::*;
use crate::program::{
  data::{CircuitData, NotExpanded, ProofParams, SetupParams, UninitializedSetup},
  initialize_setup_data,
  manifest::{
    InitialNIVCInputs, Manifest, NIVCRom, NivcCircuitInputs, Request, Response, ResponseBody,
  },
};
pub(crate) mod inputs;
mod witnesscalc;

const MAX_ROM_LENGTH: usize = 100;
const MAX_STACK_HEIGHT: usize = 10;
const CIRCUIT_SIZE: usize = 512;

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
fn wasm_witness_generator_type_256b() -> [WitnessGeneratorType; 3] {
  [
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-256b-v{}/plaintext_authentication_256b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("pa.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-256b-v{}/http_verification_256b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("hv.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-256b-v{}/json_extraction_256b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("je.wtns"),
    },
  ]
}

#[allow(dead_code)]
pub(crate) fn mock_manifest() -> Manifest {
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
async fn test_end_to_end_proofs_get() {
  let setup_data = UninitializedSetup {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_256B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_256B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_256B_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_256B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_256B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_EXTRACTION_256B_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);

  debug!("Creating `private_inputs`...");

  let request_inputs = simple_request_inputs();
  let response_inputs = simple_response_inputs();
  let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  let NIVCRom { circuit_data, rom } =
    manifest.build_rom::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);
  let NivcCircuitInputs { initial_nivc_input, fold_inputs: _, private_inputs } =
    manifest.build_inputs::<CIRCUIT_SIZE>(&request_inputs, &response_inputs).unwrap();

  let val = "world".as_bytes();
  let value_digest = &polynomial_digest(val, ciphertext_digest, 0);

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
async fn test_end_to_end_proofs_post() {
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
    witness_generator_types: // wasm_witness_generator_type_512b().to_vec(),
    vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_512B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_512B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_EXTRACTION_512B_GRAPH.to_vec()),
    ],
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
