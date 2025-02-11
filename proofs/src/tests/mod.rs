//! This test module is effectively testing a static (comptime) circuit dispatch supernova
//! program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use std::sync::Arc;

use client_side_prover::supernova::RecursiveSNARK;
use inputs::{
  complex_manifest, complex_request_inputs, complex_response_inputs, simple_request_inputs,
  simple_response_inputs, TEST_MANIFEST,
};
use web_proof_circuits_witness_generator::polynomial_digest;

use super::*;
use crate::program::{
  data::{CircuitData, NotExpanded, ProofParams, SetupParams, UninitializedSetup},
  initialize_setup_data,
  manifest::{InitialNIVCInputs, Manifest, NIVCRom, NivcCircuitInputs},
};
pub(crate) mod inputs;
mod witnesscalc;

const MAX_ROM_LENGTH: usize = 100;
const MAX_STACK_HEIGHT: usize = 10;

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

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_get() {
  const CIRCUIT_SIZE: usize = 256;
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

  let NIVCRom { circuit_data: rom_data, rom } =
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
    rom_data,
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
