//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON_MASK_OBJECT: Mask object at depth 0
//! - JSON_MASK_ARRAY: Mask array at depth 0
//! - EXTRACT_VALUE: extract final value
use proofs::program::data::{NotExpanded, R1CSType, SetupData, WitnessGeneratorType};

// -------------------------------------- 1024B circuits -------------------------------------- //
pub const MAX_ROM_LENGTH: usize = 80;
pub const MAX_ROM_LENGTH_512: usize = 10;
pub const PROVING_PARAMS_512: &str = "proofs/web_proof_circuits/serialized_setup_512.bytes";
pub const PROVING_PARAMS_1024: &str = "proofs/web_proof_circuits/serialized_setup_1024.bytes";

// Circuit 0
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/target_1024b/plaintext_authentication_1024b.r1cs"
);
const PLAINTEXT_AUTHENTICATION_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/plaintext_authentication_1024b.bin");

// Circuit 1
const HTTP_VERIFICATION_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_verification_1024b.r1cs");
const HTTP_VERIFICATION_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_verification_1024b.bin");

// Circuit 2
const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_object_1024b.r1cs");
const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_object_1024b.bin");

// Circuit 3
const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_array_index_1024b.r1cs");
const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_array_index_1024b.bin");

// circuit 4
const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extract_value_1024b.r1cs");
const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extract_value_1024b.bin");

// -------------------------------------- 512B circuits -------------------------------------- //

// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/plaintext_authentication_512b.r1cs");

// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_verification_512b.r1cs");

// Circuit 2
const JSON_MASK_OBJECT_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.r1cs");

// Circuit 3
const JSON_MASK_ARRAY_INDEX_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.r1cs");

// circuit 4
const EXTRACT_VALUE_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.r1cs");

pub fn construct_setup_data_512() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_512B_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_512B_R1CS.to_vec()),
    ],
    witness_generator_types: vec![WitnessGeneratorType::Browser; 5],
    max_rom_length:          MAX_ROM_LENGTH_512,
  }
}

pub fn construct_setup_data_1024() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  }
}

pub fn construct_setup_data(plaintext_length: usize) -> SetupData {
  let circuit_size = if plaintext_length <= 512 {
    512
  } else if plaintext_length <= 1024 {
    1024
  } else {
    panic!("plaintext is too large");
  };

  match circuit_size {
    512 => construct_setup_data_512(),
    1024 => construct_setup_data_1024(),
    _ => panic!("not supported plaintext length > 1KB"),
  }
}

use std::collections::HashMap;

use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  program::data::{CircuitData, Offline, Online, ProgramData},
  E1, F, G1, G2, S1, S2,
};

pub struct Verifier {
  pub program_data: ProgramData<Online, NotExpanded>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

pub fn get_initialized_verifiers() -> HashMap<String, Verifier> {
  // TODO: Update to support all 3 circuits in 1024.
  let decryption_label = String::from("PLAINTEXT_AUTHENTICATION");
  let http_label = String::from("HTTP_VERIFICATION");

  let rom_data_512 = HashMap::from([
    (decryption_label.clone(), CircuitData { opcode: 0 }),
    (http_label.clone(), CircuitData { opcode: 1 }),
  ]);
  let rom_512 = vec![decryption_label.clone(), http_label.clone()];

  let rom_data_1024 = HashMap::from([
    (decryption_label.clone(), CircuitData { opcode: 0 }),
    (http_label.clone(), CircuitData { opcode: 1 }),
  ]);
  let rom_1024 = vec![decryption_label.clone(), http_label.clone()];

  let params_1024 = (PROVING_PARAMS_1024, 1024, rom_data_1024, rom_1024);
  let params_512 = (PROVING_PARAMS_512, 512, rom_data_512, rom_512);

  let mut verifiers = HashMap::new();
  for (path, circuit_size, rom_data, rom) in vec![params_1024, params_512] {
    let bytes = std::fs::read(path).unwrap();
    let setup_data = construct_setup_data(circuit_size);
    let program_data = ProgramData::<Offline, NotExpanded> {
      public_params: bytes,
      // TODO: These are incorrect, but we don't know them until the internal parser completes.
      // during the transition to `into_online` they're populated.
      vk_digest_primary: F::<G1>::from(0),
      vk_digest_secondary: F::<G2>::from(0),
      setup_data,
      rom,
      rom_data,
      initial_nivc_input: vec![F::<G1>::from(0)],
      inputs: (vec![HashMap::new()], HashMap::new()),
      witnesses: vec![],
    }
    .into_online()
    .unwrap();

    let (_pk, verifier_key) =
      CompressedSNARK::<E1, S1, S2>::setup(&program_data.public_params).unwrap();
    let verifier_digest = hex::encode(program_data.vk_digest_primary.to_bytes());
    let _ = verifiers.insert(verifier_digest, Verifier { program_data, verifier_key });
  }

  return verifiers;
}
