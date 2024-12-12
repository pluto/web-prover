//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON_MASK_OBJECT: Mask object at depth 0
//! - JSON_MASK_ARRAY: Mask array at depth 0
//! - EXTRACT_VALUE: extract final value
use proofs::program::data::{R1CSType, SetupData, WitnessGeneratorType};

// -------------------------------------- 1024B circuits -------------------------------------- //
pub const MAX_ROM_LENGTH: usize = 80;

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

/// construct [`SetupData`] with all the required inputs for 1024B inputs
pub fn construct_setup_data() -> SetupData {
  SetupData {
    r1cs_types: vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    #[cfg(not(target_arch = "wasm32"))]
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    #[cfg(target_arch = "wasm32")]
    witness_generator_types: vec![WitnessGeneratorType::Browser; 5],
    max_rom_length: MAX_ROM_LENGTH,
  }
}
