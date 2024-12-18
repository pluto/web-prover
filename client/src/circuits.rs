//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON_MASK_OBJECT: Mask object at depth 0
//! - JSON_MASK_ARRAY: Mask array at depth 0
//! - EXTRACT_VALUE: extract final value
use proofs::program::data::{R1CSType, SetupData, WitnessGeneratorType};

// -------------------------------------- 1024B circuits -------------------------------------- //
pub const MAX_ROM_LENGTH: usize = 3;

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
const JSON_EXTRACTION_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extraction_1024b.r1cs");
const JSON_EXTRACTION_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extraction_1024b.bin");

// -------------------------------------- 512B circuits -------------------------------------- //
const MAX_ROM_LENGTH_512: usize = 3;

// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/plaintext_authentication_512b.r1cs");

// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_verification_512b.r1cs");

// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extraction_512b.r1cs");
const JSON_EXTRACTION_512B_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extraction_512b.bin");

/// construct [`SetupData`] with all the required inputs for 1024B inputs
pub fn construct_setup_data() -> SetupData {
  #[cfg(not(target_arch = "wasm32"))]
  {
    SetupData {
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
    }
  }

  #[cfg(target_arch = "wasm32")]
  {
    SetupData {
      r1cs_types:              vec![
        R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
        R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
        R1CSType::Raw(JSON_EXTRACTION_R1CS.to_vec()),
      ],
      witness_generator_types: vec![WitnessGeneratorType::Browser; 3],
      max_rom_length:          MAX_ROM_LENGTH_512,
    }
  }
}
