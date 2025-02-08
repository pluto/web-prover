//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains following circuits:
//! - Plaintext authentication: ChaCha encryption
//! - HTTP verification: HTTP parsing and locking
//! - JSON extraction: JSON value extraction
use crate::program::data::{R1CSType, UninitializedSetup, WitnessGeneratorType};

// -------------------------------------- 1024B circuits -------------------------------------- //
pub const MAX_ROM_LENGTH: usize = 100;
pub const CIRCUIT_SIZE_1024: usize = 1024;
pub const CIRCUIT_SIZE_512: usize = 512;
pub const PUBLIC_IO_VARS: usize = 11;
pub const MAX_STACK_HEIGHT: usize = 10;

pub const PROVING_PARAMS_512: &str = concat!(
  "proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_512b_rom_length_100.bin"
);
#[cfg(not(target_arch = "wasm32"))]
pub const PROVING_PARAMS_BYTES_512: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_512b_rom_length_100.bin"
));

// -------------------------------------- 512B circuits -------------------------------------- //
// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.r1cs"
));
const PLAINTEXT_AUTHENTICATION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.bin"
));
// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.r1cs"
));
const HTTP_VERIFICATION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.bin"
));
// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.r1cs"
));
const JSON_EXTRACTION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.bin"
));

pub fn construct_setup_data() -> UninitializedSetup {
  #[cfg(not(target_arch = "wasm32"))]
  {
    UninitializedSetup {
      r1cs_types:              vec![
        R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
        R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
        R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
      ],
      witness_generator_types: vec![
        WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_512B_GRAPH.to_vec()),
        WitnessGeneratorType::Raw(HTTP_VERIFICATION_512B_GRAPH.to_vec()),
        WitnessGeneratorType::Raw(JSON_EXTRACTION_512B_GRAPH.to_vec()),
        // WitnessGeneratorType::Wasm {
        //   path:      String::from(
        //     "proofs/web_proof_circuits/circom-artifacts-512b-v0.9.1/
        // plaintext_authentication_512b.\      wasm",
        //   ),
        //   wtns_path: String::from("witness.wtns"),
        // },
        // WitnessGeneratorType::Wasm {
        //   path:      String::from(
        //     "proofs/web_proof_circuits/circom-artifacts-512b-v0.9.1/http_verification_512b.wasm"
        // ,   ),
        //   wtns_path: String::from("witness.wtns"),
        // },
        // WitnessGeneratorType::Wasm {
        //   path:      String::from(
        //     "proofs/web_proof_circuits/circom-artifacts-512b-v0.9.1/json_extraction_512b.wasm",
        //   ),
        //   wtns_path: String::from("witness.wtns"),
        // },
      ],
      max_rom_length:          MAX_ROM_LENGTH,
    }
  }

  #[cfg(target_arch = "wasm32")]
  {
    UninitializedSetup {
      r1cs_types:              vec![
        R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
        R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
        R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
      ],
      witness_generator_types: vec![WitnessGeneratorType::Browser; 3],
      max_rom_length:          MAX_ROM_LENGTH,
    }
  }
}
