//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains following circuits:
//! - Plaintext authentication: ChaCha encryption
//! - HTTP verification: HTTP parsing and locking
//! - JSON extraction: JSON value extraction
use proofs::program::data::{R1CSType, UninitializedSetup, WitnessGeneratorType};

// -------------------------------------- 1024B circuits -------------------------------------- //
pub const MAX_ROM_LENGTH: usize = 100;

#[allow(dead_code)]
pub const PROVING_PARAMS_1024: &str = concat!(
  "proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_1024b_rom_length_100.bin"
);

// TODO: Not loaded dynamically on iOS (yet)
#[cfg(not(target_arch = "wasm32"))]
pub const PROVING_PARAMS_BYTES_1024: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_1024b_rom_length_100.bin"
));

// Circuit 0
#[allow(dead_code)]
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_1024b.r1cs"
));
#[cfg(not(target_arch = "wasm32"))]
const PLAINTEXT_AUTHENTICATION_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_1024b.bin"
));

// Circuit 1
#[allow(dead_code)]
const HTTP_VERIFICATION_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_1024b.r1cs"
));
#[cfg(not(target_arch = "wasm32"))]
const HTTP_VERIFICATION_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_1024b.bin"
));

// Circuit 2
#[allow(dead_code)]
const JSON_EXTRACTION_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_1024b.r1cs"
));
#[cfg(not(target_arch = "wasm32"))]
const JSON_EXTRACTION_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_1024b.bin"
));

/// construct [`UninitializedSetup`] with all the required inputs for 1024B inputs
pub fn construct_setup_data() -> UninitializedSetup {
  #[cfg(not(target_arch = "wasm32"))]
  {
    UninitializedSetup {
      r1cs_types:              vec![
        R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
        R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
        R1CSType::Raw(JSON_EXTRACTION_R1CS.to_vec()),
      ],
      witness_generator_types: vec![
        WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_GRAPH.to_vec()),
        WitnessGeneratorType::Raw(HTTP_VERIFICATION_GRAPH.to_vec()),
        WitnessGeneratorType::Raw(JSON_EXTRACTION_GRAPH.to_vec()),
        // WitnessGeneratorType::Wasm {
        //   path:      String::from(
        //     "proofs/web_proof_circuits/circom-artifacts-1024b-v0.9.0/\
        //      plaintext_authentication_1024b.wasm",
        //   ),
        //   wtns_path: String::from("witness.wtns"),
        // },
        // WitnessGeneratorType::Wasm {
        //   path:      String::from(
        //     "proofs/web_proof_circuits/circom-artifacts-1024b-v0.9.0/http_verification_1024b.
        // wasm",   ),
        //   wtns_path: String::from("witness.wtns"),
        // },
        // WitnessGeneratorType::Wasm {
        //   path:      String::from(
        //     "proofs/web_proof_circuits/circom-artifacts-1024b-v0.9.0/json_extraction_1024b.wasm"
        // ,   ),
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
        R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
        R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
        R1CSType::Raw(JSON_EXTRACTION_R1CS.to_vec()),
      ],
      witness_generator_types: vec![WitnessGeneratorType::Browser; 3],
      max_rom_length:          MAX_ROM_LENGTH,
    }
  }
}
