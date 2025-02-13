//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains following circuits:
//! - Plaintext authentication: ChaCha encryption
//! - HTTP verification: HTTP parsing and locking
//! - JSON extraction: JSON value extraction
use crate::{
  errors::ProofError,
  program::data::{R1CSType, UninitializedSetup, WitnessGeneratorType},
};

// -------------------------------------- circuits -------------------------------------- //
pub const MAX_ROM_LENGTH: usize = 100;
pub const CIRCUIT_SIZE_512: usize = 512;
pub const PUBLIC_IO_VARS: usize = 11;
pub const MAX_STACK_HEIGHT: usize = 12;

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
pub const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.r1cs"
));
pub const PLAINTEXT_AUTHENTICATION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.bin"
));
// Circuit 1
pub const HTTP_VERIFICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.r1cs"
));
pub const HTTP_VERIFICATION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.bin"
));
// Circuit 2pub
pub const JSON_EXTRACTION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.r1cs"
));
pub const JSON_EXTRACTION_512B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.bin"
));

#[allow(dead_code)]
fn wasm_witness_generator_type_512b() -> [WitnessGeneratorType; 3] {
  [
    WitnessGeneratorType::Wasm {
      path:      format!(
        "proofs/web_proof_circuits/circom-artifacts-512b-v{}/plaintext_authentication_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("pa.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "proofs/web_proof_circuits/circom-artifacts-512b-v{}/http_verification_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("hv.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "proofs/web_proof_circuits/circom-artifacts-512b-v{}/json_extraction_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("je.wtns"),
    },
  ]
}
pub fn construct_setup_data<const CIRCUIT_SIZE: usize>() -> Result<UninitializedSetup, ProofError> {
  let r1cs_types = match CIRCUIT_SIZE {
    CIRCUIT_SIZE_512 => vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
    ],
    _ => return Err(ProofError::InvalidCircuitSize),
  };

  #[cfg(not(target_arch = "wasm32"))]
  {
    let witness_generator_types = match CIRCUIT_SIZE {
      CIRCUIT_SIZE_512 => vec![
        WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_512B_GRAPH.to_vec()),
        WitnessGeneratorType::Raw(HTTP_VERIFICATION_512B_GRAPH.to_vec()),
        WitnessGeneratorType::Raw(JSON_EXTRACTION_512B_GRAPH.to_vec()),
      ],
      _ => return Err(ProofError::InvalidCircuitSize),
    };

    Ok(UninitializedSetup { r1cs_types, witness_generator_types, max_rom_length: MAX_ROM_LENGTH })
  }

  #[cfg(target_arch = "wasm32")]
  {
    Ok(UninitializedSetup {
      r1cs_types,
      witness_generator_types: vec![WitnessGeneratorType::Browser; 3],
      max_rom_length: MAX_ROM_LENGTH,
    })
  }
}
