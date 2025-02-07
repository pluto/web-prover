//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON: JSON extract
use std::collections::HashMap;

use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  program::data::{
    CircuitData, InstanceParams, NotExpanded, Offline, Online, ProofParams, R1CSType, SetupParams,
    UninitializedSetup, WitnessGeneratorType,
  },
  E1, F, G1, G2, S1, S2,
};
use tracing::debug;

pub const MAX_ROM_LENGTH: usize = 100;
pub const PUBLIC_IO_VARS: usize = 11;
pub const CIRCUIT_SIZE_SMALL: usize = 512;
pub const CIRCUIT_SIZE_MAX: usize = 1024;
pub const MAX_STACK_HEIGHT: usize = 10;

pub const PROVING_PARAMS_1024: &str = concat!(
  "proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_1024b_rom_length_100.bin"
);

// -------------------------------------- 1024B circuits -------------------------------------- //
// Circuit 0
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_1024b.r1cs"
));
// Circuit 1
const HTTP_VERIFICATION_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_1024b.r1cs"
));
// Circuit 2
const JSON_EXTRACTION_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_1024b.r1cs"
));

// -------------------------------------- 512B circuits -------------------------------------- //
pub const PROVING_PARAMS_512: &str = concat!(
  "proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_512b_rom_length_100.bin"
);
// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_512b.r1cs"
));
// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_512b.r1cs"
));
// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] = include_bytes!(concat!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_512b.r1cs"
));

pub fn construct_setup_data_512() -> UninitializedSetup {
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

pub fn construct_setup_data_1024() -> UninitializedSetup {
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

pub fn construct_setup_data(plaintext_length: usize) -> UninitializedSetup {
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

pub struct Verifier {
  pub setup_params: SetupParams<Online>,
  pub proof_params: ProofParams,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

pub fn initialize_verifier(rom_data: HashMap<String, CircuitData>, rom: Vec<String>) -> Verifier {
  // let params_1024 = (PROVING_PARAMS_1024, 1024, rom_data, rom.clone());

  let bytes = std::fs::read(PROVING_PARAMS_512).unwrap();
  let setup_data = construct_setup_data(512);
  let setup_params = SetupParams::<Offline> {
    public_params: bytes,
    // TODO: These are incorrect, but we don't know them until the internal parser completes.
    // during the transition to `into_online` they're populated.
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom_data,
  }
  .into_online()
  .unwrap();
  let proof_params = ProofParams { rom };

  let (pk, verifier_key) =
    CompressedSNARK::<E1, S1, S2>::setup(&setup_params.public_params).unwrap();
  debug!(
    "initialized pk pk_primary.digest={:?}, hex(primary)={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest,
    hex::encode(pk.pk_primary.vk_digest.to_bytes()),
    pk.pk_secondary.vk_digest,
  );

  Verifier { setup_params, proof_params, verifier_key }
}
