//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON: JSON extract
use proofs::program::data::{NotExpanded, R1CSType, SetupData, WitnessGeneratorType};
use tracing::debug;

pub const MAX_ROM_LENGTH: usize = 3;
pub const PROVING_PARAMS_512: &str = "proofs/web_proof_circuits/serialized_setup_512.bytes";
pub const PROVING_PARAMS_1024: &str = "proofs/web_proof_circuits/serialized_setup_1024.bytes";

// -------------------------------------- 1024B circuits -------------------------------------- //
// Circuit 0
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/target_1024b/plaintext_authentication_1024b.r1cs"
);
// Circuit 1
const HTTP_VERIFICATION_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_verification_1024b.r1cs");
// Circuit 2
const JSON_EXTRACTION_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extraction_1024b.r1cs");

// -------------------------------------- 512B circuits -------------------------------------- //
// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/plaintext_authentication_512b.r1cs");
// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_verification_512b.r1cs");
// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extraction_512b.r1cs");

pub fn construct_setup_data_512() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_512B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_512B_R1CS.to_vec()),
    ],
    witness_generator_types: vec![WitnessGeneratorType::Browser; 3],
    max_rom_length:          MAX_ROM_LENGTH,
  }
}

pub fn construct_setup_data_1024() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_R1CS.to_vec()),
    ],
    witness_generator_types: vec![WitnessGeneratorType::Browser; 3],
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
  // TODO: Update to support response verification.
  let decryption_label = String::from("PLAINTEXT_AUTHENTICATION");
  let http_label = String::from("HTTP_VERIFICATION");

  let rom_data = HashMap::from([
    (decryption_label.clone(), CircuitData { opcode: 0 }),
    (http_label.clone(), CircuitData { opcode: 1 }),
  ]);
  let rom = vec![decryption_label.clone(), http_label.clone()];

  let params_1024 = (PROVING_PARAMS_1024, 1024, rom_data.clone(), rom.clone());
  let params_512 = (PROVING_PARAMS_512, 512, rom_data.clone(), rom.clone());

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

    let (pk, verifier_key) =
      CompressedSNARK::<E1, S1, S2>::setup(&program_data.public_params).unwrap();
    debug!(
      "initialized pk pk_primary.digest={:?}, hex(primary)={:?}, pk_secondary.digest={:?}",
      pk.pk_primary.vk_digest,
      hex::encode(pk.pk_primary.vk_digest.to_bytes()),
      pk.pk_secondary.vk_digest,
    );
    let verifier_digest = hex::encode(program_data.vk_digest_primary.to_bytes());
    let _ = verifiers.insert(verifier_digest, Verifier { program_data, verifier_key });
  }

  return verifiers;
}
