//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON: JSON extract
use std::{
  collections::HashMap,
  hash::{DefaultHasher, Hash, Hasher},
};

use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  program::data::{
    CircuitData, NotExpanded, Offline, Online, ProgramData, R1CSType, SetupData,
    WitnessGeneratorType,
  },
  E1, F, G1, G2, S1, S2,
};
use tracing::debug;

pub const MAX_ROM_LENGTH: usize = 5;
pub const PROVING_PARAMS_512: &str =
  "proofs/web_proof_circuits/circom-artifacts-512b-v0.7.3/serialized_setup_512b_rom_length_5.bin";
pub const PROVING_PARAMS_1024: &str =
  "proofs/web_proof_circuits/circom-artifacts-1024b-v0.7.3/serialized_setup_1024b_rom_length_5.bin";

// -------------------------------------- 1024B circuits -------------------------------------- //
// Circuit 0
const PLAINTEXT_AUTHENTICATION_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v0.7.3/plaintext_authentication_1024b.\
   r1cs"
);
// Circuit 1
const HTTP_VERIFICATION_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v0.7.3/http_verification_1024b.r1cs"
);
// Circuit 2
const JSON_EXTRACTION_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/circom-artifacts-1024b-v0.7.3/json_extraction_1024b.r1cs"
);

// -------------------------------------- 512B circuits -------------------------------------- //
// Circuit 0
const PLAINTEXT_AUTHENTICATION_512B_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v0.7.3/plaintext_authentication_512b.r1cs"
);
// Circuit 1
const HTTP_VERIFICATION_512B_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v0.7.3/http_verification_512b.r1cs"
);
// Circuit 2
const JSON_EXTRACTION_512B_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/circom-artifacts-512b-v0.7.3/json_extraction_512b.r1cs"
);

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

pub struct Verifier {
  pub program_data: ProgramData<Online, NotExpanded>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

// TODO: add another initialization endpoint when the rom is not static
pub fn get_initialized_verifiers() -> HashMap<String, Verifier> {
  let decryption_label = String::from("PLAINTEXT_AUTHENTICATION");
  let http_label = String::from("HTTP_VERIFICATION");
  let json_label = String::from("JSON_EXTRACTION");

  let request_rom_data = HashMap::from([
    (decryption_label.clone(), CircuitData { opcode: 0 }),
    (http_label.clone(), CircuitData { opcode: 1 }),
  ]);
  let response_rom_data = HashMap::from([
    ("PLAINTEXT_AUTHENTICATION_0".to_string(), CircuitData { opcode: 0 }),
    ("PLAINTEXT_AUTHENTICATION_1".to_string(), CircuitData { opcode: 0 }),
    (http_label.clone(), CircuitData { opcode: 1 }),
    (json_label.clone(), CircuitData { opcode: 2 }),
  ]);
  let request_rom = vec![decryption_label.clone(), http_label.clone()];
  let response_rom = vec![
    "PLAINTEXT_AUTHENTICATION_0".to_string(),
    "PLAINTEXT_AUTHENTICATION_1".to_string(),
    http_label.clone(),
    json_label.clone(),
  ];

  let request_params_1024 =
    ("request", PROVING_PARAMS_1024, 1024, request_rom_data, request_rom.clone());
  let response_params_1024 =
    ("response", PROVING_PARAMS_1024, 1024, response_rom_data, response_rom.clone());

  let mut verifiers = HashMap::new();
  for (label, path, circuit_size, rom_data, rom) in [request_params_1024, response_params_1024] {
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
      inputs: (Vec::new(), HashMap::new()),
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
    let verifier_digest =
      format!("{}_{}", label, hex::encode(program_data.vk_digest_primary.to_bytes()));
    let _ = verifiers.insert(verifier_digest, Verifier { program_data, verifier_key });
  }

  verifiers
}
