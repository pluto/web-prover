//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON: JSON extract
use std::collections::HashMap;

use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  program::data::{
    CircuitData, NotExpanded, Offline, Online, ProgramData, R1CSType, UninitializedSetup,
    WitnessGeneratorType,
  },
  E1, F, G1, G2, S1, S2,
};
use tracing::debug;

pub const MAX_ROM_LENGTH: usize = 20;
pub const PUBLIC_IO_VARS: usize = 11;

pub const PROVING_PARAMS_1024: &str = concat!(
  "proofs/web_proof_circuits/circom-artifacts-1024b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_1024b_rom_length_20.bin"
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
    witness_generator_types: vec![
      // WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(HTTP_VERIFICATION_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_EXTRACTION_GRAPH.to_vec()),
      WitnessGeneratorType::Wasm {
        path:      String::from(
          "proofs/web_proof_circuits/circom-artifacts-1024b-v0.9.0/plaintext_authentication_1024b.\
           wasm",
        ),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from(
          "proofs/web_proof_circuits/circom-artifacts-1024b-v0.9.0/http_verification_1024b.wasm",
        ),
        wtns_path: String::from("witness.wtns"),
      },
      WitnessGeneratorType::Wasm {
        path:      String::from(
          "proofs/web_proof_circuits/circom-artifacts-1024b-v0.9.0/json_extraction_1024b.wasm",
        ),
        wtns_path: String::from("witness.wtns"),
      },
    ],
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
  pub program_data: ProgramData<Online, NotExpanded>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

// TODO: add another initialization endpoint when the rom is not static
pub fn get_initialized_verifiers() -> HashMap<String, Verifier> {
  let rom_data = HashMap::from([
    (String::from("PLAINTEXT_AUTHENTICATION_0"), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION_0"), CircuitData { opcode: 1 }),
    ("PLAINTEXT_AUTHENTICATION_1".to_string(), CircuitData { opcode: 0 }),
    ("PLAINTEXT_AUTHENTICATION_2".to_string(), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION_1"), CircuitData { opcode: 1 }),
    (String::from("JSON_EXTRACTION_0"), CircuitData { opcode: 2 }),
  ]);
  let rom = vec![
    "PLAINTEXT_AUTHENTICATION_0".to_string(),
    "HTTP_VERIFICATION_0".to_string(),
    "PLAINTEXT_AUTHENTICATION_1".to_string(),
    "PLAINTEXT_AUTHENTICATION_2".to_string(),
    "HTTP_VERIFICATION_1".to_string(),
    "JSON_EXTRACTION_0".to_string(),
  ];

  let params_1024 = (PROVING_PARAMS_1024, 1024, rom_data, rom.clone());

  let mut verifiers = HashMap::new();
  for (path, circuit_size, rom_data, rom) in [params_1024] {
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
      initial_nivc_input: vec![F::<G1>::from(0); PUBLIC_IO_VARS],
      inputs: (Vec::new(), HashMap::new()),
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

  verifiers
}

pub fn initialize_verifier(rom_data: HashMap<String, CircuitData>, rom: Vec<String>) -> Verifier {
  // let params_1024 = (PROVING_PARAMS_1024, 1024, rom_data, rom.clone());

  let bytes = std::fs::read(PROVING_PARAMS_1024).unwrap();
  let setup_data = construct_setup_data(1024);
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: bytes,
    // TODO: These are incorrect, but we don't know them until the internal parser completes.
    // during the transition to `into_online` they're populated.
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom,
    rom_data,
    initial_nivc_input: vec![F::<G1>::from(0); PUBLIC_IO_VARS],
    inputs: (Vec::new(), HashMap::new()),
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

  Verifier { program_data, verifier_key }
}
