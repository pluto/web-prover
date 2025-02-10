//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON: JSON extract
use std::collections::HashMap;

use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  circuits::{construct_setup_data, PROVING_PARAMS_512, PUBLIC_IO_VARS},
  program::data::{
    CircuitData, InstanceParams, NotExpanded, Offline, Online, ProofParams, R1CSType, SetupParams,
    UninitializedSetup, WitnessGeneratorType,
  },
  E1, F, G1, G2, S1, S2,
};
use tracing::debug;

use crate::errors::ProxyError;

pub struct Verifier {
  pub setup_params: SetupParams<Online>,
  pub proof_params: ProofParams,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

pub fn initialize_verifier(rom_data: HashMap<String, CircuitData>, rom: Vec<String>) -> Verifier {
  // let params_1024 = (PROVING_PARAMS_1024, 1024, rom_data, rom.clone());

  let bytes = std::fs::read(PROVING_PARAMS_512).unwrap();
  let setup_data = construct_setup_data();
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
