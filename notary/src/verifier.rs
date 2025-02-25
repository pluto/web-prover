use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  circuits::{construct_setup_data_from_fs, PROVING_PARAMS_512},
  program::{
    data::{CircuitData, Offline, Online, SetupParams},
    manifest::Manifest,
  },
  E1, F, G1, G2, S1, S2,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::errors::ProxyError;

pub struct Verifier {
  pub setup_params: SetupParams<Online>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyQuery<T: AsRef<[u8]>> {
  pub value:    T,
  pub manifest: Manifest,
}

pub fn flatten_rom(rom: Vec<String>) -> Vec<String> {
  rom
    .iter()
    .map(|s| {
      s.rfind('_')
        .and_then(
          |i| if s[i + 1..].chars().all(|c| c.is_ascii_digit()) { Some(&s[..i]) } else { None },
        )
        .unwrap_or(s)
        .to_string()
    })
    .collect()
}

pub fn initialize_verifier() -> Result<Verifier, ProxyError> {
  let bytes = std::fs::read(PROVING_PARAMS_512)?;
  let setup_data = construct_setup_data_from_fs::<{ proofs::circuits::CIRCUIT_SIZE_512 }>()?;
  let rom_data = HashMap::from([
    (String::from("PLAINTEXT_AUTHENTICATION"), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION"), CircuitData { opcode: 1 }),
    (String::from("JSON_EXTRACTION"), CircuitData { opcode: 2 }),
  ]);

  let setup_params = SetupParams::<Offline> {
    public_params: bytes,
    // TODO: These are incorrect, but we don't know them until the internal parser completes.
    // during the transition to `into_online` they're populated.
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom_data,
  }
  .into_online()?;

  let (pk, verifier_key) = CompressedSNARK::<E1, S1, S2>::setup(&setup_params.public_params)?;
  debug!(
    "initialized pk pk_primary.digest={:?}, hex(primary)={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest,
    hex::encode(pk.pk_primary.vk_digest.to_bytes()),
    pk.pk_secondary.vk_digest,
  );

  Ok(Verifier { setup_params, verifier_key })
}
