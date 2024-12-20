use std::{collections::HashMap, path::PathBuf, str::FromStr};

use circom::CircomCircuit;
use client_side_prover::{
  fast_serde::{self, FastSerde},
  provider::GrumpkinEngine,
  spartan::batched::BatchedRelaxedR1CSSNARK,
  supernova::{snark::CompressedSNARK, PublicParams, TrivialCircuit},
  traits::{Dual, Engine, Group},
};
use ff::Field;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info};

use crate::{
  errors::ProofError,
  program::data::{Expanded, Online, ProgramData, R1CSType, SetupData, WitnessGeneratorType},
};

pub mod circom;
pub mod errors;
pub mod program;
pub mod proof;
#[cfg(test)] pub(crate) mod tests;
pub mod witness;

pub type E1 = client_side_prover::provider::Bn256EngineKZG;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
pub type EE1 =
  client_side_prover::provider::hyperkzg::EvaluationEngine<halo2curves::bn256::Bn256, E1>;
pub type EE2 = client_side_prover::provider::ipa_pc::EvaluationEngine<E2>;
pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

pub type F<G> = <G as Group>::Scalar;

/// Represents the params needed to create `PublicParams` alongside the circuits' R1CSs.
/// Specifically typed to the `proofs` crate choices of curves and engines.
pub type AuxParams = client_side_prover::supernova::AuxParams<E1>;
/// The `ProverKey` needed to create a `CompressedSNARK` using the `proofs` crate choices of curves
/// and engines.
pub type ProverKey = client_side_prover::supernova::snark::ProverKey<E1, S1, S2>;
/// The `VerifierKey` needed to create a `CompressedSNARK` using the `proofs` crate choices of
/// curves and engines.
pub type VerifierKey = client_side_prover::supernova::snark::VerifierKey<E1, S1, S2>;

use std::io::Cursor;

use client_side_prover::fast_serde::{SerdeByteError, SerdeByteTypes};

#[derive(Debug)]
pub struct ProvingParams {
  pub aux_params:          AuxParams,
  pub vk_digest_primary:   <E1 as Engine>::Scalar,
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
}

impl FastSerde for ProvingParams {
  /// Initialize ProvingParams from an efficiently serializable data format.
  fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SerdeByteError> {
    let mut cursor = Cursor::new(bytes);
    Self::validate_header(&mut cursor, SerdeByteTypes::ProverParams, 3)?;

    // TODO: Clean up these messy unwraps?
    let aux_params =
      Self::read_section_bytes(&mut cursor, 1).map(|bytes| AuxParams::from_bytes(&bytes))?.unwrap();
    let vk_digest_primary = Self::read_section_bytes(&mut cursor, 2)
      .map(|bytes| <E1 as Engine>::Scalar::from_bytes(&bytes.try_into().unwrap()))?
      .unwrap();
    let vk_digest_secondary = Self::read_section_bytes(&mut cursor, 3)
      .map(|bytes| <Dual<E1> as Engine>::Scalar::from_bytes(&bytes.try_into().unwrap()))?
      .unwrap();

    Ok(ProvingParams { aux_params, vk_digest_primary, vk_digest_secondary })
  }

  /// Convert ProvingParams to an efficient serialization.
  fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&fast_serde::MAGIC_NUMBER);
    out.push(SerdeByteTypes::ProverParams as u8);
    out.push(3); // num_sections

    Self::write_section_bytes(&mut out, 1, &self.aux_params.to_bytes());
    Self::write_section_bytes(&mut out, 2, &self.vk_digest_primary.to_bytes().to_vec());
    Self::write_section_bytes(&mut out, 3, &self.vk_digest_secondary.to_bytes().to_vec());

    return out;
  }
}

impl ProvingParams {
  /// Method used externally to initialize all the backend data needed to create a verifiable proof
  /// with [`client_side_prover`] and `proofs` crate. Intended to be used to create these values
  /// offline and then be loaded at or before proof creation or verification.
  ///
  /// # Arguments
  /// - `setup_data`: the data that defines what types of supernova programs can be run, i.e.,
  ///   specified by a list of circuit R1CS and max ROM length.
  pub fn new(aux_params: AuxParams, prover_key: ProverKey) -> Result<ProvingParams, ProofError> {
    // TODO: How do we abstract this correctly?
    //
    // let public_params = program::setup(&setup_data);
    // let (prover_key, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;

    // debug!("initialized pk_primary.digest={:?}, pk_secondary.digest={:?}",
    // hex::encode(pk.pk_primary.vk_digest.to_bytes()),
    // hex::encode(pk.pk_secondary.vk_digest.to_bytes()));
    Ok(ProvingParams {
      aux_params,
      vk_digest_primary: prover_key.pk_primary.vk_digest,
      vk_digest_secondary: prover_key.pk_secondary.vk_digest,
    })
  }
}
