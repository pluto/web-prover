use std::{collections::HashMap, path::PathBuf, str::FromStr};

use circom::CircomCircuit;
use client_side_prover::{
  provider::GrumpkinEngine,
  spartan::batched_ppsnark::BatchedRelaxedR1CSSNARK,
  supernova::{snark::CompressedSNARK, PublicParams, TrivialCircuit},
  traits::{Engine, Group},
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
#[cfg(test)] mod tests;
pub mod witness;

// pub type E1 = client_side_prover::provider::Bn256EngineKZG;
pub type E1 = client_side_prover::provider::Bn256EngineIPA;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
// pub type EE1 =
//   client_side_prover::provider::hyperkzg::EvaluationEngine<halo2curves::bn256::Bn256, E1>;
pub type EE1 = client_side_prover::provider::ipa_pc::EvaluationEngine<E1>;
pub type EE2 = client_side_prover::provider::ipa_pc::EvaluationEngine<E2>;
pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

pub type F<G> = <G as Group>::Scalar;

/// Computes a web proof from the given program data.
///
/// This function runs the program using the provided `program_data`, generates a recursive SNARK,
/// compresses the proof, and serializes it into a compressed format.
///
/// # Arguments
///
/// * `program_data` - A reference to the `ProgramData` containing the setup and public parameters.
///
/// # Returns
///
/// A `Result` containing a vector of bytes representing the serialized and compressed proof,
/// or a `ProofError` if an error occurs during the computation.
///
/// # Errors
///
/// This function will return a `ProofError` if:
/// - The program fails to run with the provided `program_data`.
/// - The proof compression fails.
pub fn compute_web_proof(
  program_data: &ProgramData<Online, Expanded>,
) -> Result<Vec<u8>, ProofError> {
  let recursive_snark = program::run(program_data)?;
  // TODO: Unecessary 2x generation of pk,vk, but it is cheap. Refactor later if need be!
  let proof = program::compress_proof(&recursive_snark, &program_data.public_params)?;
  let serialized_proof = proof.serialize_and_compress();
  Ok(serialized_proof.0)
}

/// Represents the params needed to create `PublicParams` alongside the circuits' R1CSs.
/// Specifically typed to the `proofs` crate choices of curves and engines.
pub type AuxParams = client_side_prover::supernova::AuxParams<E1>;
/// The `ProverKey` needed to create a `CompressedSNARK` using the `proofs` crate choices of curves
/// and engines.
pub type ProverKey = client_side_prover::supernova::snark::ProverKey<E1, S1, S2>;
/// The `VerifierKey` needed to create a `CompressedSNARK` using the `proofs` crate choices of
/// curves and engines.
pub type VerifierKey = client_side_prover::supernova::snark::VerifierKey<E1, S1, S2>;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackendData {
  pub aux_params:   AuxParams,
  pub prover_key:   ProverKey,
  pub verifier_key: VerifierKey,
}

/// Method used externally to setup all the backend data needed to create a verifiable proof with
/// [`client_side_prover`] and `proofs` crate. Intended to be used to create these values offline
/// and then be loaded at or before proof creation or verification.
///
/// # Arguments
/// - `setup_data`: the data that defines what types of supernova programs can be run, i.e.,
///   specified by a list of circuit R1CS and max ROM length.
pub fn setup_backend(setup_data: &SetupData) -> Result<BackendData, ProofError> {
  let public_params = program::setup(setup_data);
  let (prover_key, verifier_key) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;
  Ok(BackendData { aux_params: public_params.aux_params(), prover_key, verifier_key })
}
