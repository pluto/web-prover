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
  program::data::{Online, ProgramData, R1CSType, SetupData, WitnessGeneratorType},
};

pub mod circom;
pub mod errors;
pub mod program;
pub mod proof;
pub mod setup;
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
