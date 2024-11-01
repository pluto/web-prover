#![feature(internal_output_capture)]
use std::{collections::HashMap, path::PathBuf, str::FromStr};

use circom::CircomCircuit;
use client_side_prover::{
  provider::{hyperkzg::EvaluationEngine, Bn256EngineIPA, Bn256EngineKZG, GrumpkinEngine},
  spartan::batched::BatchedRelaxedR1CSSNARK,
  supernova::{snark::CompressedSNARK, PublicParams, TrivialCircuit},
  traits::{Engine, Group},
};
use ff::Field;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "timing")] use tracing::trace;
use tracing::{debug, error, info};

use crate::program::data::{
  Expanded, Online, ProgramData, R1CSType, SetupData, WitnessGeneratorType,
};

pub mod circom;
pub mod program;
pub mod proof;
#[cfg(test)] mod tests;

// pub type E1 = Bn256EngineKZG;
pub type E1 = Bn256EngineIPA;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
// pub type EE1 = EvaluationEngine<halo2curves::bn256::Bn256, E1>;
pub type EE1 = client_side_prover::provider::ipa_pc::EvaluationEngine<E1>;
pub type EE2 = client_side_prover::provider::ipa_pc::EvaluationEngine<E2>;
pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

pub type F<G> = <G as Group>::Scalar;

pub fn compute_web_proof(program_data: &ProgramData<Online, Expanded>) -> Vec<u8> {
  let recursive_snark = program::run(program_data);
  // TODO: Unecessary 2x generation of pk,vk, but it is cheap. Refactor later if need be!
  let proof = program::compress_proof(&recursive_snark, &program_data.public_params);
  let serialized_proof = proof.serialize_and_compress();
  serialized_proof.0
}
