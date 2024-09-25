#![feature(internal_output_capture)]

pub mod circom;
pub mod compress;
pub mod program;
#[cfg(test)] mod tests;
use std::{collections::HashMap, path::PathBuf};

use arecibo::{
  provider::{hyperkzg::EvaluationEngine, Bn256EngineKZG, GrumpkinEngine},
  spartan::batched::BatchedRelaxedR1CSSNARK,
  traits::{circuit::TrivialCircuit, Engine, Group},
};
use circom::CircomCircuit;
use ff::Field;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, trace};

pub type E1 = Bn256EngineKZG;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
pub type EE1 = EvaluationEngine<halo2curves::bn256::Bn256, E1>;
pub type EE2 = arecibo::provider::ipa_pc::EvaluationEngine<E2>;
pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

pub type F<G> = <G as Group>::Scalar;

pub type C1 = CircomCircuit;
pub type C2 = TrivialCircuit<F<G2>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProgramData {
  pub r1cs_paths:              Vec<PathBuf>,
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  pub rom:                     Vec<u64>,
  pub initial_public_input:    Vec<u64>,
  pub private_input:           HashMap<String, Value>, /* TODO: We should probably just make
                                                        * this a vec here */
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WitnessGeneratorType {
  #[serde(rename = "wasm")]
  Wasm { path: String, wtns_path: String },
  #[serde(rename = "circom-witnesscalc")]
  CircomWitnesscalc { path: String },
  #[serde(skip)]
  Raw(Vec<u8>), // TODO: Would prefer to not alloc here, but i got lifetime hell lol
}
