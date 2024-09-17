pub mod circom;
pub mod handler;
use circom::circuit::CircomCircuit;
use nova_snark::{
  provider::{ipa_pc::EvaluationEngine, Bn256EngineIPA, GrumpkinEngine},
  spartan::snark::RelaxedR1CSSNARK,
  traits::{circuit::TrivialCircuit, Engine, Group},
};
use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use handler::run_circuit;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(name = "prove")]
pub struct Args {
  #[arg(long, short, required = true)]
  input_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitData {
  #[serde(rename = "circom")]
  pub circom_path: PathBuf,
  #[serde(rename = "r1cs")]
  pub r1cs_path: PathBuf,
  #[serde(rename = "cbuild")]
  pub cbuild_path: PathBuf,
  #[serde(rename = "wgen")]
  pub wgen_path: PathBuf,
  // #[serde(rename = "wgen_type")]
  // pub wgen_type: WitnessgenType,
  #[serde(rename = "graph")]
  pub graph_path: PathBuf,
  pub private_input: HashMap<String, Value>,
  pub num_folds: usize,
  pub init_step_in: Vec<u64>,
}

pub type E1 = Bn256EngineIPA;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
pub type EE1 = EvaluationEngine<E1>;
pub type EE2 = EvaluationEngine<E2>;
pub type S1 = RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
pub type S2 = RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

pub type F<G> = <G as Group>::Scalar;

pub type C1 = CircomCircuit<<E1 as Engine>::Scalar>;
pub type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

// Note:
// Run with `cargo run --release -i setup/test.json`
// from the `./proofs/` dir.
fn main() {
  let file = Args::parse().input_file;
  println!("Using file: {:?}", file);
  let read = std::fs::read(file).unwrap();
  let circuit_data: CircuitData = serde_json::from_slice(&read).unwrap();
  run_circuit(circuit_data);
}
