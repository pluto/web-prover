#![feature(internal_output_capture)]

pub mod circom;
pub mod handler;
pub mod program;
#[cfg(test)] mod tests;
use std::{collections::HashMap, path::PathBuf};

use arecibo::{
  provider::{ipa_pc::EvaluationEngine, Bn256EngineIPA, GrumpkinEngine},
  spartan::snark::RelaxedR1CSSNARK,
  traits::{circuit::TrivialCircuit, Engine, Group},
};
use circom::circuit::CircomCircuit;
use clap::Parser;
use ff::Field;
use handler::run_circuit;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, trace, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "prove")]
pub struct Args {
  /// Setup file to use for generating proof
  #[arg(long, short, required = true)]
  input_file: PathBuf,

  /// Increase logging verbosity (-v, -vv, -vvv, etc.)
  #[arg(short, long, action = clap::ArgAction::Count)]
  verbose: u8,

  #[arg(short, long, value_enum)]
  scheme: Scheme,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitData {
  pub circuit_path:           PathBuf,
  pub r1cs_path:              PathBuf,
  pub graph_path:             PathBuf,
  pub witness_generator_type: WitnessGeneratorType,
  pub num_folds:              usize,
  pub initial_public_input:   Vec<u64>,
  pub private_input:          HashMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WitnessGeneratorType {
  #[serde(rename = "wasm")]
  Wasm { path: String, wtns_path: String },
  #[serde(rename = "circom-witnesscalc")]
  CircomWitnesscalc { path: String },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Scheme {
  Nova,
  SuperNova,
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

pub type C1 = CircomCircuit;
pub type C2 = TrivialCircuit<F<G2>>;

// Note:
// Run with `cargo run --release -i setup/test.json`
// from the `./proofs/` dir.
fn main() {
  let args = Args::parse();

  // Logging options
  let log_level = match args.verbose {
    0 => Level::ERROR,
    1 => Level::WARN,
    2 => Level::INFO,
    3 => Level::DEBUG,
    _ => Level::TRACE,
  };
  let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
  tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

  let file = args.input_file;
  info!("Using file: {:?}", file);

  let read = std::fs::read(file).unwrap();
  let circuit_data: CircuitData = serde_json::from_slice(&read).unwrap();
  match args.scheme {
    Scheme::Nova => run_circuit(circuit_data),
    Scheme::SuperNova => program::run_program(circuit_data),
  }
}
