#![feature(internal_output_capture)]

pub mod circom;
pub mod program;
#[cfg(test)] pub mod tests;
use std::{collections::HashMap, path::PathBuf};

use arecibo::{
  provider::{hyperkzg::EvaluationEngine, Bn256EngineKZG, GrumpkinEngine},
  spartan::batched::BatchedRelaxedR1CSSNARK,
  traits::{circuit::TrivialCircuit, Engine, Group},
};
use circom::CircomCircuit;
use clap::Parser;
use ff::Field;
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
}

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

  // Read in the supernova program data
  let file = args.input_file;
  info!("Using file: {:?}", file);
  let read = std::fs::read(file).unwrap();
  let program_data: ProgramData = serde_json::from_slice(&read).unwrap();
  program::run(&program_data);
}
