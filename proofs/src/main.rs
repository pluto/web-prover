pub mod handler;
use std::path::PathBuf;

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
  #[serde(rename = "witness")]
  pub witness_json: Value,
  #[serde(rename = "r1cs")]
  pub r1cs_path: PathBuf,
  #[serde(rename = "wgen")]
  pub wgen_path: PathBuf,
  pub num_folds: usize,
}

// Note:
// Run with `cargo run --release -i setup/test.json`
// from the `./proofs/` dir.
fn main() {
  let file = Args::parse().input_file;
  let read = std::fs::read(file).unwrap();
  let circuit_data: CircuitData = serde_json::from_slice(&read).unwrap();
  // dbg!(circuit_data.clone());
  run_circuit(circuit_data);
}
