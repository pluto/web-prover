pub mod handler;
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
  pub circom_path:   PathBuf,
  #[serde(rename = "r1cs")]
  pub r1cs_path:     PathBuf,
  #[serde(rename = "cbuild")]
  pub cbuild_path:   PathBuf,
  #[serde(rename = "wgen")]
  pub wgen_path:     PathBuf,
  #[serde(rename = "wgen_type")]
  pub wgen_type:     WitnessgenType,
  #[serde(rename = "graph")]
  pub graph_path:    PathBuf,
  pub private_input: HashMap<String, Value>,
  pub num_folds:     usize,
  pub init_step_in:  Vec<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum WitnessgenType {
  #[serde(rename = "node")]
  Node,
  #[serde(rename = "cpp")]
  Cpp,
  #[serde(rename = "circom-witnesscalc")]
  CircomWitnesscalc,
}

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
