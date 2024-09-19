use std::{
  collections::HashMap,
  fs, io,
  path::PathBuf,
  sync::{Arc, Mutex},
};

// use arecibo::supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit};
use arecibo::{
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
  PublicParams, RecursiveSNARK,
};
use circom::circuit::CircomCircuit;
use ff::{Field, PrimeField};
use num_bigint::BigInt;
use num_traits::Num;
use r1cs::R1CS;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;

pub mod circuit;
pub mod r1cs;

pub fn create_public_params(r1cs: R1CS) -> PublicParams<E1> {
  let circuit_primary = CircomCircuit { r1cs, witness: None };
  let circuit_secondary = TrivialCircuit::<F<G2>>::default();

  PublicParams::setup(&circuit_primary, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())
    .unwrap() // nova setup
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
  step_in: Vec<String>,

  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

pub fn compute_witness(
  current_public_input: Vec<F<G1>>,
  private_input: HashMap<String, Value>,
  graph_data: &[u8],
) -> Vec<<G1 as Group>::Scalar> {
  dbg!(&current_public_input);
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.to_bytes()).to_str_radix(10))
    .collect();

  let input = CircomInput { step_in: decimal_stringified_input, extra: private_input.clone() };

  let input_json = serde_json::to_string(&input).unwrap();

  dbg!(&input_json);
  let witness = circom_witnesscalc::calc_witness(&input_json, graph_data).unwrap();
  // let witness =
  //   capture_and_log(|| circom_witnesscalc::calc_witness(&input_json, graph_data).unwrap()); //
  // TODO: helpful if we want tracing crate only to handle stdout

  witness
    .iter()
    .map(|elem| <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str()).unwrap())
    .collect()
}

pub fn create_recursive_circuit(
  witness_generator_file: &PathBuf,
  r1cs: R1CS,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<G1>>,
  pp: &PublicParams<E1>,
) -> Result<RecursiveSNARK<E1>, std::io::Error> {
  use std::time::Instant;

  let iteration_count = private_inputs.len();

  // let start_public_input_hex = start_public_input
  //   .iter()
  //   .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
  //   .collect::<Vec<String>>();
  // let mut current_public_input = start_public_input_hex.clone();

  // TODO: This should be held in memory instead of read every time.
  let graph_bin = std::fs::read(witness_generator_file)?;

  let mut now = Instant::now();
  trace!("private_inputs: {:?}", private_inputs[0]);
  let witness_0 =
    compute_witness(start_public_input.clone(), private_inputs[0].clone(), &graph_bin);
  debug!("witness generation for step 0 took: {:?}, {}", now.elapsed(), witness_0.len());

  let circuit_0 = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness_0) };
  let circuit_secondary = TrivialCircuit::<F<G2>>::default();
  let z0_secondary = vec![<F<G2>>::ZERO];

  let mut recursive_snark = RecursiveSNARK::<E1>::new(
    pp,
    &circuit_0,
    &circuit_secondary,
    &start_public_input,
    &z0_secondary,
  )
  .unwrap();

  let mut current_public_input = start_public_input; // TODO: awk

  for (i, private_input) in private_inputs.iter().enumerate().take(iteration_count) {
    now = Instant::now();
    let witness = compute_witness(current_public_input.clone(), private_input.clone(), &graph_bin);
    debug!("witness generation for step {} took: {:?}", i, now.elapsed());

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    current_public_input = circuit.get_public_outputs();
    // current_public_input = current_public_output
    //   .iter()
    //   .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
    //   .collect();

    now = Instant::now();
    let res = recursive_snark.prove_step(pp, &circuit, &circuit_secondary);
    debug!("proving for step {} took: {:?}", i, now.elapsed());
    assert!(res.is_ok());
  }

  Ok(recursive_snark)
}

fn capture_and_log<F, T>(f: F) -> T
where F: FnOnce() -> T {
  // Create a buffer to capture stdout
  let output_buffer = Arc::new(Mutex::new(Vec::new()));

  // Capture the stdout into this buffer
  io::set_output_capture(Some(output_buffer.clone()));

  // Call the function that generates the output
  let result = f();

  // Release the capture and flush
  io::set_output_capture(None);

  // Get the captured output
  let captured_output = output_buffer.lock().unwrap();
  let output_str = String::from_utf8_lossy(&captured_output);

  // Log the captured output using tracing
  trace!("{}", output_str);

  result
}
