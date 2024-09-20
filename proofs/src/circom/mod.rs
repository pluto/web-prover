use std::{
  collections::HashMap,
  env::current_dir,
  fs,
  path::{Path, PathBuf},
  process::Command,
  sync::{Arc, Mutex},
  time::Instant,
};

use arecibo::{
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait},
  PublicParams, RecursiveSNARK,
};
use circom::circuit::CircomCircuit;
use ff::{Field, PrimeField};
use num_bigint::BigInt;
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

pub fn create_recursive_circuit(
  witness_generator_type: WitnessGenType,
  witness_generator_file: &PathBuf,
  r1cs: R1CS,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<G1>>,
  pp: &PublicParams<E1>,
) -> std::result::Result<RecursiveSNARK<E1>, std::io::Error> {
  let root = current_dir().unwrap();
  let witness_generator_output = root.join("circom_witness.wtns");

  let iteration_count = private_inputs.len();

  let mut current_public_input = start_public_input;

  let graph_bin = std::fs::read(witness_generator_file)?;

  let mut now = Instant::now();

  let witness_0 = match witness_generator_type {
    WitnessGenType::CircomWitnesscalc => compute_witness_witnesscalc(
      current_public_input.clone(),
      private_inputs[0].clone(),
      &graph_bin,
    ),
    WitnessGenType::Node => compute_witness(
      current_public_input.clone(),
      private_inputs[0].clone(),
      witness_generator_file,
      &witness_generator_output,
    ),
  };

  debug!("witness generation for step 0 took: {:?}, {}", now.elapsed(), witness_0.len());

  let circuit_0 = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness_0) };
  let circuit_secondary = TrivialCircuit::<F<G2>>::default();
  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark = RecursiveSNARK::<E1>::new(
    pp,
    &circuit_0,
    &circuit_secondary,
    &current_public_input,
    &z0_secondary,
  )
  .unwrap();

  for (i, private_input) in private_inputs.iter().enumerate().take(iteration_count) {
    now = Instant::now();
    let witness = match witness_generator_type {
      WitnessGenType::CircomWitnesscalc =>
        compute_witness_witnesscalc(current_public_input.clone(), private_input.clone(), &graph_bin),
      WitnessGenType::Node => compute_witness(
        current_public_input.clone(),
        private_input.clone(),
        witness_generator_file,
        &witness_generator_output,
      ),
    };
    debug!("witness generation for step {} took: {:?}", i, now.elapsed());

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    current_public_input = circuit.get_public_outputs();

    now = Instant::now();
    let res = recursive_snark.prove_step(pp, &circuit, &circuit_secondary);
    debug!("proving for step {} took: {:?}", i, now.elapsed());
    assert!(res.is_ok());
  }

  Ok(recursive_snark)
}

pub fn compute_witness(
  current_public_input: Vec<F<G1>>,
  private_input: HashMap<String, Value>,
  witness_generator_file: &PathBuf,
  witness_generator_output: &Path,
) -> Vec<F<G1>> {
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.to_bytes()).to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let input_json = serde_json::to_string(&input).unwrap();

  generate_witness_from_wasm::<F<G1>>(witness_generator_file, &input_json, witness_generator_output)
}

fn compute_witness_witnesscalc(
  current_public_input: Vec<F<G1>>,
  private_input: HashMap<String, Value>,
  graph_data: &[u8],
) -> Vec<F<G1>> {
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.to_bytes()).to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let input_json = serde_json::to_string(&input).unwrap();

  let witness = circom_witnesscalc::calc_witness(&input_json, graph_data).unwrap();
  // let witness =
  //   capture_and_log(|| circom_witnesscalc::calc_witness(&input_json, graph_data).unwrap());

  witness
    .iter()
    .map(|elem| <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str()).unwrap())
    .collect()
}

pub fn generate_witness_from_wasm<Fr: PrimeField>(
  witness_wasm: &PathBuf,
  witness_input_json: &String,
  witness_output: &Path,
) -> Vec<Fr> {
  let root = current_dir().unwrap();
  let witness_generator_input = root.join("circom_input.json");
  fs::write(&witness_generator_input, witness_input_json).unwrap();

  let witness_js = witness_wasm.parent().unwrap().join("generate_witness.js");

  let output = Command::new("node")
    .arg(witness_js)
    .arg(witness_wasm)
    .arg(&witness_generator_input)
    .arg(witness_output)
    .output()
    .expect("failed to execute process");
  if !output.stdout.is_empty() || !output.stderr.is_empty() {
    print!("stdout: {}", std::str::from_utf8(&output.stdout).unwrap());
    print!("stderr: {}", std::str::from_utf8(&output.stderr).unwrap());
  }
  let _ = fs::remove_file(witness_generator_input);
  load_witness_from_bin_file(witness_output)
}

fn _capture_and_log<F, T>(f: F) -> T
where F: FnOnce() -> T {
  // Create a buffer to capture stdout
  let output_buffer = Arc::new(Mutex::new(Vec::new()));

  // Capture the stdout into this buffer
  std::io::set_output_capture(Some(output_buffer.clone()));

  // Call the function that generates the output
  let result = f();

  // Release the capture and flush
  std::io::set_output_capture(None);

  // Get the captured output
  let captured_output = output_buffer.lock().unwrap();
  let output_str = String::from_utf8_lossy(&captured_output);

  // Log the captured output using tracing
  trace!("{}", output_str);

  result
}
