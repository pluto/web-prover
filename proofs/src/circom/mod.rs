use super::*;
use std::{collections::HashMap, env::current_dir, fs, path::PathBuf};

use circom::circuit::{CircomCircuit, R1CS};
use ff::{Field, PrimeField};
use nova_snark::{
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
  PublicParams, RecursiveSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod circuit;
pub mod r1cs;

pub fn create_public_params(r1cs: R1CS<F<<E1 as Engine>::GE>>) -> PublicParams<E1, E2, C1, C2> {
  let circuit_primary = CircomCircuit::<<E1 as Engine>::Scalar> { r1cs, witness: None };
  let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

  PublicParams::setup(&circuit_primary, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())
    .unwrap()
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
  step_in: Vec<String>,

  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

fn compute_witness(
  current_public_input: Vec<String>,
  private_input: HashMap<String, Value>,
  witness_generator_file: &[u8],
) -> Vec<<G1 as Group>::Scalar> {
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let input_json = serde_json::to_string(&input).unwrap();

  let witness = circom_witnesscalc::calc_witness(&input_json, witness_generator_file).unwrap();
  witness
    .iter()
    .map(|elem| <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str()).unwrap())
    .collect()
}

pub fn create_recursive_circuit(
  witness_generator_file: &PathBuf,
  r1cs: R1CS<F<G1>>,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<G1>>,
  pp: &PublicParams<E1, E2, C1, C2>,
) -> Result<RecursiveSNARK<E1, E2, C1, C2>, std::io::Error> {
  use std::time::Instant;

  let iteration_count = private_inputs.len();

  let start_public_input_hex = start_public_input
    .iter()
    .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
    .collect::<Vec<String>>();
  let mut current_public_input = start_public_input_hex.clone();

  let graph_bin = std::fs::read(witness_generator_file)?;

  let mut now = Instant::now();
  println!("private_inputs: {:?}", private_inputs[0]);
  let witness_0 =
    compute_witness(current_public_input.clone(), private_inputs[0].clone(), &graph_bin);
  println!("witness generation for step 0: {:?}, {}", now.elapsed(), witness_0.len());

  let circuit_0 =
    CircomCircuit::<<E1 as Engine>::Scalar> { r1cs: r1cs.clone(), witness: Some(witness_0) };
  let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();
  let z0_secondary = vec![<E2 as Engine>::Scalar::ZERO];

  let mut recursive_snark =
    RecursiveSNARK::<
      E1,
      E2,
      CircomCircuit<<E1 as Engine>::Scalar>,
      TrivialCircuit<<E2 as Engine>::Scalar>,
    >::new(pp, &circuit_0, &circuit_secondary, &start_public_input, &z0_secondary)
    .unwrap();

  for (i, private_input) in private_inputs.iter().enumerate().take(iteration_count) {
    now = Instant::now();
    let witness = compute_witness(current_public_input.clone(), private_input.clone(), &graph_bin);
    println!("witness generation for step {}: {:?}", i, now.elapsed());

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    let current_public_output = circuit.get_public_outputs();
    current_public_input = current_public_output
      .iter()
      .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
      .collect();

    now = Instant::now();
    let res = recursive_snark.prove_step(pp, &circuit, &circuit_secondary);
    println!("proving for step {}: {:?}", i, now.elapsed());
    assert!(res.is_ok());
  }

  Ok(recursive_snark)
}
