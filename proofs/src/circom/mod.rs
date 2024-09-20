use std::{
  collections::HashMap,
  env::current_dir,
  fs,
  io::{BufReader, Cursor, Error, ErrorKind, Read, Result, Seek, SeekFrom},
  path::PathBuf,
  process::Command,
  sync::{Arc, Mutex},
  time::Instant,
};

use arecibo::{
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait},
  PublicParams, RecursiveSNARK,
};
use byteorder::{LittleEndian, ReadBytesExt};
use circom::circuit::CircomCircuit;
use ff::{Field, PrimeField};
use num_bigint::BigInt;
use r1cs::R1CS;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use self::witness::compute_witness_from_generator_type;
use super::*;

pub mod circuit;
pub mod r1cs;
pub mod witness;

#[derive(Serialize, Deserialize)]
struct CircomInput {
  step_in: Vec<String>,

  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

pub fn create_public_params(r1cs: R1CS) -> PublicParams<E1> {
  let circuit_primary = CircomCircuit { r1cs, witness: None };
  let circuit_secondary = TrivialCircuit::<F<G2>>::default();

  PublicParams::setup(&circuit_primary, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())
    .unwrap() // nova setup
}

// TODO: This entrypoint or something like it should be used for supernova too.
pub fn create_recursive_circuit(
  r1cs: R1CS,
  public_params: &PublicParams<E1>,
  initial_public_input: &[F<G1>],
  private_inputs: &[HashMap<String, Value>],
  witness_generator_type: WitnessGeneratorType,
) -> RecursiveSNARK<E1> {
  // let root = current_dir().unwrap();
  // let witness_generator_output = root.join("circom_witness.wtns");

  let mut now = Instant::now();
  let witness_0 = compute_witness_from_generator_type(
    initial_public_input,
    &private_inputs[0],
    &witness_generator_type,
  );
  debug!("Witness generation for step 0 took: {:?}, {}", now.elapsed(), witness_0.len());

  let c_primary = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness_0) }; // TODO: Have CircomCircuit take &R1CS
  let circuit_secondary = TrivialCircuit::<F<G2>>::default();
  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark = RecursiveSNARK::<E1>::new(
    public_params,
    &c_primary,
    &circuit_secondary,
    initial_public_input,
    &z0_secondary,
  )
  .unwrap();

  let mut public_input = initial_public_input.to_vec(); // TODO: Don't need this alloc probably
  for (i, private_input) in private_inputs.iter().enumerate() {
    now = Instant::now();
    let witness =
      compute_witness_from_generator_type(&public_input, private_input, &witness_generator_type);
    debug!("witness generation for step {} took: {:?}", i, now.elapsed());

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    public_input = circuit.get_public_outputs();

    now = Instant::now();
    let res = recursive_snark.prove_step(public_params, &circuit, &circuit_secondary);
    debug!("Proving for step {} took: {:?}", i, now.elapsed());
    assert!(res.is_ok());
  }
  recursive_snark
}
