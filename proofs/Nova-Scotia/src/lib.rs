use std::{
  collections::HashMap,
  env::current_dir,
  fs,
  path::{Path, PathBuf},
};

use crate::circom::reader::generate_witness_from_bin;
use circom::circuit::{CircomCircuit, R1CS};
use ff::Field;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::{
  provider::{Bn256EngineIPA, Bn256EngineKZG, GrumpkinEngine},
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
  PublicParams, RecursiveSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(not(target_family = "wasm"))]
use crate::circom::reader::generate_witness_from_wasm;

#[cfg(target_family = "wasm")]
use crate::circom::wasm::generate_witness_from_wasm;

pub mod circom;

type E1 = Bn256EngineIPA;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

pub type F<G> = <G as Group>::Scalar;
pub type C1<G> = CircomCircuit<<G as Group>::Scalar>;
pub type C2<G> = TrivialCircuit<<G as Group>::Scalar>;

#[derive(Clone)]
pub enum FileLocation {
  PathBuf(PathBuf),
  URL(String),
}

pub fn create_public_params(
  r1cs: R1CS<F<<E1 as Engine>::GE>>,
) -> PublicParams<E1, E2, C1<<E1 as Engine>::GE>, C2<<E2 as Engine>::GE>> {
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

#[cfg(not(target_family = "wasm"))]
fn compute_witness<G1, G2>(
  current_public_input: Vec<String>,
  private_input: HashMap<String, Value>,
  witness_generator_file: FileLocation,
  witness_generator_output: &Path,
) -> Vec<<G1 as Group>::Scalar>
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>,
{
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let is_wasm = match &witness_generator_file {
    FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
    FileLocation::URL(_) => true,
  };
  let input_json = serde_json::to_string(&input).unwrap();

  if is_wasm {
    generate_witness_from_wasm::<F<G1>>(
      &witness_generator_file,
      &input_json,
      &witness_generator_output,
    )
  } else {
    let witness_generator_file = match &witness_generator_file {
      FileLocation::PathBuf(path) => path,
      FileLocation::URL(_) => panic!("unreachable"),
    };
    generate_witness_from_bin::<F<G1>>(
      &witness_generator_file,
      &input_json,
      &witness_generator_output,
    )
  }
}

#[cfg(target_family = "wasm")]
async fn compute_witness<G1, G2>(
  current_public_input: Vec<String>,
  private_input: HashMap<String, Value>,
  witness_generator_file: FileLocation,
) -> Vec<<G1 as Group>::Scalar>
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>,
{
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let is_wasm = match &witness_generator_file {
    FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
    FileLocation::URL(_) => true,
  };
  let input_json = serde_json::to_string(&input).unwrap();

  if is_wasm {
    generate_witness_from_wasm::<F<G1>>(&witness_generator_file, &input_json).await
  } else {
    let root = current_dir().unwrap(); // compute path only when generating witness from a binary
    let witness_generator_output = root.join("circom_witness.wtns");
    let witness_generator_file = match &witness_generator_file {
      FileLocation::PathBuf(path) => path,
      FileLocation::URL(_) => panic!("unreachable"),
    };
    generate_witness_from_bin::<F<G1>>(
      &witness_generator_file,
      &input_json,
      &witness_generator_output,
    )
  }
}

#[cfg(not(target_family = "wasm"))]
pub fn create_recursive_circuit<G1, G2>(
  witness_generator_file: FileLocation,
  r1cs: R1CS<F<<E1 as Engine>::GE>>,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<<E1 as Engine>::GE>>,
  pp: &PublicParams<E1, E2, C1<<E1 as Engine>::GE>, C2<<E2 as Engine>::GE>>,
) -> Result<
  RecursiveSNARK<
    E1,
    E2,
    CircomCircuit<<E1 as Engine>::Scalar>,
    TrivialCircuit<<E2 as Engine>::Scalar>,
  >,
  std::io::Error,
> {
  let root = current_dir().unwrap();
  let witness_generator_output = root.join("circom_witness.wtns");

  let iteration_count = private_inputs.len();

  let start_public_input_hex = start_public_input
    .iter()
    .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
    .collect::<Vec<String>>();
  let mut current_public_input = start_public_input_hex.clone();

  let witness_0 = compute_witness::<<E1 as Engine>::GE, <E2 as Engine>::GE>(
    current_public_input.clone(),
    private_inputs[0].clone(),
    witness_generator_file.clone(),
    &witness_generator_output,
  );

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
    >::new(&pp, &circuit_0, &circuit_secondary, &start_public_input, &z0_secondary)
    .unwrap();

  for i in 0..iteration_count {
    let witness = compute_witness::<<E1 as Engine>::GE, <E2 as Engine>::GE>(
      current_public_input.clone(),
      private_inputs[i].clone(),
      witness_generator_file.clone(),
      &witness_generator_output,
    );

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    let current_public_output = circuit.get_public_outputs();
    current_public_input = current_public_output
      .iter()
      .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
      .collect();

    let res = recursive_snark.prove_step(&pp, &circuit, &circuit_secondary);
    assert!(res.is_ok());
  }
  fs::remove_file(witness_generator_output)?;

  Ok(recursive_snark)
}

#[cfg(target_family = "wasm")]
pub async fn create_recursive_circuit<G1, G2>(
  witness_generator_file: FileLocation,
  r1cs: R1CS<F<G1>>,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<G1>>,
  pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>, std::io::Error>
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>,
{
  let iteration_count = private_inputs.len();

  let start_public_input_hex = start_public_input
    .iter()
    .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
    .collect::<Vec<String>>();
  let mut current_public_input = start_public_input_hex.clone();

  let witness_0 = compute_witness::<G1, G2>(
    current_public_input.clone(),
    private_inputs[0].clone(),
    witness_generator_file.clone(),
  )
  .await;

  let circuit_0 = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness_0) };
  let circuit_secondary = TrivialTestCircuit::default();
  let z0_secondary = vec![G2::Scalar::ZERO];

  let mut recursive_snark = RecursiveSNARK::<G1, G2, C1<G1>, C2<G2>>::new(
    &pp,
    &circuit_0,
    &circuit_secondary,
    start_public_input.clone(),
    z0_secondary.clone(),
  );

  for i in 0..iteration_count {
    let witness = compute_witness::<G1, G2>(
      current_public_input.clone(),
      private_inputs[i].clone(),
      witness_generator_file.clone(),
    )
    .await;

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    let current_public_output = circuit.get_public_outputs();
    current_public_input = current_public_output
      .iter()
      .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
      .collect();

    let res = recursive_snark.prove_step(
      &pp,
      &circuit,
      &circuit_secondary,
      start_public_input.clone(),
      z0_secondary.clone(),
    );
    assert!(res.is_ok());
  }

  Ok(recursive_snark)
}

// #[cfg(not(target_family = "wasm"))]
// pub fn continue_recursive_circuit<G1, G2>(
//   recursive_snark: &mut RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>,
//   last_zi: Vec<F<G1>>,
//   witness_generator_file: FileLocation,
//   r1cs: R1CS<F<G1>>,
//   private_inputs: Vec<HashMap<String, Value>>,
//   start_public_input: Vec<F<G1>>,
//   pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
// ) -> Result<(), std::io::Error>
// where
//   G1: Group<Base = <G2 as Group>::Scalar>,
//   G2: Group<Base = <G1 as Group>::Scalar>,
// {
//   let root = current_dir().unwrap();
//   let witness_generator_output = root.join("circom_witness.wtns");

//   let iteration_count = private_inputs.len();

//   let mut current_public_input = last_zi
//     .iter()
//     .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
//     .collect::<Vec<String>>();

//   let circuit_secondary = TrivialCircuit::default();
//   let z0_secondary = vec![G2::Scalar::ZERO];

//   for i in 0..iteration_count {
//     let witness = compute_witness::<G1, G2>(
//       current_public_input.clone(),
//       private_inputs[i].clone(),
//       witness_generator_file.clone(),
//       &witness_generator_output,
//     );

//     let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

//     let current_public_output = circuit.get_public_outputs();
//     current_public_input = current_public_output
//       .iter()
//       .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
//       .collect();

//     let res = recursive_snark.prove_step(
//       pp,
//       &circuit,
//       &circuit_secondary,
//       start_public_input.clone(),
//       z0_secondary.clone(),
//     );

//     assert!(res.is_ok());
//   }

//   fs::remove_file(witness_generator_output)?;

//   Ok(())
// }

#[cfg(target_family = "wasm")]
pub async fn continue_recursive_circuit<G1, G2>(
  recursive_snark: &mut RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>,
  last_zi: Vec<F<G1>>,
  witness_generator_file: FileLocation,
  r1cs: R1CS<F<G1>>,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<G1>>,
  pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<(), std::io::Error>
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>,
{
  let root = current_dir().unwrap();
  let witness_generator_output = root.join("circom_witness.wtns");

  let iteration_count = private_inputs.len();

  let mut current_public_input = last_zi
    .iter()
    .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
    .collect::<Vec<String>>();

  let circuit_secondary = TrivialTestCircuit::default();
  let z0_secondary = vec![G2::Scalar::ZERO];

  for i in 0..iteration_count {
    let witness = compute_witness::<G1, G2>(
      current_public_input.clone(),
      private_inputs[i].clone(),
      witness_generator_file.clone(),
    )
    .await;

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    let current_public_output = circuit.get_public_outputs();
    current_public_input = current_public_output
      .iter()
      .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
      .collect();

    let res = recursive_snark.prove_step(
      pp,
      &circuit,
      &circuit_secondary,
      start_public_input.clone(),
      z0_secondary.clone(),
    );

    assert!(res.is_ok());
  }

  fs::remove_file(witness_generator_output)?;

  Ok(())
}
