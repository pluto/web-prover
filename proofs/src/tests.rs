//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

use std::str::FromStr;

use arecibo::supernova::RecursiveSNARK;
use circom::CircomInput;
use ff::PrimeField;
use num_bigint::BigInt;

use super::*;

pub const ROM: &[u64] = &[0, 1, 2, 0, 1, 2];

pub const ADD_INTO_ZEROTH_R1CS: &[u8] =
  include_bytes!("../examples/circuit_data/addIntoZeroth.r1cs");
pub const ADD_INTO_ZEROTH_GRAPH: &[u8] =
  include_bytes!("../examples/circuit_data/addIntoZeroth.bin");

pub const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("../examples/circuit_data/squareZeroth.r1cs");
pub const SQUARE_ZEROTH_GRAPH: &[u8] = include_bytes!("../examples/circuit_data/squareZeroth.bin");

pub const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("../examples/circuit_data/swapMemory.r1cs");
pub const SWAP_MEMORY_GRAPH: &[u8] = include_bytes!("../examples/circuit_data/swapMemory.bin");

pub const INIT_PUBLIC_INPUT: [u64; 2] = [1, 2];

#[allow(unused)]
fn remap_inputs(input_json: &str) -> Vec<(String, Vec<BigInt>)> {
  let circom_input: CircomInput = serde_json::from_str(input_json).unwrap();
  dbg!(&circom_input);
  let mut unfuckulated = vec![];
  unfuckulated.push((
    "step_in".to_string(),
    circom_input.step_in.into_iter().map(|s| BigInt::from_str(&s).unwrap()).collect(),
  ));
  for (k, v) in circom_input.extra {
    let val = v
      .as_array()
      .unwrap()
      .iter()
      .map(|x| BigInt::from_str(&x.as_number().unwrap().to_string()).unwrap())
      .collect::<Vec<BigInt>>();
    unfuckulated.push((k, val));
  }
  unfuckulated
}

rust_witness::witness!(addIntoZeroth);
#[allow(unused)]
fn add_into_zeroth_witness(input_json: &str) -> Vec<F<G1>> {
  addIntoZeroth_witness(remap_inputs(input_json))
    .into_iter()
    .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
    .collect()
}

rust_witness::witness!(squareZeroth);
fn square_zeroth_witness(input_json: &str) -> Vec<F<G1>> {
  squareZeroth_witness(remap_inputs(input_json))
    .into_iter()
    .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
    .collect()
}

rust_witness::witness!(swapMemory);
fn swap_memory_witness(input_json: &str) -> Vec<F<G1>> {
  swapMemory_witness(remap_inputs(input_json))
    .into_iter()
    .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
    .collect()
}

fn run_entry_wc() -> (SetupData, RecursiveSNARK<E1>) {
  let program_data = ProgramData {
    r1cs_types:              vec![
      R1CSType::Raw(ADD_INTO_ZEROTH_R1CS.to_vec()),
      R1CSType::Raw(SQUARE_ZEROTH_R1CS.to_vec()),
      R1CSType::Raw(SWAP_MEMORY_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(ADD_INTO_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
    ],
    rom:                     ROM.to_vec(),
    initial_public_input:    INIT_PUBLIC_INPUT.to_vec(),
    private_input:           HashMap::new(),
    witnesses:               vec![vec![]],
  };
  let circuit_list = program::initialize_circuit_list(&program_data);
  let setup_data = program::setup(circuit_list);
  println!("here");
  let snark = program::run(&program_data, &setup_data);
  (setup_data, snark)
}

fn run_entry_rwit() -> RecursiveSNARK<E1> {
  let program_data = ProgramData {
    r1cs_types:              vec![
      R1CSType::Raw(ADD_INTO_ZEROTH_R1CS.to_vec()),
      R1CSType::Raw(SQUARE_ZEROTH_R1CS.to_vec()),
      R1CSType::Raw(SWAP_MEMORY_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::RustWitness(add_into_zeroth_witness),
      WitnessGeneratorType::RustWitness(square_zeroth_witness),
      WitnessGeneratorType::RustWitness(swap_memory_witness),
    ],
    rom:                     ROM.to_vec(),
    initial_public_input:    INIT_PUBLIC_INPUT.to_vec(),
    private_input:           HashMap::new(),
    witnesses:               vec![vec![]],
  };
  let circuit_list = program::initialize_circuit_list(&program_data);
  let setup_data = program::setup(circuit_list);
  program::run(&program_data, &setup_data)
}

#[test]
#[tracing_test::traced_test]
fn test_run_wc() {
  let (_, proof) = run_entry_wc();
  let final_mem = [
    F::<G1>::from(0),
    F::<G1>::from(81),
    F::<G1>::from(6),
    F::<G1>::from(0),
    F::<G1>::from(1),
    F::<G1>::from(2),
    F::<G1>::from(0),
    F::<G1>::from(1),
    F::<G1>::from(2),
  ];
  assert_eq!(&final_mem.to_vec(), proof.zi_primary());
}

#[test]
#[tracing_test::traced_test]
fn test_run_verify_wc() {
  let (setup_data, recursive_snark) = run_entry_wc();
  let proof = program::compress(&setup_data, &recursive_snark);

  // Serialize and compress further
  let serialized_compressed_proof = proof.serialize_and_compress();

  // Decompress and deserialize
  let proof = serialized_compressed_proof.decompress_and_serialize();

  // Extend the initial state input with the ROM (happens internally inside of `program::run`, so
  // we do it out here)
  let mut z0_primary = INIT_PUBLIC_INPUT.to_vec();
  z0_primary.push(0);
  z0_primary.extend(ROM.iter());

  // Check that it verifies
  let res = proof.0.verify(
    &setup_data.public_params,
    &setup_data.verifier_key,
    z0_primary.into_iter().map(F::<G1>::from).collect::<Vec<_>>().as_slice(),
    [0].into_iter().map(F::<G2>::from).collect::<Vec<_>>().as_slice(),
  );
  assert!(res.is_ok());
}

#[test]
#[tracing_test::traced_test]
fn test_parse_batch_wc() {
  let read = std::fs::read("examples/parse_batch_wc.json").unwrap();
  let program_data: ProgramData = serde_json::from_slice(&read).unwrap();
  let circuit_list = program::initialize_circuit_list(&program_data);
  let setup_data = program::setup(circuit_list);

  let recursive_snark = program::run(&program_data, &setup_data);

  let final_mem = [
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(4),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
  ];
  assert_eq!(&final_mem.to_vec(), recursive_snark.zi_primary());
}

#[test]
#[tracing_test::traced_test]
fn test_parse_batch_wasm() {
  let read = std::fs::read("examples/parse_batch_wasm.json").unwrap();
  let program_data: ProgramData = serde_json::from_slice(&read).unwrap();

  let circuit_list = program::initialize_circuit_list(&program_data);
  let setup_data = program::setup(circuit_list);

  let recursive_snark = program::run(&program_data, &setup_data);
  let final_mem = [
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(4),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
    F::<G1>::from(0),
  ];
  assert_eq!(&final_mem.to_vec(), recursive_snark.zi_primary());
}

rust_witness::witness!(parsefoldbatch);
fn parse_batch_witness(input_json: &str) -> Vec<F<G1>> {
  parsefoldbatch_witness(remap_inputs(input_json))
    .into_iter()
    .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
    .collect()
}

#[test]
#[tracing_test::traced_test]
fn test_parse_batch_rwit() {
  let read = std::fs::read("examples/parse_batch_rwit.json").unwrap();
  let mut program_data: ProgramData = serde_json::from_slice(&read).unwrap();
  program_data.witness_generator_types =
    vec![WitnessGeneratorType::RustWitness(parse_batch_witness)];
  let circuit_list = program::initialize_circuit_list(&program_data);
  let setup_data = program::setup(circuit_list);

  program::run(&program_data, &setup_data);
}

rust_witness::witness!(aesgcmfold);
fn aes_gcm_fold_witness(input_json: &str) -> Vec<F<G1>> {
  aesgcmfold_witness(remap_inputs(input_json))
    .into_iter()
    .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
    .collect()
}

#[test]
#[tracing_test::traced_test]
fn test_aes_gcm_fold_rwit() {
  let read = std::fs::read("examples/aes_fold.json").unwrap();
  let mut program_data: ProgramData = serde_json::from_slice(&read).unwrap();
  program_data.witness_generator_types =
    vec![WitnessGeneratorType::RustWitness(aes_gcm_fold_witness)];
  let circuit_list = program::initialize_circuit_list(&program_data);
  let setup_data = program::setup(circuit_list);

  program::run(&program_data, &setup_data);
}
