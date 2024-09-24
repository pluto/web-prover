//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

use super::*;

const ROM: &[u64] = &[0, 1, 2, 0, 1, 2];

const ADD_INTO_ZEROTH_R1CS: &str = "examples/circuit_data/addIntoZeroth.r1cs";
const ADD_INTO_ZEROTH_GRAPH: &[u8] = include_bytes!("../examples/circuit_data/addIntoZeroth.bin");

const SQUARE_ZEROTH_R1CS: &str = "examples/circuit_data/squareZeroth.r1cs";
const SQUARE_ZEROTH_GRAPH: &[u8] = include_bytes!("../examples/circuit_data/squareZeroth.bin");

const SWAP_MEMORY_R1CS: &str = "examples/circuit_data/swapMemory.r1cs";
const SWAP_MEMORY_GRAPH: &[u8] = include_bytes!("../examples/circuit_data/swapMemory.bin");

#[test]
#[tracing_test::traced_test]
fn test_run() {
  let program_data = ProgramData {
    r1cs_paths:              vec![
      PathBuf::from(ADD_INTO_ZEROTH_R1CS),
      PathBuf::from(SQUARE_ZEROTH_R1CS),
      PathBuf::from(SWAP_MEMORY_R1CS),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(ADD_INTO_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
    ],
    rom:                     ROM.to_vec(),
    initial_public_input:    vec![1, 2],
    private_input:           HashMap::new(),
  };

  let (_pp, recursive_snark) = program::run(program_data);

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
  assert_eq!(&final_mem.to_vec(), recursive_snark.zi_primary());
}

#[test]
#[tracing_test::traced_test]
fn test_run_verify() {
  let z0_primary = vec![1, 2];
  let program_data = ProgramData {
    r1cs_paths:              vec![
      PathBuf::from(ADD_INTO_ZEROTH_R1CS),
      PathBuf::from(SQUARE_ZEROTH_R1CS),
      PathBuf::from(SWAP_MEMORY_R1CS),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(ADD_INTO_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
    ],
    rom:                     ROM.to_vec(),
    initial_public_input:    z0_primary.clone(),
    private_input:           HashMap::new(),
  };

  let (public_params, recursive_snark) = program::run(program_data);

  // Compress the proof
  let (_prover_key, verifier_key, compressed_snark) =
    program::compress(&public_params, &recursive_snark);
  let json = serde_json::to_string(&compressed_snark).unwrap();
  assert_eq!(json.len(), 28410);

  // Check that it verifies
  let res = compressed_snark.verify(
    &public_params,
    &verifier_key,
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

  let (_pp, recursive_snark) = program::run(program_data);

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

  let (_pp, recursive_snark) = program::run(program_data);

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
