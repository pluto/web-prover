//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

use ff::PrimeField;
use program::utils::remap_inputs;
use proving_ground::supernova::RecursiveSNARK;

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

pub const MAX_ROM_SIZE: usize = 10;

rust_witness::witness!(addIntoZeroth);
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

fn run_entry_wc() -> (PublicParams<E1>, RecursiveSNARK<E1>) {
  let mut program_data = ProgramData {
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
    rom:                     vec![0; MAX_ROM_SIZE],
    initial_public_input:    INIT_PUBLIC_INPUT.to_vec(),
    private_input:           HashMap::new(),
    witnesses:               vec![vec![]],
  };
  let circuit_list = program::initialize_circuit_list(&program_data);
  let public_params = program::setup(circuit_list);
  let mut rom = ROM.to_vec();
  rom.resize(MAX_ROM_SIZE, u64::MAX);
  program_data.rom = rom;
  let recursive_snark = program::run(&program_data, &public_params);
  (public_params, recursive_snark)
}

fn run_entry_rwit() -> (PublicParams<E1>, RecursiveSNARK<E1>) {
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
    private_input:           vec![HashMap::new(), HashMap::new(), HashMap::new()],
    witnesses:               vec![vec![]],
  };
  let circuit_list = program::initialize_circuit_list(&program_data);
  let public_params = program::setup(circuit_list);
  let recursive_snark = program::run(&program_data, &public_params);
  (public_params, recursive_snark)
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
    F::<G1>::from(u64::MAX),
    F::<G1>::from(u64::MAX),
    F::<G1>::from(u64::MAX),
    F::<G1>::from(u64::MAX),
  ];
  assert_eq!(&final_mem.to_vec(), proof.zi_primary());
}

#[test]
#[tracing_test::traced_test]
fn test_run_rwit() {
  let (_, proof) = run_entry_rwit();
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
fn test_run_serialized_verify_wc() {
  let (public_params, recursive_snark) = run_entry_wc();

  // Pseudo-offline the `PublicParams` and regenerate it
  let serialized_public_params = bincode::serialize(&public_params).unwrap();
  let public_params = bincode::deserialize(&serialized_public_params).unwrap();

  // Create the compressed proof with the offlined `PublicParams`
  let proof = program::compress_proof(&recursive_snark, &public_params);

  // Serialize the proof and zlib compress further
  let serialized_compressed_proof = proof.serialize_and_compress();

  // Decompress and deserialize
  let proof = serialized_compressed_proof.decompress_and_serialize();

  // Extend the initial state input with the ROM (happens internally inside of `program::run`, so
  // we do it out here)
  let mut z0_primary = INIT_PUBLIC_INPUT.to_vec();
  z0_primary.push(0);
  let mut rom = ROM.to_vec();
  rom.resize(MAX_ROM_SIZE, u64::MAX);
  z0_primary.extend(rom.iter());

  // Check that it verifies with offlined `PublicParams` regenerated pkey vkey
  let (_pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let res = proof.0.verify(
    &public_params,
    &vk,
    z0_primary.clone().into_iter().map(F::<G1>::from).collect::<Vec<_>>().as_slice(),
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

#[ignore]
#[test]
#[tracing_test::traced_test]
fn test_end_to_end_proofs() {
  // HTTP/1.1 200 OK
  // content-type: application/json; charset=utf-8
  // content-encoding: gzip
  // Transfer-Encoding: chunked
  //
  // {
  //    "data": {
  //        "items": [
  //            {
  //                "data": "Artist",
  //                "profile": {
  //                    "name": "Taylor Swift"
  //                }
  //            }
  //        ]
  //    }
  // }

  // let read = std::fs::read("examples/aes_http_json_extract.json").unwrap();
  let read = std::fs::read("examples/universal.json").unwrap();
  let program_data: ProgramData = serde_json::from_slice(&read).unwrap();

  let ProgramOutput { recursive_snark, .. } = program::run(&program_data);

  let res = "\"Taylor Swift\"";
  let final_mem =
    res.as_bytes().into_iter().map(|val| F::<G1>::from(*val as u64)).collect::<Vec<F<G1>>>();

  assert_eq!(recursive_snark.zi_primary()[..res.len()], final_mem);
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
