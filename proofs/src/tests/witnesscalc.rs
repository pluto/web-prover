use std::str::FromStr;

use program::data::Expanded;
use serde_json::json;

use super::*;
use crate::program::data::{R1CSType, SetupData, WitnessGeneratorType};

const ADD_EXTERNAL_GRAPH: &[u8] = include_bytes!("../../examples/circuit_data/add_external.bin");
const SQUARE_ZEROTH_GRAPH: &[u8] = include_bytes!("../../examples/circuit_data/square_zeroth.bin");
const SWAP_MEMORY_GRAPH: &[u8] = include_bytes!("../../examples/circuit_data/swap_memory.bin");

const TEST_OFFLINE_PATH: &str = "src/tests/test_run_serialized_verify.bin";

fn get_setup_data() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(ADD_EXTERNAL_R1CS.to_vec()),
      R1CSType::Raw(SQUARE_ZEROTH_R1CS.to_vec()),
      R1CSType::Raw(SWAP_MEMORY_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(ADD_EXTERNAL_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  }
}

fn run_entry(setup_data: SetupData) -> (ProgramData<Online, Expanded>, RecursiveSNARK<E1>) {
  let mut external_input0: HashMap<String, Value> = HashMap::new();
  external_input0.insert("external".to_string(), json!(EXTERNAL_INPUTS[0]));
  let mut external_input1: HashMap<String, Value> = HashMap::new();
  external_input1.insert("external".to_string(), json!(EXTERNAL_INPUTS[1]));
  let rom_data = HashMap::from([
    (String::from("ADD_EXTERNAL"), CircuitData { opcode: 0 }),
    (String::from("SQUARE_ZEROTH"), CircuitData { opcode: 1 }),
    (String::from("SWAP_MEMORY"), CircuitData { opcode: 2 }),
  ]);
  let rom = vec![
    RomOpcodeConfig { name: String::from("ADD_EXTERNAL"), private_input: external_input0 },
    RomOpcodeConfig { name: String::from("SQUARE_ZEROTH"), private_input: HashMap::new() },
    RomOpcodeConfig { name: String::from("SWAP_MEMORY"), private_input: HashMap::new() },
    RomOpcodeConfig { name: String::from("ADD_EXTERNAL"), private_input: external_input1 },
    RomOpcodeConfig { name: String::from("SQUARE_ZEROTH"), private_input: HashMap::new() },
    RomOpcodeConfig { name: String::from("SWAP_MEMORY"), private_input: HashMap::new() },
  ];
  let public_params = program::setup(&setup_data);
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom_data,
    rom,
    initial_nivc_input: INIT_PUBLIC_INPUT.to_vec(),
    inputs: HashMap::new(),
    witnesses: vec![],
  }
  .into_expanded();
  let recursive_snark = program::run(&program_data);
  (program_data, recursive_snark)
}

#[test]
#[tracing_test::traced_test]
fn test_run() {
  let setup_data = get_setup_data();
  let (_, proof) = run_entry(setup_data);
  // [1,2] + [5,7]
  // --> [6,9]
  // --> [36,9]
  // --> [9,36] + [13,1]
  // --> [22,37]
  // --> [484,37]
  // [37,484]
  let final_mem = [
    F::<G1>::from(37),
    F::<G1>::from(484),
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
fn test_run_serialized_verify() {
  let setup_data = get_setup_data();
  let (program_data, recursive_snark) = run_entry(setup_data);

  // Pseudo-offline the `PublicParams` and regenerate it
  let program_data = program_data.into_offline(PathBuf::from_str(TEST_OFFLINE_PATH).unwrap());
  let program_data = program_data.into_online();

  // Create the compressed proof with the offlined `PublicParams`
  let proof = program::compress_proof(&recursive_snark, &program_data.public_params);

  // Serialize the proof and zlib compress further
  let serialized_compressed_proof = proof.serialize_and_compress();

  // Decompress and deserialize
  let proof = serialized_compressed_proof.decompress_and_serialize();

  // Extend the initial state input with the ROM (happens internally inside of `program::run`, so
  // we do it out here just for the test)
  let mut z0_primary = INIT_PUBLIC_INPUT.to_vec();
  z0_primary.push(0);
  let mut rom = ROM.to_vec();
  rom.resize(MAX_ROM_LENGTH, u64::MAX);
  z0_primary.extend(rom.iter());

  // Check that it verifies with offlined `PublicParams` regenerated pkey vkey
  let (_pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&program_data.public_params).unwrap();
  let res = proof.0.verify(
    &program_data.public_params,
    &vk,
    z0_primary.clone().into_iter().map(F::<G1>::from).collect::<Vec<_>>().as_slice(),
    [0].into_iter().map(F::<G2>::from).collect::<Vec<_>>().as_slice(),
  );
  assert!(res.is_ok());
  std::fs::remove_file(PathBuf::from_str(TEST_OFFLINE_PATH).unwrap()).unwrap();
}
