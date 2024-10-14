use super::*;

const ADD_INTO_ZEROTH_GRAPH: &[u8] =
  include_bytes!("../../examples/circuit_data/addIntoZeroth.bin");
const SQUARE_ZEROTH_GRAPH: &[u8] = include_bytes!("../../examples/circuit_data/squareZeroth.bin");
const SWAP_MEMORY_GRAPH: &[u8] = include_bytes!("../../examples/circuit_data/swapMemory.bin");

fn get_setup_data() -> SetupData {
  SetupData {
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
    max_rom_length:          MAX_ROM_LENGTH,
  }
}

// TODO: This likely won't work until we adaptively resize the ROM given the `SetupData`
fn run_entry() -> (ProgramData<Online>, RecursiveSNARK<E1>) {
  let setup_data = get_setup_data();
  let public_params = program::setup(&setup_data);
  let program_data = ProgramData {
    public_params,
    setup_data,
    rom: ROM.to_vec(),
    initial_public_input: INIT_PUBLIC_INPUT.to_vec(),
    private_input: Vec::new(),
    witnesses: vec![vec![]],
  };
  let recursive_snark = program::run(&program_data);
  (program_data, recursive_snark)
}

#[test]
#[tracing_test::traced_test]
fn test_run() {
  let (_, proof) = run_entry();
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
fn test_run_serialized_verify() {
  let (public_params, recursive_snark) = run_entry();

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
  rom.resize(MAX_ROM_LENGTH, u64::MAX);
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

// TODO: Consider reworking this to at least show an offline example
// #[test]
// #[tracing_test::traced_test]
// fn test_parse_batch() {
//   let read = std::fs::read("examples/parse_batch_wc.json").unwrap();
//   let program_data: ProgramData<Offline> = serde_json::from_slice(&read).unwrap();
//   let setup_data = program::setup(circuit_list);

//   let recursive_snark = program::run(&program_data, &setup_data);

//   let final_mem = [
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(4),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//     F::<G1>::from(0),
//   ];
//   assert_eq!(&final_mem.to_vec(), recursive_snark.zi_primary());
// }
