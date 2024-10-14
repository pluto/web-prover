// use super::*;

// rust_witness::witness!(add_external);
// fn add_external_witness_remapped(input_json: &str) -> Vec<F<G1>> {
//   add_external_witness(remap_inputs(input_json))
//     .into_iter()
//     .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
//     .collect()
// }

// rust_witness::witness!(square_zeroth);
// fn square_zeroth_witness_remapped(input_json: &str) -> Vec<F<G1>> {
//   square_zeroth_witness(remap_inputs(input_json))
//     .into_iter()
//     .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
//     .collect()
// }

// rust_witness::witness!(swap_memory);
// fn swap_memory_witness_remapped(input_json: &str) -> Vec<F<G1>> {
//   swap_memory_witness(remap_inputs(input_json))
//     .into_iter()
//     .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
//     .collect()
// }

// fn get_setup_data() -> SetupData {
//   SetupData {
//     r1cs_types:              vec![
//       R1CSType::Raw(ADD_EXTERNAL_R1CS.to_vec()),
//       R1CSType::Raw(SQUARE_ZEROTH_R1CS.to_vec()),
//       R1CSType::Raw(SWAP_MEMORY_R1CS.to_vec()),
//     ],
//     witness_generator_types: vec![
//       WitnessGeneratorType::RustWitness(add_external_witness_remapped),
//       WitnessGeneratorType::RustWitness(square_zeroth_witness_remapped),
//       WitnessGeneratorType::RustWitness(swap_memory_witness_remapped),
//     ],
//     max_rom_length:          MAX_ROM_LENGTH,
//   }
// }

// fn run_entry() -> (ProgramData<Online>, RecursiveSNARK<E1>) {
//   let setup_data = get_setup_data();
//   let public_params = program::setup(&setup_data);
//   let program_data = ProgramData {
//     public_params,
//     setup_data,
//     rom: ROM.to_vec(),
//     initial_public_input: INIT_PUBLIC_INPUT.to_vec(),
//     private_input: vec![HashMap::new(), HashMap::new(), HashMap::new()],
//     witnesses: vec![vec![]],
//   };
//   let recursive_snark = program::run(&program_data);
//   (program_data, recursive_snark)
// }

// #[test]
// #[tracing_test::traced_test]
// fn test_run_rwit() {
//   let (_, proof) = run_entry();
//   let final_mem = [
//     F::<G1>::from(0),
//     F::<G1>::from(81),
//     F::<G1>::from(6),
//     F::<G1>::from(0),
//     F::<G1>::from(1),
//     F::<G1>::from(2),
//     F::<G1>::from(0),
//     F::<G1>::from(1),
//     F::<G1>::from(2),
//   ];
//   assert_eq!(&final_mem.to_vec(), proof.zi_primary());
// }

// // rust_witness::witness!(aesgcmfold);
// // fn aes_gcm_fold_witness(input_json: &str) -> Vec<F<G1>> {
// //   aesgcmfold_witness(remap_inputs(input_json))
// //     .into_iter()
// //     .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
// //     .collect()
// // }

// // TODO: This needs reworked and is an expensive test anyway. Maybe just replace with an e2e

// // #[test]
// // #[tracing_test::traced_test]
// // fn test_aes_gcm_fold_rwit() {
// //   let read = std::fs::read("examples/aes_fold.json").unwrap();
// //   let mut program_data: ProgramData = serde_json::from_slice(&read).unwrap();
// //   program_data.witness_generator_types =
// //     vec![WitnessGeneratorType::RustWitness(aes_gcm_fold_witness)];
// //   let circuit_list = program::initialize_circuit_list(&program_data);
// //   let setup_data = program::setup(circuit_list);

// //   program::run(&program_data, &setup_data);
// // }

// // TODO: This is also an offlined example that can be replaced with the use of the default 3
// // circuits

// // rust_witness::witness!(parsefoldbatch);
// // fn parse_batch_witness(input_json: &str) -> Vec<F<G1>> {
// //   parsefoldbatch_witness(remap_inputs(input_json))
// //     .into_iter()
// //     .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
// //     .collect()
// // }

// // #[test]
// // #[tracing_test::traced_test]
// // fn test_parse_batch_rwit() {
// //   let read = std::fs::read("examples/parse_batch_rwit.json").unwrap();
// //   let mut program_data: ProgramData = serde_json::from_slice(&read).unwrap();
// //   program_data.witness_generator_types =
// //     vec![WitnessGeneratorType::RustWitness(parse_batch_witness)];
// //   let circuit_list = program::initialize_circuit_list(&program_data);
// //   let setup_data = program::setup(circuit_list);

// //   program::run(&program_data, &setup_data);
// // }
