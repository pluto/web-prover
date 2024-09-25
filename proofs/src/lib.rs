#![feature(internal_output_capture)]

pub mod circom;
pub mod compress;
pub mod program;
pub mod tests;
use std::{collections::HashMap, path::PathBuf};

use arecibo::{
  provider::{hyperkzg::EvaluationEngine, Bn256EngineKZG, GrumpkinEngine},
  spartan::batched::BatchedRelaxedR1CSSNARK,
  traits::{circuit::TrivialCircuit, Engine, Group},
};
use circom::CircomCircuit;
use compress::CompressedVerifier;
use ff::Field;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, trace};

use crate::tests::{
  ADD_INTO_ZEROTH_GRAPH, ADD_INTO_ZEROTH_R1CS, INIT_PUBLIC_INPUT, ROM, SQUARE_ZEROTH_GRAPH,
  SQUARE_ZEROTH_R1CS, SWAP_MEMORY_GRAPH, SWAP_MEMORY_R1CS,
};

pub type E1 = Bn256EngineKZG;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
pub type EE1 = EvaluationEngine<halo2curves::bn256::Bn256, E1>;
pub type EE2 = arecibo::provider::ipa_pc::EvaluationEngine<E2>;
pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

pub type F<G> = <G as Group>::Scalar;

pub type C1 = CircomCircuit;
pub type C2 = TrivialCircuit<F<G2>>;

const TEST_JSON: &str = include_str!("../examples/aes_fold.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProgramData {
  pub r1cs_paths:              Vec<PathBuf>,
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  pub rom:                     Vec<u64>,
  pub initial_public_input:    Vec<u64>,
  pub private_input:           HashMap<String, Value>, /* TODO: We should probably just make
                                                        * this a vec here */
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WitnessGeneratorType {
  #[serde(rename = "wasm")]
  Wasm { path: String, wtns_path: String },
  #[serde(rename = "circom-witnesscalc")]
  CircomWitnesscalc { path: String },
  #[serde(skip)]
  Raw(Vec<u8>), // TODO: Would prefer to not alloc here, but i got lifetime hell lol
}

#[cfg(not(target_os = "ios"))]
pub fn run_program(program_data: ProgramData) -> Vec<u8> {
  let program_output = program::run(&program_data);
  let compressed_verifier = CompressedVerifier::from(program_output);
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();
  serialized_compressed_verifier.proof.0
}

// #[no_mangle]
// #[allow(clippy::missing_safety_doc)]
// pub unsafe extern "C" fn setup_tracing() {
//   let collector =
//     tracing_subscriber::fmt().with_ansi(false).with_max_level(tracing::Level::TRACE).finish();
//   tracing::subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();
// }

// use std::ffi::c_char;

// #[no_mangle]
// #[allow(clippy::missing_safety_doc)]
// pub unsafe extern "C" fn run_program_ios(program_data_json: *const c_char) -> *const c_char {
//   let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
//     let program_data_str = unsafe {
//       assert!(!program_data_json.is_null());
//       std::ffi::CStr::from_ptr(program_data_json).to_str().unwrap()
//     };
//     serde_json::from_str::<ProgramData>(program_data_str).unwrap()
//   }));

//   match result {
//     Ok(program_data) => {
//       let program_output = program::run(&program_data);
//       let compressed_verifier = CompressedVerifier::from(program_output);
//       let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();
//       std::ffi::CString::new(serialized_compressed_verifier.proof.0).unwrap().into_raw()
//     },
//     Err(err) => {
//       let backtrace = std::backtrace::Backtrace::capture();

//       let out = if let Some(e) = err.downcast_ref::<&str>() {
//         format!("Captured Panic\nError: {}\n\nStack:\n{}", e, backtrace)
//       } else {
//         format!("Captured Panic\n{:#?}\n\nStack:\n{}", err, backtrace)
//       };

//       let out_json = serde_json::to_string_pretty(&out).unwrap(); // should never panic
//       std::ffi::CString::new(out_json).unwrap().into_raw() // should never panic
//     },
//   }
// }

// // #[cfg(target_os = "ios")]
// #[no_mangle]
// #[allow(clippy::missing_safety_doc)]
// pub unsafe extern "C" fn run_program_ios_void() -> *const c_char {
//   let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
//     // let program_data_str = unsafe {
//     //   assert!(!program_data_json.is_null());
//     //   std::ffi::CStr::from_ptr(program_data_json).to_str().unwrap()
//     // };
//     serde_json::from_str::<ProgramData>(TEST_JSON).unwrap()
//   }));

//   match result {
//     Ok(program_data) => {
//       let program_output = program::run(&program_data);
//       let compressed_verifier = CompressedVerifier::from(program_output);
//       let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();
//       std::ffi::CString::new(serialized_compressed_verifier.proof.0).unwrap().into_raw()
//     },
//     Err(err) => {
//       let backtrace = std::backtrace::Backtrace::capture();

//       let out = if let Some(e) = err.downcast_ref::<&str>() {
//         format!("Captured Panic\nError: {}\n\nStack:\n{}", e, backtrace)
//       } else {
//         format!("Captured Panic\n{:#?}\n\nStack:\n{}", err, backtrace)
//       };

//       let out_json = serde_json::to_string_pretty(&out).unwrap(); // should never panic
//       std::ffi::CString::new(out_json).unwrap().into_raw() // should never panic
//     },
//   }
// }

// #[no_mangle]
// #[allow(clippy::missing_safety_doc)]
// pub unsafe extern "C" fn run_program_ios_void_void() {
//   // let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
//   //   let program_data_str = unsafe {
//   //     // assert!(!TEST_JSON.is_null());
//   //     // std::ffi::CStr::from_ptr(TEST_JSON).to_str().unwrap()
//   //     println!("test");
//   //   };
//   //   let program_data = serde_json::from_str::<ProgramData>(TEST_JSON).unwrap();
//   // }));

//   let program_data = ProgramData {
//     r1cs_paths:              vec![
//       PathBuf::from(ADD_INTO_ZEROTH_R1CS),
//       PathBuf::from(SQUARE_ZEROTH_R1CS),
//       PathBuf::from(SWAP_MEMORY_R1CS),
//     ],
//     witness_generator_types: vec![
//       WitnessGeneratorType::Raw(ADD_INTO_ZEROTH_GRAPH.to_vec()),
//       WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
//       WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
//     ],
//     rom:                     ROM.to_vec(),
//     initial_public_input:    INIT_PUBLIC_INPUT.to_vec(),
//     private_input:           HashMap::new(),
//   };
//   let program_output = program::run(&program_data);
//   // Get the CompressedSNARK
//   let compressed_verifier = CompressedVerifier::from(program_output);

//   // Serialize and compress further
//   let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();

//   // Decompress and deserialize
//   let compressed_verifier = serialized_compressed_verifier.decompress_and_serialize();

//   // Extend the initial state input with the ROM (happens internally inside of `program::run`, so
// we   // do it out here)
//   let mut z0_primary = INIT_PUBLIC_INPUT.to_vec();
//   z0_primary.push(0);
//   z0_primary.extend(ROM.iter());

//   // Check that it verifies
//   let res = compressed_verifier.proof.verify(
//     &compressed_verifier.public_params,
//     &compressed_verifier.verifier_key,
//     z0_primary.into_iter().map(F::<G1>::from).collect::<Vec<_>>().as_slice(),
//     [0].into_iter().map(F::<G2>::from).collect::<Vec<_>>().as_slice(),
//   );
//   assert!(res.is_ok());
//   // program::run(&program_data);
//   //   match result {
//   //     Ok(program_data) => {
//   //       let program_output = program::run(&program_data);
//   //       let compressed_verifier = CompressedVerifier::from(program_output);
//   //       let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();
//   //       // std::ffi::CString::new(serialized_compressed_verifier.proof.0).unwrap().into_raw()
//   //     },
//   //     Err(err) => {
//   //       let backtrace = std::backtrace::Backtrace::capture();

//   //       let out = if let Some(e) = err.downcast_ref::<&str>() {
//   //         format!("Captured Panic\nError: {}\n\nStack:\n{}", e, backtrace)
//   //       } else {
//   //         format!("Captured Panic\n{:#?}\n\nStack:\n{}", err, backtrace)
//   //       };

//   //       let out_json = serde_json::to_string_pretty(&out).unwrap(); // should never panic
//   //                                                                   //
//   // std::ffi::CString::new(out_json).unwrap().into_raw() // should never panic     },
//   //   }
// }
