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
  pub r1cs_types:              Vec<R1CSType>,
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  pub rom:                     Vec<u64>,
  pub initial_public_input:    Vec<u64>,
  // TODO: We should probably just make this a vec here
  pub private_input:           Vec<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum R1CSType {
  #[serde(rename = "file")]
  File { path: PathBuf },
  #[serde(skip)]
  Raw(Vec<u8>),
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
pub fn get_compressed_proof(program_data: ProgramData) -> Vec<u8> {
  let program_output = program::run(&program_data);
  let compressed_verifier = CompressedVerifier::from(program_output);
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();
  serialized_compressed_verifier.proof.0
}
#[cfg(target_os = "ios")] use std::ffi::c_char;
#[cfg(target_os = "ios")]
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn get_compressed_proof(program_data_json: *const c_char) -> *const c_char {
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let program_data_str = unsafe {
      assert!(!program_data_json.is_null());
      std::ffi::CStr::from_ptr(program_data_json).to_str().unwrap()
    };
    serde_json::from_str::<ProgramData>(program_data_str).unwrap()
  }));

  match result {
    Ok(program_data) => {
      let program_output = program::run(&program_data);
      let compressed_verifier = CompressedVerifier::from(program_output);
      let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();
      std::ffi::CString::new(serialized_compressed_verifier.proof.0).unwrap().into_raw()
    },
    Err(err) => {
      let backtrace = std::backtrace::Backtrace::capture();

      let out = if let Some(e) = err.downcast_ref::<&str>() {
        format!("Captured Panic\nError: {}\n\nStack:\n{}", e, backtrace)
      } else {
        format!("Captured Panic\n{:#?}\n\nStack:\n{}", err, backtrace)
      };

      let out_json = serde_json::to_string_pretty(&out).unwrap(); // should never panic
      std::ffi::CString::new(out_json).unwrap().into_raw() // should never panic
    },
  }
}
