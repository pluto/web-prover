use std::{collections::HashMap, io::Write, path::PathBuf};

use circom::CircomCircuit;
use ff::Field;
use proving_ground::{
  provider::{hyperkzg::EvaluationEngine, Bn256EngineKZG, GrumpkinEngine},
  spartan::batched::BatchedRelaxedR1CSSNARK,
  supernova::{snark::CompressedSNARK, PublicParams, TrivialCircuit},
  traits::{Engine, Group},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, trace};

pub mod circom;
pub mod program;
pub mod proof;
#[cfg(test)] mod tests;

pub type E1 = Bn256EngineKZG;
pub type E2 = GrumpkinEngine;
pub type G1 = <E1 as Engine>::GE;
pub type G2 = <E2 as Engine>::GE;
pub type EE1 = EvaluationEngine<halo2curves::bn256::Bn256, E1>;
pub type EE2 = proving_ground::provider::ipa_pc::EvaluationEngine<E2>;
pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

pub type F<G> = <G as Group>::Scalar;

trait SetupStatus {
  type PublicParams;
}
pub struct Online;
impl SetupStatus for Online {
  type PublicParams = PublicParams<E1>;
}
pub struct Offline;
impl SetupStatus for Offline {
  type PublicParams = PathBuf;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetupData {
  pub r1cs_types:              Vec<R1CSType>,
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  pub max_rom_length:          usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgramData<S: SetupStatus> {
  pub public_params:        S::PublicParams,
  pub setup_data:           SetupData,
  pub rom:                  Vec<u64>, // TODO: Put the inputs in here (use aliases)
  pub initial_public_input: Vec<u64>,
  pub private_input:        Vec<HashMap<String, Value>>,
  pub witnesses:            Vec<Vec<F<G1>>>,
}

impl ProgramData<Offline> {
  fn into_online(self) -> ProgramData<Online> {
    let file = std::fs::read(&self.public_params).unwrap();
    let public_params = bincode::deserialize(&file).unwrap();
    let ProgramData { setup_data, rom, initial_public_input, private_input, witnesses, .. } = self;
    ProgramData { public_params, setup_data, rom, initial_public_input, private_input, witnesses }
  }
}

impl ProgramData<Online> {
  fn into_offline(self, path: PathBuf) -> ProgramData<Offline> {
    let serialized = bincode::serialize(&self.public_params).unwrap();
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).unwrap();
    }
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&serialized).unwrap();

    let ProgramData { setup_data, rom, initial_public_input, private_input, witnesses, .. } = self;
    ProgramData {
      public_params: path,
      setup_data,
      rom,
      initial_public_input,
      private_input,
      witnesses,
    }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum R1CSType {
  #[serde(rename = "file")]
  File { path: PathBuf },
  #[serde(rename = "raw")]
  Raw(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WitnessGeneratorType {
  #[serde(rename = "wasm")]
  Wasm { path: String, wtns_path: String },
  #[serde(rename = "circom-witnesscalc")]
  CircomWitnesscalc { path: String },
  #[serde(rename = "browser")] // TODO: Can we merge this with Raw?
  Browser,
  #[serde(skip)]
  Raw(Vec<u8>), // TODO: Would prefer to not alloc here, but i got lifetime hell lol
  #[serde(skip)]
  RustWitness(fn(&str) -> Vec<F<G1>>),
}

#[cfg(not(target_os = "ios"))]
pub fn compute_web_proof(program_data: &ProgramData<Online>) -> Vec<u8> {
  let recursive_snark = program::run(program_data);
  // TODO: Unecessary 2x generation of pk,vk, but it is cheap. Refactor later if need be!
  let proof = program::compress_proof(&recursive_snark, &program_data.public_params);
  let serialized_proof = proof.serialize_and_compress();
  serialized_proof.0
}
#[cfg(target_os = "ios")] use std::ffi::c_char;
#[cfg(target_os = "ios")]
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn compute_web_proof(
  program_data_json: *const c_char,
  public_params_bincode: *const c_char,
  public_params_len: usize,
) -> *const c_char {
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    // Deserialize the `ProgramData` JSON
    let program_data_str = unsafe {
      assert!(!program_data_json.is_null());
      std::ffi::CStr::from_ptr(program_data_json).to_str().unwrap()
    };
    let program_data = serde_json::from_str::<ProgramData>(program_data_str).unwrap();

    // Deserialize the `PublicParams` bincode
    let public_params_bytes = unsafe {
      assert!(!public_params_bincode.is_null());
      std::slice::from_raw_parts(public_params_bincode as *const u8, public_params_len)
    };
    let public_params = bincode::deserialize::<PublicParams<E1>>(public_params_bytes).unwrap();

    (program_data, public_params)
  }));

  match result {
    Ok((program_data, public_params)) => {
      let recursive_snark = program::run(&program_data, &public_params);
      // TODO: Unecessary 2x generation of pk,vk, but it is cheap. Refactor later if need be!
      let proof = program::compress_proof(&recursive_snark, &public_params);
      let serialized_proof = proof.serialize_and_compress();
      std::ffi::CString::new(serialized_proof.0).unwrap().into_raw()
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
