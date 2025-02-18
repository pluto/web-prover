use std::{
  ffi::{c_char, CStr, CString},
  time::Instant,
};

use client::config::Config;
use proofs::{
  circuits::{construct_setup_data_from_fs, load_proving_params_512},
  program::data::UninitializedSetup,
};
use tracing::debug;

#[derive(serde::Serialize)]
struct Output {
  proof: Option<String>,
  error: Option<String>,
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn get_web_prover_circuits_version() -> *const c_char {
  CString::new(client::get_web_prover_circuits_version()).unwrap().into_raw()
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn setup_tracing() {
  let collector =
    tracing_subscriber::fmt().with_ansi(false).with_max_level(tracing::Level::TRACE).finish();
  tracing::subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();
}

#[repr(C)]
pub struct UninitializedSetupFFI {
  r1cs_types:              *const *const u8,
  r1cs_lengths:            *const usize,
  r1cs_count:              usize,
  witness_generator_types: *const *const u8,
  witness_lengths:         *const usize,
  witness_count:           usize,
}

impl UninitializedSetupFFI {
  pub unsafe fn to_canonical(&self) -> UninitializedSetup {
    // Deserialize `r1cs_types`
    let r1cs_types = (0..self.r1cs_count)
      .map(|i| {
        let len = *self.r1cs_lengths.add(i);
        let ptr = *self.r1cs_types.add(i);
        std::slice::from_raw_parts(ptr, len).to_vec()
      })
      .collect::<Vec<Vec<u8>>>();

    // Deserialize `witness_generator_types`
    let witness_generator_types = (0..self.witness_count)
      .map(|i| {
        let len = *self.witness_lengths.add(i);
        let ptr = *self.witness_generator_types.add(i);
        std::slice::from_raw_parts(ptr, len).to_vec()
      })
      .collect::<Vec<Vec<u8>>>();

    UninitializedSetup::from_raw_parts(r1cs_types, witness_generator_types)
  }
}

#[no_mangle]
// TODO: We should probably clarify this safety doc
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn prover(
  config_json: *const c_char,
  // TODO: `setup_data` parameter handling is untested
  setup_data: *const UninitializedSetupFFI,
) -> *const c_char {
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let config_str = unsafe {
      assert!(!config_json.is_null());
      CStr::from_ptr(config_json).to_str().unwrap()
    };

    let mut config: Config = serde_json::from_str(config_str).unwrap();
    config.set_session_id();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let start = Instant::now();
    debug!("starting proving");

    // TODO: Remove this after updating Swift client code
    let setup_data = if setup_data.is_null() {
      construct_setup_data_from_fs::<512>().unwrap()
    } else {
      let setup_data = unsafe { &*setup_data };
      setup_data.to_canonical()
    };

    let proof = rt
      .block_on(client::prover_inner(
        config,
        // TODO: Do I pass these here from `prover` call args or just make Some(...) in-place?
        Some(load_proving_params_512().unwrap()),
        Some(setup_data),
      ))
      .unwrap();
    debug!("done proving: {:?}", Instant::now() - start);
    serde_json::to_string_pretty(&proof).unwrap()
  }));

  // code should not panic after this line ...

  match result {
    Ok(proof) => {
      let out = Output { proof: Some(proof), error: None };
      let out_json = serde_json::to_string_pretty(&out).unwrap(); // should never panic
      CString::new(out_json).unwrap().into_raw() // should never panic
    },
    Err(err) => {
      let backtrace = std::backtrace::Backtrace::capture();
      let out = Output {
        proof: None,
        error: if let Some(e) = err.downcast_ref::<&str>() {
          Some(format!("Captured Panic\nError: {}\n\nStack:\n{}", e, backtrace))
        } else {
          Some(format!("Captured Panic\n{:#?}\n\nStack:\n{}", err, backtrace))
        },
      };
      let out_json = serde_json::to_string_pretty(&out).unwrap(); // should never panic
      CString::new(out_json).unwrap().into_raw() // should never panic
    },
  }
}
