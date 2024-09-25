use std::ffi::{c_char, CStr, CString};

use client::{config::Config, errors::ClientErrors};
use proofs::{compress::CompressedVerifier, program, ProgramData};

#[derive(serde::Serialize)]
struct Output {
  proof: Option<String>,
  error: Option<String>,
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn setup_tracing() {
  let collector =
    tracing_subscriber::fmt().with_ansi(false).with_max_level(tracing::Level::TRACE).finish();
  tracing::subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();
}

#[no_mangle]
// TODO: We should probably clarify this safety doc
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn prover(config_json: *const c_char) -> *const c_char {
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let config_str = unsafe {
      assert!(!config_json.is_null());
      CStr::from_ptr(config_json).to_str().unwrap()
    };
    let config: Config = serde_json::from_str(config_str).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let proof = rt.block_on(client::prover_inner(config)).unwrap();
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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn run_program_ios(program_data_json: *const c_char) -> *const c_char {
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
