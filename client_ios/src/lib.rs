use std::{
  collections::HashMap,
  ffi::{c_char, CStr, CString},
  path::PathBuf,
  time::Instant,
};

use client::{config::Config, errors::ClientErrors};
use tracing::debug;

// TODO: Load from server.
const PROVING_PARAM_BYTES: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/serialized_setup_1024.bytes"
);

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
    
    let mut config: Config = serde_json::from_str(config_str).unwrap();
    config.session_id();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let start = Instant::now();
    debug!("starting proving");

    let proof = rt.block_on(client::prover_inner(config, Some(PROVING_PARAM_BYTES))).unwrap();
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
