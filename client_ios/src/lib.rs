use std::ffi::{c_char, CStr, CString};

use client::{errors::ClientErrors, Config};

#[derive(serde::Serialize)]
struct Output {
  proof: Option<String>,
  error: Option<String>,
}

#[no_mangle]
// TODO: We should probably clarify this safety doc
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn prover(config_json: *const c_char) -> *const c_char {
  let collector = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).finish();
  tracing::subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();

  let result: Result<client::TlsProof, ClientErrors> =
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let config_str = unsafe {
        assert!(!config_json.is_null());
        CStr::from_ptr(config_json).to_str()?
      };
      let config: Config = serde_json::from_str(config_str)?;
      let rt = tokio::runtime::Runtime::new()?;
      rt.block_on(client::prover_inner(config))
    }))
    .map_err(|e| panic!("{e:?}"))
    .unwrap();
  let proof = result
    .map_err(|e| {
      let backtrace = std::backtrace::Backtrace::capture();
      panic!(
        "Error:{e:?}/n
  Stack:{backtrace:?}"
      )
    })
    .unwrap();
  CString::new(
    serde_json::to_string_pretty(&Output {
      proof: Some(serde_json::to_string_pretty(&proof).unwrap()),
      error: None,
    })
    .map_err(|e| panic!("{e:?}"))
    .unwrap(),
  )
  .map_err(|e| panic!("{e:?}"))
  .unwrap()
  .into_raw()
}
