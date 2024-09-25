use std::{
  collections::HashMap,
  ffi::{c_char, CStr, CString},
  path::PathBuf,
};

use client::{config::Config, errors::ClientErrors};
use proofs::{
  compress::CompressedVerifier,
  program,
  tests::{
    ADD_INTO_ZEROTH_GRAPH, ADD_INTO_ZEROTH_R1CS, INIT_PUBLIC_INPUT, ROM, SQUARE_ZEROTH_GRAPH,
    SQUARE_ZEROTH_R1CS, SWAP_MEMORY_GRAPH, SWAP_MEMORY_R1CS,
  },
  ProgramData, R1CSType, WitnessGeneratorType, F, G1, G2,
};

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
pub unsafe extern "C" fn run_program_ios_void_void() {
  let program_data = ProgramData {
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
    rom:                     ROM.to_vec(),
    initial_public_input:    INIT_PUBLIC_INPUT.to_vec(),
    private_input:           HashMap::new(),
  };
  let program_output = program::run(&program_data);
  // Get the CompressedSNARK
  let compressed_verifier = CompressedVerifier::from(program_output);

  // Serialize and compress further
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();

  // Decompress and deserialize
  let compressed_verifier = serialized_compressed_verifier.decompress_and_serialize();

  // Extend the initial state input with the ROM (happens internally inside of `program::run`, so we
  // do it out here)
  let mut z0_primary = INIT_PUBLIC_INPUT.to_vec();
  z0_primary.push(0);
  z0_primary.extend(ROM.iter());

  // Check that it verifies
  let res = compressed_verifier.proof.verify(
    &compressed_verifier.public_params,
    &compressed_verifier.verifier_key,
    z0_primary.into_iter().map(F::<G1>::from).collect::<Vec<_>>().as_slice(),
    [0].into_iter().map(F::<G2>::from).collect::<Vec<_>>().as_slice(),
  );
  assert!(res.is_ok());
}
