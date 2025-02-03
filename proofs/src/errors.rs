use thiserror::Error;

// Wrapper for circom_witnesscalc::Error since it doesn't implement display
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Error)]
pub enum WitnessCalcError {
  Circom(circom_witnesscalc::Error),
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Display for WitnessCalcError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<circom_witnesscalc::Error> for ProofError {
  fn from(err: circom_witnesscalc::Error) -> ProofError {
    ProofError::WitnessCalc(WitnessCalcError::Circom(err))
  }
}

impl From<Box<bincode::ErrorKind>> for ProofError {
  fn from(err: Box<bincode::ErrorKind>) -> ProofError { ProofError::Bincode(*err) }
}

#[derive(Debug, Error)]
pub enum ProofError {
  #[error(transparent)]
  Synthesis(#[from] bellpepper_core::SynthesisError),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  Serde(#[from] serde_json::Error),

  #[error("Other error: {0}")]
  Other(String),

  #[error("Failed to verify proof")]
  VerifyFailed(),

  #[error(transparent)]
  Parse(#[from] num_bigint::ParseBigIntError),

  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  WitnessCalc(#[from] WitnessCalcError),

  #[error("Missing header section")]
  MissingSection,

  #[error(transparent)]
  Bincode(#[from] bincode::ErrorKind),

  #[error(transparent)]
  SuperNova(#[from] client_side_prover::supernova::error::SuperNovaError),

  #[error("json key not found: {0}")]
  JsonKeyError(String),

  #[error(transparent)]
  WitnessGenerator(#[from] web_proof_circuits_witness_generator::WitnessGeneratorError),

  #[error("Invalid circuit size")]
  InvalidCircuitSize,

  #[cfg(target_arch = "wasm32")]
  #[error("transparent")]
  SerdeWasmBindgen(#[from] serde_wasm_bindgen::Error),

  // TODO: Add concrete cases?
  #[error("Invalid circuit inputs")]
  InvalidCircuitInputs,

  // TODO: Add concrete cases?
  #[error("Invalid manifest")]
  InvalidManifest,
}
