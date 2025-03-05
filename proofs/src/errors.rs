//! Error type for the `proofs` crate.
//!
//! This enum represents the various error conditions that can occur within the `proofs` crate.
//! It provides a unified way to handle and propagate errors throughout the crate.
//!
//! The possible error variants include:
//!
//! - `Synthesis`: Represents an error that occurred during the synthesis process.
//! - `Io`: Represents an I/O error.
//! - `Serde`: Represents a serialization or deserialization error.
//! - `Other`: Represents any other error with a custom error message.
//! - `VerifyFailed`: Indicates that the proof verification failed.
//! - `Parse`: Represents an error that occurred while parsing a big integer.
//! - `WitnessCalc`: Represents an error that occurred during witness calculation (only available
//!   when not targeting `wasm32`).
//! - `MissingSection`: Indicates that a required section is missing.
//! - `Bincode`: Represents a Bincode serialization or deserialization error.
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Error)]
/// Wrapper for circom_witnesscalc::Error since it doesn't implement display
pub enum WitnessCalcError {
  /// The error is a circom_witnesscalc::Error
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

/// Represents the various error conditions that can occur within the `proofs` crate.
#[derive(Debug, Error)]
pub enum ProofError {
  /// The error is a bellpepper_core::SynthesisError
  #[error(transparent)]
  Synthesis(#[from] bellpepper_core::SynthesisError),

  /// The error is a std::io::Error
  #[error(transparent)]
  Io(#[from] std::io::Error),

  /// The error is a serde_json::Error
  #[error(transparent)]
  Serde(#[from] serde_json::Error),

  /// The error is a custom error with a message
  #[error("Other error: {0}")]
  Other(String),

  /// The error is a failed proof verification
  #[error("Failed to verify proof: {0}")]
  VerifyFailed(String),

  /// The error is a num_bigint::ParseBigIntError
  #[error(transparent)]
  Parse(#[from] num_bigint::ParseBigIntError),

  /// The error is a WitnessCalcError
  #[cfg(not(target_arch = "wasm32"))]
  #[error(transparent)]
  WitnessCalc(#[from] WitnessCalcError),

  /// The error is a missing header section
  #[error("Missing header section")]
  MissingSection,

  /// The error is a bincode::ErrorKind
  #[error(transparent)]
  Bincode(#[from] bincode::ErrorKind),

  /// The error is a client_side_prover::supernova::error::SuperNovaError
  #[error(transparent)]
  SuperNova(#[from] client_side_prover::supernova::error::SuperNovaError),

  /// The error is a json key error
  #[error("json key not found: {0}")]
  JsonKeyError(String),

  /// The error is a web_proof_circuits_witness_generator::WitnessGeneratorError
  #[error(transparent)]
  WitnessGenerator(#[from] web_proof_circuits_witness_generator::WitnessGeneratorError),

  /// The error is an invalid circuit size
  #[error("Invalid circuit size")]
  InvalidCircuitSize,

  /// The error is a serde_wasm_bindgen::Error
  #[cfg(target_arch = "wasm32")]
  #[error(transparent)]
  SerdeWasmBindgen(#[from] serde_wasm_bindgen::Error),

  /// The error is a ManifestError
  #[error(transparent)]
  Manifest(#[from] web_prover_core::errors::ManifestError),
}
