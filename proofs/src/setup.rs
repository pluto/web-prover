//! # Setup Module
//!
//! The `setup` module contains utilities and structures for setting up the proof system.
//!
//! ## Structs
//!
//! - `ProvingParams`: Represents the parameters needed for proving, including auxiliary parameters
//!   and verification key digests.
//!
//! ## Functions
//!
//! - `from_bytes`: Initializes `ProvingParams` from an efficiently serializable data format.
//! - `to_bytes`: Converts `ProvingParams` to an efficient serialization.
//!
//! ## Types
//!
//! - `AuxParams`: Represents the auxiliary parameters needed to create `PublicParams`.
//! - `ProverKey`: Represents the prover key needed to create a `CompressedSNARK`.
//! - `UninitializedSetup`: Represents the uninitialized setup data for circuits, including R1CS and
//!   witness generator types.
//! - `WitnessGeneratorType`: Represents the type of witness generator, including raw bytes and
//!   paths to Wasm binaries.

use std::io::Cursor;

use client_side_prover::{
  fast_serde::{self, FastSerde, SerdeByteError, SerdeByteTypes},
  supernova::snark::CompressedSNARK,
  traits::{Dual, Engine},
};

use crate::{
  errors::ProofError, program, program::data::R1CSType, AuxParams, ProverKey, UninitializedSetup,
  WitnessGeneratorType, E1, S1, S2,
};

/// Proving parameters
#[derive(Debug)]
pub struct ProvingParams {
  /// Auxiliary parameters
  pub aux_params:          AuxParams,
  /// Primary verification key digest
  pub vk_digest_primary:   <E1 as Engine>::Scalar,
  /// Secondary verification key digest
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
}

impl FastSerde for ProvingParams {
  /// Initialize ProvingParams from an efficiently serializable data format.
  fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SerdeByteError> {
    let mut cursor = Cursor::new(bytes);
    Self::validate_header(&mut cursor, SerdeByteTypes::ProverParams, 3)?;

    let aux_params =
      Self::read_section_bytes(&mut cursor, 1).map(|bytes| AuxParams::from_bytes(&bytes))??;

    let vk_digest_primary = Self::read_section_bytes(&mut cursor, 2)
      .and_then(|bytes| bytes.try_into().map_err(|_| SerdeByteError::G1DecodeError))
      .map(|bytes| <E1 as Engine>::Scalar::from_bytes(&bytes))?
      .into_option()
      .ok_or(SerdeByteError::G1DecodeError)?;

    let vk_digest_secondary = Self::read_section_bytes(&mut cursor, 3)
      .and_then(|bytes| bytes.try_into().map_err(|_| SerdeByteError::G2DecodeError))
      .map(|bytes| <Dual<E1> as Engine>::Scalar::from_bytes(&bytes))?
      .into_option()
      .ok_or(SerdeByteError::G1DecodeError)?;

    Ok(ProvingParams { aux_params, vk_digest_primary, vk_digest_secondary })
  }

  /// Convert ProvingParams to an efficient serialization.
  fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&fast_serde::MAGIC_NUMBER);
    out.push(SerdeByteTypes::ProverParams as u8);
    out.push(3); // num_sections

    Self::write_section_bytes(&mut out, 1, &self.aux_params.to_bytes());
    Self::write_section_bytes(&mut out, 2, &self.vk_digest_primary.to_bytes().to_vec());
    Self::write_section_bytes(&mut out, 3, &self.vk_digest_secondary.to_bytes().to_vec());

    out
  }
}

impl ProvingParams {
  /// Method used externally to initialize all the backend data needed to create a verifiable proof
  /// with [`client_side_prover`] and `proofs` crate. Intended to be used in combination with setup,
  /// which creates these values offline to be loaded at or before proof creation or verification.
  ///
  /// # Arguments
  /// - `aux_params`: the data that defines what types of supernova programs can be run, i.e.,
  ///   specified by a list of circuit R1CS and max ROM length.
  /// - `prover_key`: The key used for generating proofs, allows us to pin a specific verifier.
  pub fn new(aux_params: AuxParams, prover_key: ProverKey) -> Result<ProvingParams, ProofError> {
    Ok(ProvingParams {
      aux_params,
      vk_digest_primary: prover_key.pk_primary.vk_digest,
      vk_digest_secondary: prover_key.pk_secondary.vk_digest,
    })
  }
}

/// Create a setup for a given list of R1CS files including the necessary
/// setup for compressed proving.
///
/// # Arguments
/// - `r1cs_files`: A list of r1cs files that are accessible by the program using the setup
///
/// # Returns
/// * `Result<Vec<u8>, ProofError>` - Bytes ready to be written to disk
pub fn setup(r1cs_files: &[R1CSType], rom_length: usize) -> Vec<u8> {
  let setup_data = UninitializedSetup {
    r1cs_types:              r1cs_files.to_vec(),
    witness_generator_types: vec![WitnessGeneratorType::Browser; r1cs_files.len()],
    max_rom_length:          rom_length,
  };

  let public_params = program::setup(&setup_data);
  let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let (_, aux_params) = public_params.into_parts();

  ProvingParams {
    aux_params,
    vk_digest_primary: pk.pk_primary.vk_digest,
    vk_digest_secondary: pk.pk_secondary.vk_digest,
  }
  .to_bytes()
}
