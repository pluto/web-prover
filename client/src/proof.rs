use proofs::{
  program::{
    data::{InitializedSetup, NotExpanded, Offline, Online, ProgramData},
    manifest::{
      EncryptionInput, NIVCRom, NivcCircuitInputs, Request as ManifestRequest,
      Response as ManifestResponse,
    },
  },
  proof::FoldingProof,
  F, G1, G2,
};
use client_side_prover::supernova::PublicParams;
use proofs::E1;
use std::sync::Arc;

use tracing::debug;

use crate::{circuits::*, ClientErrors};

/// creates NIVC proof from TLS transcript and [`Manifest`] config
///
/// # Arguments
/// - `manifest` - [`Manifest`] config containing proof and circuit information
/// - `inputs` - TLS transcript inputs
///
/// # Returns
/// - `CompressedSNARKProof` - NIVC proof
///
/// # Details
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`UninitializedSetup`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
pub fn construct_request_program_data_and_proof(
  manifest_request: ManifestRequest,
  inputs: EncryptionInput,
  vks: (F<G1>, F<G2>),
  proving_params: Arc<PublicParams<E1>>,
  setup_data: Arc<InitializedSetup>,
  witnesses: Vec<Vec<F<G1>>>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  let NivcCircuitInputs { fold_inputs, private_inputs, initial_nivc_input } =
    manifest_request.build_inputs(&inputs);
  let NIVCRom { circuit_data, rom } = manifest_request.build_rom();

  debug!("Generating request's `ProgramData`...");
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params: proving_params,
    vk_digest_primary: vks.0,
    vk_digest_secondary: vks.1,
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: vec![initial_nivc_input[0]],
    inputs: (private_inputs, fold_inputs),
    witnesses,
  }
  .into_expanded()?;

  debug!("starting request recursive proving");
  let proof = program_data.generate_proof()?;
  Ok(proof)
}

/// takes TLS transcripts and [`ProvingData`] and generates NIVC [`ProgramData`] for request and
/// response separately
/// - decrypts TLS ciphertext in [`WitnessData`]
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`UninitializedSetup`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
pub fn construct_response_program_data_and_proof(
  manifest_response: ManifestResponse,
  inputs: EncryptionInput,
  vks: (F<G1>, F<G2>),
  proving_params: Arc<PublicParams<E1>>,
  setup_data: Arc<InitializedSetup>,
  witnesses: Vec<Vec<F<G1>>>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
    manifest_response.build_inputs(&inputs)?;
  let NIVCRom { circuit_data, rom } = manifest_response.build_rom(inputs.plaintext.len());

  debug!("Generating response's `ProgramData`...");
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params: proving_params,
    vk_digest_primary: vks.0,
    vk_digest_secondary: vks.1,
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: vec![initial_nivc_input[0]],
    inputs: (private_inputs, fold_inputs),
    witnesses,
  }
  .into_expanded()?;

  debug!("starting response recursive proving");
  let proof = program_data.generate_proof()?;
  Ok(proof)
}
