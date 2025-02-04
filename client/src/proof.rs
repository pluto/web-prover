use std::sync::Arc;

use client_side_prover::supernova::PublicParams;
use proofs::{
  program::{
    data::{InitializedSetup, NotExpanded, Online, ProgramData, Witnesses},
    manifest::{EncryptionInput, Manifest, NIVCRom, NivcCircuitInputs},
  },
  E1, F, G1, G2,
};
use tracing::debug;

use crate::{ClientErrors, OrigoProof};

/// creates NIVC proof from TLS transcript and [`Manifest`] config
///
/// # Arguments
/// - `manifest` - [`Manifest`] config containing proof and circuit information
/// - `request_inputs` - TLS transcript request inputs
/// - `response_inputs` - TLS transcript response inputs
/// - `vks` - verification keys
/// - `proving_params` - proving parameters
/// - `setup_data` - [`InitializedSetup`] containing circuit R1CS and witness generator files
///
/// # Returns
/// - `CompressedSNARKProof` - NIVC proof
///
/// # Details
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`UninitializedSetup`] containing circuit R1CS and witness generator files
///   according to input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
pub async fn construct_program_data_and_proof(
  manifest: Manifest,
  request_inputs: EncryptionInput,
  response_inputs: EncryptionInput,
  vks: (F<G1>, F<G2>),
  proving_params: Arc<PublicParams<E1>>,
  setup_data: Arc<InitializedSetup>,
  witnesses: &Witnesses,
) -> Result<OrigoProof, ClientErrors> {
  let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
    manifest.build_inputs(&request_inputs, &response_inputs)?;

  let NIVCRom { circuit_data, rom } = manifest.build_rom(&request_inputs, &response_inputs);

  debug!("Generating `ProgramData`...");
  let program_data = ProgramData::<Online, NotExpanded> {
    public_params: proving_params,
    vk_digest_primary: vks.0,
    vk_digest_secondary: vks.1,
    setup_data,
    rom: rom.clone(),
    rom_data: circuit_data.clone(),
    initial_nivc_input: initial_nivc_input.to_vec(),
    inputs: (private_inputs, fold_inputs),
  }
  .into_expanded()?;

  debug!("starting recursive proving");
  let proof = program_data.generate_proof(&witnesses).await?;
  Ok(OrigoProof { proof, rom: NIVCRom { circuit_data, rom } })
}
