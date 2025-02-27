use std::sync::Arc;

use client_side_prover::supernova::PublicParams;
use proofs::{
  E1, F, G1, G2,
  program::{
    data::{InitializedSetup, InstanceParams, NotExpanded, Online, ProofParams, SetupParams},
    manifest::{EncryptionInput, NIVCRom, NivcCircuitInputs, OrigoManifest},
  },
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
/// - create consolidate [`InstanceParams`]
/// - expand private inputs into fold inputs as per circuits
pub async fn construct_program_data_and_proof<const CIRCUIT_SIZE: usize>(
  manifest: &OrigoManifest,
  request_inputs: &EncryptionInput,
  response_inputs: &EncryptionInput,
  vks: (F<G1>, F<G2>),
  proving_params: Arc<PublicParams<E1>>,
  setup_data: Arc<InitializedSetup>,
) -> Result<OrigoProof, ClientErrors> {
  let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
    manifest.build_inputs::<CIRCUIT_SIZE>(request_inputs, response_inputs)?;

  let NIVCRom { circuit_data, rom } =
    manifest.build_rom::<CIRCUIT_SIZE>(request_inputs, response_inputs);

  debug!("Generating response's parameters...");
  let setup_params = SetupParams::<Online> {
    public_params: proving_params,
    vk_digest_primary: vks.0,
    vk_digest_secondary: vks.1,
    setup_data,
    rom_data: circuit_data.clone(),
  };
  let proof_params = ProofParams { rom: rom.clone() };
  let instance_params = InstanceParams::<NotExpanded> {
    nivc_input:     initial_nivc_input.to_vec(),
    private_inputs: (private_inputs, fold_inputs),
  }
  .into_expanded(&proof_params)?;

  debug!("starting recursive proving");
  let proof = setup_params.generate_proof(&proof_params, &instance_params).await?;
  Ok(OrigoProof {
    proof,
    rom: NIVCRom { circuit_data, rom },
    ciphertext_digest: initial_nivc_input[0].to_bytes(),
    sign_reply: None,
    value: None,
  })
}
