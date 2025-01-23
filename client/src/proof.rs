use proofs::{
  program::{
    data::{NotExpanded, Offline, ProgramData},
    manifest::{
      EncryptionInput, NIVCRom, NivcCircuitInputs, Request as ManifestRequest,
      Response as ManifestResponse,
    },
  },
  proof::FoldingProof,
  F, G1, G2,
};
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
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
pub async fn construct_request_program_data_and_proof(
  manifest_request: &ManifestRequest,
  inputs: EncryptionInput,
  proving_params: Option<Vec<u8>>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  let setup_data = construct_setup_data();

  let NivcCircuitInputs { fold_inputs, private_inputs, initial_nivc_input } =
    manifest_request.build_inputs(&inputs);
  let NIVCRom { circuit_data, rom } = manifest_request.build_rom();

  let witnesses = vec![vec![F::<G1>::from(0)]];
  #[cfg(target_arch = "wasm32")]
  let witnesses = {
    let rom_opcodes: Vec<u64> =
      rom.iter().map(|c| circuit_data.get(c).unwrap().opcode).collect::<Vec<_>>();

    let mut wasm_private_inputs = private_inputs.clone();
    let initial_nivc_inputs = initial_nivc_input
      .iter()
      .map(|&x| proofs::witness::field_element_to_base10_string(x))
      .collect::<Vec<String>>();

    for (input, initial_input) in wasm_private_inputs.iter_mut().zip(initial_nivc_inputs.iter()) {
      input.insert("step_in".to_string(), serde_json::json!(initial_input));
    }

    // now we call the js FFI to generate the witness in wasm with snarkjs
    debug!("generating witness in wasm");
    crate::origo_wasm32::build_witness_data_from_wasm(wasm_private_inputs.clone(), rom_opcodes)
      .await?
  };

  debug!("Generating request's `ProgramData`...");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params.unwrap(),
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: vec![initial_nivc_input[0]],
    inputs: (private_inputs, fold_inputs),
    witnesses,
  }
  .into_online()?
  .into_expanded()?;

  debug!("starting request recursive proving");
  let proof = program_data.generate_proof()?;
  Ok(proof)
}

/// takes TLS transcripts and [`ProvingData`] and generates NIVC [`ProgramData`] for request and
/// response separately
/// - decrypts TLS ciphertext in [`WitnessData`]
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
pub async fn construct_response_program_data_and_proof(
  manifest_response: &ManifestResponse,
  inputs: EncryptionInput,
  proving_params: Option<Vec<u8>>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  let setup_data = construct_setup_data();

  // - construct private inputs and program layout for circuits for TLS request -
  let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
    manifest_response.build_inputs(&inputs)?;
  let NIVCRom { circuit_data, rom } = manifest_response.build_rom(inputs.plaintext.len());

  let witnesses = vec![vec![F::<G1>::from(0)]];
  #[cfg(target_arch = "wasm32")]
  let witnesses = {
    let rom_opcodes = rom.iter().map(|c| circuit_data.get(c).unwrap().opcode).collect::<Vec<_>>();

    // TODO (tracy): Today we are carrying witness data on the proving object,
    // it's not obviously the right place for it. This code path needs a larger
    // refactor.
    let mut wasm_private_inputs = private_inputs.clone();
    let initial_nivc_inputs = initial_nivc_input
      .iter()
      .map(|&x| proofs::witness::field_element_to_base10_string(x))
      .collect::<Vec<String>>();

    for (input, initial_input) in wasm_private_inputs.iter_mut().zip(initial_nivc_inputs.iter()) {
      input.insert("step_in".to_string(), serde_json::json!(initial_input));
    }

    // now we call the js FFI to generate the witness in wasm with snarkjs
    debug!("generating witness in wasm");

    // now we pass witness input type to generate program data
    crate::origo_wasm32::build_witness_data_from_wasm(wasm_private_inputs, rom_opcodes).await?
  };

  debug!("initializing public params");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params.unwrap(),
    vk_digest_primary: proofs::F::<G1>::from(0),
    vk_digest_secondary: proofs::F::<G2>::from(0),
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: vec![initial_nivc_input[0]],
    inputs: (private_inputs, fold_inputs),
    witnesses,
  }
  .into_online()?
  .into_expanded()?;

  debug!("starting response recursive proving");
  let proof = program_data.generate_proof()?;
  Ok(proof)
}
