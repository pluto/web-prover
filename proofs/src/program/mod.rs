//! # Program Module
//!
//! The `program` module contains the core logic for setting up and running the proof system.
//! It provides functionality for initializing the setup, generating proofs, and verifying proofs.
//!
//! ## Submodules
//!
//! - `data`: Contains data structures and types used in the proof system.
//! - `http`: Provides utilities for handling HTTP-related operations in the proof system.
//! - `manifest`: Contains the manifest structure and related utilities.
//! - `utils`: Provides utility functions used throughout the module.

use std::sync::Arc;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::{r1cs::R1CS, witness::generate_witness_from_generator_type};
use client_side_prover::{
  supernova::{NonUniformCircuit, RecursiveSNARK, StepCircuit},
  traits::{snark::default_ck_hint, Dual},
};
use data::{Expanded, InitializedSetup};
use proof::FoldingProof;
#[cfg(feature = "timing")] use tracing::trace;
use utils::into_input_json;

use super::*;
use crate::{
  circom::witness::generate_witness_from_browser_type,
  program::{
    data::{ProofParams, SetupParams},
    utils::into_circom_input,
  },
};

pub mod data;
pub mod http;
pub mod manifest;
pub mod utils;

// TODO: Consider moving contents of mod.rs files to a separate files. mod.rs files should
//  only be used to adjust the visibility of exported items.

/// Compressed proof type
pub type CompressedProof = FoldingProof<CompressedSNARK<E1, S1, S2>, F<G1>>;

/// Represents the memory used in the proof system.
///
/// This struct contains the circuits and ROM data required for the proof system.
pub struct Memory {
  /// A vector of ROM circuits used in the proof system.
  pub circuits: Vec<RomCircuit>,
  /// A vector of ROM data, represented as 64-bit unsigned integers.
  pub rom:      Vec<u64>,
}

/// Represents a ROM circuit used in the proof system.
///
/// This struct encapsulates the necessary components and metadata for a ROM circuit,
/// including the circuit itself, its index, size, and various inputs.
#[derive(Clone)]
pub struct RomCircuit {
  /// The Circom circuit associated with this ROM circuit.
  pub circuit:                CircomCircuit,
  /// The index of this circuit within the ROM.
  pub circuit_index:          usize,
  /// The size of the ROM.
  pub rom_size:               usize,
  /// Optional NIVC I/O values for the circuit.
  pub nivc_io:                Option<Vec<F<G1>>>,
  /// Optional private inputs for the circuit, mapped by their labels.
  pub private_input:          Option<HashMap<String, Value>>,
  /// The type of witness generator used for this circuit.
  pub witness_generator_type: WitnessGeneratorType,
}

// NOTE (Colin): This is added so we can cache only the active circuits we are using.
impl Default for RomCircuit {
  fn default() -> Self {
    Self {
      circuit:                CircomCircuit::default(),
      circuit_index:          usize::MAX - 1,
      rom_size:               0,
      nivc_io:                None,
      private_input:          None,
      witness_generator_type: WitnessGeneratorType::Raw(vec![]),
    }
  }
}

impl NonUniformCircuit<E1> for Memory {
  type C1 = RomCircuit;
  type C2 = TrivialCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { self.circuits.len() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  fn secondary_circuit(&self) -> Self::C2 { Default::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl StepCircuit<F<G1>> for RomCircuit {
  fn arity(&self) -> usize { self.circuit.arity() + 1 + self.rom_size }

  fn circuit_index(&self) -> usize { self.circuit_index }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    let rom_index = &z[self.circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[self.circuit.arity() + 1..]; // jump to where we pushed rom data into C
    let (rom_index_next, pc_next) = utils::next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;
    let mut circuit_constraints = self.circuit.vanilla_synthesize(cs, z)?;
    circuit_constraints.push(rom_index_next);
    circuit_constraints.extend(z[self.circuit.arity() + 1..].iter().cloned());
    Ok((Some(pc_next), circuit_constraints))
  }
}

// TODO: This is like a one-time use setup that overlaps some with `ProgramData::into_online()`.
// Worth checking out how to make this simpler, clearer, more efficient.
/// Setup function
pub fn setup(setup_data: &UninitializedSetup) -> PublicParams<E1> {
  // Optionally time the setup stage for the program
  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();

  // TODO: I don't think we want to have to call `initialize_circuit_list` more than once on setup
  // ever and it seems like it may get used more frequently.
  let initilized_setup = initialize_setup_data(setup_data).unwrap();
  let circuits = initialize_circuit_list(&initilized_setup); // TODO, change the type signature of trait to use arbitrary error types.
  let memory = Memory { circuits, rom: vec![0; setup_data.max_rom_length] }; // Note, `rom` here is not used in setup, only `circuits`
  let public_params = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());

  #[cfg(feature = "timing")]
  trace!("`PublicParams::setup()` elapsed: {:?}", time.elapsed());

  public_params
}

/// Executes the SuperNova program with the provided setup, proof, and instance parameters.
///
/// This function initializes the public inputs, resizes the ROM, and iteratively processes each
/// step of the ROM to generate a recursive SNARK proof. It handles the private inputs, witness
/// generation, and circuit execution for each opcode in the ROM.
///
/// # Arguments
///
/// * `setup_params` - The setup parameters containing the setup data and public parameters.
/// * `proof_params` - The proof parameters containing the ROM and other proof-related data.
/// * `instance_params` - The instance parameters containing the NIVC input and private inputs.
///
/// # Returns
///
/// A `Result` containing the generated `RecursiveSNARK` on success, or a `ProofError` on failure.
///
/// # Errors
///
/// This function can return a `ProofError` if there are issues with the NIVC input, private inputs,
/// or witness generation.
pub async fn run(
  setup_params: &SetupParams<Online>,
  proof_params: &ProofParams,
  instance_params: &InstanceParams<Expanded>,
) -> Result<RecursiveSNARK<E1>, ProofError> {
  info!("Starting SuperNova program...");

  // Resize the rom to be the `max_rom_length` committed to in the `S::SetupData`
  let (z0_primary, resized_rom) =
    setup_params.extend_public_inputs(&proof_params.rom, &instance_params.nivc_input)?;
  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark_option = None;
  let mut next_public_input = z0_primary.clone();

  // TODO (Colin): We are basically creating a `R1CS` for each circuit here, then also creating
  // `R1CSWithArity` for the circuits in the `PublicParams`. Surely we don't need both?
  let circuits = initialize_circuit_list(&setup_params.setup_data); // TODO: AwK?

  let mut memory = Memory { rom: resized_rom.clone(), circuits };

  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();
  for (idx, &op_code) in
    resized_rom.iter().enumerate().take_while(|(_, &op_code)| op_code != u64::MAX)
  {
    info!("Step {} of ROM", idx);
    debug!("Opcode = {:?}", op_code);
    memory.circuits[op_code as usize].private_input =
      Some(instance_params.private_inputs[idx].clone());
    // trace!("private input: {:?}", memory.circuits[op_code as usize].private_input);
    memory.circuits[op_code as usize].nivc_io = Some(next_public_input);

    let wit_type = memory.circuits[op_code as usize].witness_generator_type.clone();
    let public_params = &setup_params.public_params;

    memory.circuits[op_code as usize].circuit.witness =
      if wit_type == WitnessGeneratorType::Browser {
        // When running in browser, the witness is passed as input.
        // Some(witnesses[idx].clone())
        let arity = memory.circuits[op_code as usize].circuit.arity();
        let nivc_io =
          &memory.circuits[op_code as usize].nivc_io.as_ref().ok_or_else(|| {
            ProofError::Other(format!("nivc_io not found for op_code {}", op_code))
          })?[..arity];

        let private_input =
          memory.circuits[op_code as usize].private_input.as_ref().ok_or_else(|| {
            ProofError::Other(format!("private_input not found for op_code {}", op_code))
          })?;

        let circom_input = into_circom_input(nivc_io, private_input);
        let witness = generate_witness_from_browser_type(circom_input, op_code).await?;
        Some(witness)
      } else {
        let arity = memory.circuits[op_code as usize].circuit.arity();
        let nivc_io =
          &memory.circuits[op_code as usize].nivc_io.as_ref().ok_or_else(|| {
            ProofError::Other(format!("nivc_io not found for op_code {}", op_code))
          })?[..arity];

        let private_input =
          memory.circuits[op_code as usize].private_input.as_ref().ok_or_else(|| {
            ProofError::Other(format!("private_input not found for op_code {}", op_code))
          })?;
        let in_json = into_input_json(nivc_io, private_input)?;
        let witness = generate_witness_from_generator_type(&in_json, &wit_type)?;
        Some(witness)
      };

    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        public_params,
        &memory,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
    })?;

    info!("Proving single step...");
    recursive_snark.prove_step(public_params, &circuit_primary, &circuit_secondary)?;
    info!("Done proving single step...");

    #[cfg(feature = "verify-steps")]
    {
      info!("Verifying single step...");
      recursive_snark.verify(public_params, &z0_primary, &z0_secondary)?;
      info!("Single step verification done");
    }

    // Update everything now for next step
    next_public_input = recursive_snark.zi_primary().clone();
    next_public_input.truncate(circuit_primary.arity());

    recursive_snark_option = Some(Ok(recursive_snark));
  }
  // Note, this unwrap cannot fail
  let recursive_snark = recursive_snark_option.unwrap();
  #[cfg(feature = "timing")]
  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  Ok(recursive_snark?)
}

/// Compresses a proof without performing the setup step.
///
/// This function takes an existing `RecursiveSNARK` and compresses it into a `CompressedProof`
/// using pre-initialized proving keys. This is useful when the setup step has already been
/// performed and the proving keys are available, allowing for more efficient proof generation.
///
/// # Arguments
///
/// * `recursive_snark` - A reference to the `RecursiveSNARK` that needs to be compressed.
/// * `public_params` - The public parameters required for the proof system.
/// * `vk_digest_primary` - The primary verification key digest.
/// * `vk_digest_secondary` - The secondary verification key digest.
///
/// # Returns
///
/// A `Result` containing the `CompressedProof` if successful, or a `ProofError` if an error occurs.
///
/// # Errors
///
/// This function will return a `ProofError` if the compression process fails at any step.
pub fn compress_proof_no_setup(
  recursive_snark: &RecursiveSNARK<E1>,
  public_params: &PublicParams<E1>,
  vk_digest_primary: <E1 as Engine>::Scalar,
  vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
) -> Result<CompressedProof, ProofError> {
  let pk = CompressedSNARK::<E1, S1, S2>::initialize_pk(
    public_params,
    vk_digest_primary,
    vk_digest_secondary,
  )
  .unwrap();
  debug!(
    "initialized pk pk_primary.digest={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest, pk.pk_secondary.vk_digest
  );

  debug!("`CompressedSNARK::prove STARTING PROVING!");
  let proof = FoldingProof {
    proof:           CompressedSNARK::<E1, S1, S2>::prove(public_params, &pk, recursive_snark)?,
    verifier_digest: pk.pk_primary.vk_digest,
  };
  debug!("`CompressedSNARK::prove completed!");

  Ok(proof)
}

/// Compresses a proof by performing the setup step and generating a compressed proof.
///
/// This function initializes the proving keys by performing the setup step, and then uses these
/// keys to generate a compressed proof from an existing `RecursiveSNARK`. This is useful when the
/// setup step has not been performed yet, and the proving keys need to be initialized before
/// generating the proof.
///
/// # Arguments
///
/// * `recursive_snark` - A reference to the `RecursiveSNARK` that needs to be compressed.
/// * `public_params` - The public parameters required for the proof system.
///
/// # Returns
///
/// A `Result` containing the `CompressedProof` if successful, or a `ProofError` if an error occurs.
///
/// # Errors
///
/// This function will return a `ProofError` if the setup or compression process fails at any step.
pub fn compress_proof(
  recursive_snark: &RecursiveSNARK<E1>,
  public_params: &PublicParams<E1>,
) -> Result<CompressedProof, ProofError> {
  debug!("Setting up `CompressedSNARK`");
  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();
  let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(public_params)?;
  debug!("Done setting up `CompressedSNARK`");
  #[cfg(feature = "timing")]
  trace!("`CompressedSNARK::setup` elapsed: {:?}", time.elapsed());

  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();

  let proof = FoldingProof {
    proof:           CompressedSNARK::<E1, S1, S2>::prove(public_params, &pk, recursive_snark)?,
    verifier_digest: pk.pk_primary.vk_digest,
  };
  debug!("`CompressedSNARK::prove completed!");

  #[cfg(feature = "timing")]
  trace!("`CompressedSNARK::prove` elapsed: {:?}", time.elapsed());

  Ok(proof)
}

/// Initializes the setup data for the program.
///
/// This function takes an `UninitializedSetup` and converts it into an `InitializedSetup` by
/// iterating over the R1CS types and witness generator types, creating `R1CS` instances and
/// collecting them into vectors. It then returns an `InitializedSetup` containing the R1CS and
/// witness generator types, along with the maximum ROM length.
///
/// # Arguments
///
/// * `setup_data` - The `UninitializedSetup` to initialize.
///
/// # Returns
///
/// A `Result` containing the `InitializedSetup` if successful, or a `ProofError` if an error
/// occurs.
pub fn initialize_setup_data(
  setup_data: &UninitializedSetup,
) -> Result<InitializedSetup, ProofError> {
  let (r1cs, witness_generator_types) = setup_data
    .r1cs_types
    .iter()
    .zip(setup_data.witness_generator_types.iter())
    .map(|(r1cs_type, generator)| {
      let r1cs = R1CS::try_from(r1cs_type)?;
      Ok::<(Arc<circom::r1cs::R1CS>, data::WitnessGeneratorType), ProofError>((
        Arc::new(r1cs),
        generator.clone(),
      ))
    })
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .unzip();

  Ok(InitializedSetup { r1cs, witness_generator_types, max_rom_length: setup_data.max_rom_length })
}

/// Initializes a list of ROM circuits from the provided setup data.
///
/// This function takes an `InitializedSetup` and creates a vector of `RomCircuit` instances.
/// Each `RomCircuit` is constructed using the R1CS and witness generator types from the setup data,
/// and is assigned a unique circuit index and the maximum ROM length.
///
/// # Arguments
///
/// * `setup_data` - The `InitializedSetup` containing the R1CS and witness generator types.
///
/// # Returns
///
/// A vector of `RomCircuit` instances initialized with the provided setup data.
pub fn initialize_circuit_list(setup_data: &InitializedSetup) -> Vec<RomCircuit> {
  setup_data
    .r1cs
    .iter()
    .zip(setup_data.witness_generator_types.iter())
    .enumerate()
    .map(|(i, (r1cs, generator))| {
      let circuit = circom::CircomCircuit { r1cs: r1cs.clone(), witness: None };
      RomCircuit {
        circuit,
        circuit_index: i,
        rom_size: setup_data.max_rom_length,
        nivc_io: None,
        private_input: None,
        witness_generator_type: generator.clone(),
      }
    })
    .collect::<Vec<_>>()
}
