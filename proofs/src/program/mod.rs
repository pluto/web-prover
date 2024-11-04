use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::{
  r1cs::R1CS,
  witness::{aes_gcm_fold_wrapper, generate_witness_from_generator_type},
};
use client_side_prover::{
  r1cs::R1CSShape,
  supernova::{get_circuit_shapes, NonUniformCircuit, RecursiveSNARK, StepCircuit},
  traits::snark::default_ck_hint,
  R1CSWithArity,
};
use data::Expanded;
use proof::Proof;
use tracing::trace;
use utils::into_input_json;

use super::*;

pub mod data;
pub mod manifest;
pub mod utils;

pub struct Memory {
  pub circuits: Vec<RomCircuit>,
  pub rom:      Vec<u64>,
}

#[derive(Clone)]
pub struct RomCircuit {
  pub circuit:                CircomCircuit,
  pub circuit_index:          usize,
  pub rom_size:               usize,
  pub nivc_io:                Option<Vec<F<G1>>>,
  pub private_input:          Option<HashMap<String, Value>>,
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
pub fn setup(setup_data: &SetupData) -> PublicParams<E1> {
  // Optionally time the setup stage for the program
  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();

  // TODO: I don't think we want to have to call `initialize_circuit_list` more than once on setup
  // ever and it seems like it may get used more frequently.
  let circuits = initialize_circuit_list(setup_data);
  let memory = Memory { circuits, rom: vec![0; setup_data.max_rom_length] }; // Note, `rom` here is not used in setup, only `circuits`
  let public_params = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());

  #[cfg(feature = "timing")]
  trace!("`PublicParams::setup()` elapsed: {:?}", time.elapsed());

  public_params
}

pub fn run(program_data: &ProgramData<Online, Expanded>) -> RecursiveSNARK<E1> {
  info!("Starting SuperNova program...");

  // Resize the rom to be the `max_rom_length` committed to in the `SetupData`
  let mut rom = program_data
    .rom
    .iter()
    .map(|opcode_config| program_data.rom_data.get(&opcode_config.name).unwrap().opcode)
    .collect::<Vec<u64>>();
  rom.resize(program_data.setup_data.max_rom_length, u64::MAX);

  // Get the public inputs needed for circuits
  let mut z0_primary: Vec<F<G1>> =
    program_data.initial_nivc_input.iter().map(|val| F::<G1>::from(*val)).collect();
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark_option = None;
  let mut next_public_input = z0_primary.clone();

  // TODO (Colin): We are basically creating a `R1CS` for each circuit here, then also creating
  // `R1CSWithArity` for the circuits in the `PublicParams`. Surely we don't need both?
  let circuits = initialize_circuit_list(&program_data.setup_data); // TODO: AwK?
  let mut memory = Memory { rom: rom.clone(), circuits };

  let aux_params = program_data.public_params.aux_params();

  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();
  for (idx, &op_code) in rom.iter().enumerate().take_while(|(_, &op_code)| op_code != u64::MAX) {
    info!("Step {} of ROM", idx);
    debug!("Opcode = {:?}", op_code);
    memory.circuits[op_code as usize].private_input = Some(program_data.inputs[idx].clone());
    trace!("private input: {:?}", memory.circuits[op_code as usize].private_input);
    memory.circuits[op_code as usize].nivc_io = Some(next_public_input);

    let wit_type = memory.circuits[op_code as usize].witness_generator_type.clone();
    let (is_browser, is_mobile) = match wit_type.clone() {
      WitnessGeneratorType::Browser => (true, false),
      WitnessGeneratorType::Mobile { circuit } => (false, true),
      _ => (false, false),
    };

    // NOTE (Colin): Alloc only the used R1CSWithArity
    let mut temp_memory =
      Memory { rom: vec![], circuits: vec![RomCircuit::default(); memory.circuits.len()] };
    temp_memory.circuits[op_code as usize] = memory.circuits[op_code as usize].clone();
    let temp_shapes = get_circuit_shapes(&temp_memory);
    let public_params = PublicParams::from_parts_unchecked(temp_shapes, aux_params.clone());

    memory.circuits[op_code as usize].circuit.witness = if is_browser {
      // When running in browser, the witness is passed as input.
      Some(program_data.witnesses[op_code as usize].clone())
    } else if is_mobile {
      // TODO: Obviously this code is horrible. Migration to circom-witnesscalc
      // will help. In the mean time, do the dirty to benchmark performance.
      match wit_type.clone() {
        WitnessGeneratorType::Mobile { circuit } => {
          let r = if circuit == "aes-gcm-fold" {
            let arity = memory.circuits[op_code as usize].circuit.arity().clone();
            let in_json = into_input_json(
              &memory.circuits[op_code as usize].nivc_io.as_ref().unwrap()[..arity],
              memory.circuits[op_code as usize].private_input.as_ref().unwrap(),
            );

            Some(aes_gcm_fold_wrapper(&in_json))
          } else {
            panic!("Mobile only supports aes-gcm-fold")
          };
          r
        },
        _ => panic!("Mobile only supported"),
      }
    } else {
      let arity = memory.circuits[op_code as usize].circuit.arity().clone();
      let in_json = into_input_json(
        &memory.circuits[op_code as usize].nivc_io.as_ref().unwrap()[..arity],
        memory.circuits[op_code as usize].private_input.as_ref().unwrap(),
      );

      let witness = generate_witness_from_generator_type(&in_json, &wit_type);
      Some(witness)
    };

    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        &public_params,
        &memory,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .unwrap()
    });

    info!("Proving single step...");
    recursive_snark.prove_step(&public_params, &circuit_primary, &circuit_secondary).unwrap();
    info!("Done proving single step...");

    #[cfg(feature = "verify-steps")]
    {
      info!("Verifying single step...");
      recursive_snark.verify(&public_params, &z0_primary, &z0_secondary).unwrap();
      info!("Single step verification done");
    }

    // Update everything now for next step
    next_public_input = recursive_snark.zi_primary().clone();
    next_public_input.truncate(circuit_primary.arity());

    recursive_snark_option = Some(recursive_snark);
  }
  // Note, this unwrap cannot fail
  let recursive_snark = recursive_snark_option.unwrap();
  #[cfg(feature = "timing")]
  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  recursive_snark
}

pub fn compress_proof(
  recursive_snark: &RecursiveSNARK<E1>,
  public_params: &PublicParams<E1>,
) -> Proof<CompressedSNARK<E1, S1, S2>> {
  debug!("Generating `CompressedSNARK`");
  let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(public_params).unwrap();

  // Optionally time the `CompressedSNARK` creation
  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();

  let proof =
    Proof(CompressedSNARK::<E1, S1, S2>::prove(public_params, &pk, recursive_snark).unwrap());
  debug!("`CompressedSNARK::prove completed!");

  #[cfg(feature = "timing")]
  trace!("`CompressedSNARK::prove` of `program::run()` elapsed: {:?}", time.elapsed());

  proof
}

// TODO: May want to rethink this slightly as we also store the R1CS data inside the PP. Avoid
// doubling up if possible (maybe need to use refs)
pub fn initialize_circuit_list(setup_data: &SetupData) -> Vec<RomCircuit> {
  let mut circuits = vec![];
  for (circuit_index, (r1cs_type, witness_generator_type)) in
    setup_data.r1cs_types.iter().zip(setup_data.witness_generator_types.iter()).enumerate()
  {
    let circuit = circom::CircomCircuit { r1cs: R1CS::from(r1cs_type), witness: None };
    let rom_circuit = RomCircuit {
      circuit,
      circuit_index,
      rom_size: setup_data.max_rom_length,
      nivc_io: None,
      private_input: None,
      witness_generator_type: witness_generator_type.clone(),
    };

    circuits.push(rom_circuit);
  }
  circuits
}
