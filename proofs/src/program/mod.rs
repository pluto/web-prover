use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::{circuit::StepCircuit, snark::default_ck_hint},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::{r1cs::R1CS, witness::generate_witness_from_generator_type};
use utils::{into_input_json, map_private_inputs};

use super::*;

pub mod utils;

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};

pub struct Memory {
  pub rom:      Vec<u64>,
  pub circuits: Vec<RomCircuit>,
}

#[derive(Clone)]
pub struct RomCircuit {
  pub circuit:                C1,
  pub circuit_index:          usize,
  pub rom_size:               usize,
  pub curr_public_input:      Option<Vec<F<G1>>>,
  pub curr_private_input:     Option<HashMap<String, Value>>,
  pub witness_generator_type: WitnessGeneratorType,
}

pub struct ProgramOutput {
  pub recursive_snark: RecursiveSNARK<E1>,
  pub public_params:   PublicParams<E1>,
}

impl NonUniformCircuit<E1> for Memory {
  type C1 = RomCircuit;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { self.circuits.len() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  fn secondary_circuit(&self) -> Self::C2 { Default::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl SNStepCircuit<F<G1>> for RomCircuit {
  fn arity(&self) -> usize { self.circuit.arity() + 1 + self.rom_size }

  fn circuit_index(&self) -> usize { self.circuit_index }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>, // TODO: idk how to use the program counter lol
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    // TODO: Clean this up.
    let circuit = if let Some(allocated_num) = pc {
      if allocated_num.get_value().is_some() {
        self.circuit.clone()
      } else {
        self.circuit.clone()
      }
    } else {
      panic!("allocated num was none?")
    };

    let rom_index = &z[circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[circuit.arity() + 1..]; // jump to where we pushed rom data into C
    let (rom_index_next, pc_next) = utils::next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;
    let mut circuit_constraints = circuit.vanilla_synthesize(cs, z)?;
    circuit_constraints.push(rom_index_next);
    circuit_constraints.extend(z[circuit.arity() + 1..].iter().cloned());
    Ok((Some(pc_next), circuit_constraints))
  }
}

pub fn run(program_data: &ProgramData) -> ProgramOutput {
  info!("Starting SuperNova program...");

  // Get the public inputs needed for circuits
  let mut z0_primary: Vec<F<G1>> =
    program_data.initial_public_input.iter().map(|val| F::<G1>::from(*val)).collect();
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(program_data.rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

  // Get the private inputs needed for circuits
  let private_inputs = map_private_inputs(program_data);

  let mut circuits = vec![];
  for (circuit_index, (r1cs_path, witness_generator_type)) in
    program_data.r1cs_types.iter().zip(program_data.witness_generator_types.iter()).enumerate()
  {
    let circuit = circom::CircomCircuit { r1cs: R1CS::from(r1cs_path), witness: None };
    let rom_circuit = RomCircuit {
      circuit,
      circuit_index,
      rom_size: program_data.rom.len(),
      curr_public_input: if program_data.rom[0] as usize == circuit_index {
        Some(z0_primary.clone())
      } else {
        None
      },
      curr_private_input: if program_data.rom[0] as usize == circuit_index {
        Some(private_inputs[0].clone())
      } else {
        None
      },
      witness_generator_type: witness_generator_type.clone(),
    };

    circuits.push(rom_circuit);
  }

  debug!("Initialized RomCircuits: len={:?}", circuits.len());

  let mut memory = Memory { rom: program_data.rom.clone(), circuits };

  // NOTE: This needs move to a preprocessing step.
  let public_params = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());

  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark_option = None;
  let mut next_public_input = z0_primary.clone();

  for (idx, &op_code) in program_data.rom.iter().enumerate() {
    info!("Step {} of ROM", idx);
    debug!("Opcode = {}", op_code);

    memory.circuits[op_code as usize].curr_private_input = Some(private_inputs[idx].clone());
    memory.circuits[op_code as usize].curr_public_input = Some(next_public_input);

    let wit_type = memory.circuits[op_code as usize].witness_generator_type.clone();
    let (is_browser, is_mobile) = match wit_type.clone() {
      WitnessGeneratorType::Browser => (true, false),
      WitnessGeneratorType::Mobile{ circuit } => (false, true),
      _ => (false, false)
    };

    memory.circuits[op_code as usize].circuit.witness = if is_browser {
      // When running in browser, the witness is passed as input.
      Some(program_data.witnesses[op_code as usize].clone())
    } else if is_mobile {

      // TODO: Obviously this code is horrible. Migration to circom-witnesscalc
      // will help. In the mean time, do the dirty to benchmark performance. 
      match wit_type.clone() {
        WitnessGeneratorType::Mobile{circuit} => {
          let r = if circuit == "aes-gcm-fold" {
            let arity = memory.circuits[op_code as usize].circuit.arity().clone();
            let in_json = into_input_json(
              &memory.circuits[op_code as usize].curr_public_input.as_ref().unwrap()[..arity],
              memory.circuits[op_code as usize].curr_private_input.as_ref().unwrap(),
            );

            Some(aes_gcm_fold_Wrapper(&in_json))
          } else {
            panic!("Mobile only supports aes-gcm-fold")
          };
          r
        }, 
        _ => panic!("Mobile only supported")
      }
    } else {
      let arity = memory.circuits[op_code as usize].circuit.arity().clone();
      let in_json = into_input_json(
        &memory.circuits[op_code as usize].curr_public_input.as_ref().unwrap()[..arity],
        memory.circuits[op_code as usize].curr_private_input.as_ref().unwrap(),
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
  ProgramOutput { public_params, recursive_snark: recursive_snark_option.unwrap() }
}
