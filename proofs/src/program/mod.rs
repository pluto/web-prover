use std::time::Instant;

use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::{circuit::StepCircuit, snark::default_ck_hint},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::r1cs::{load_r1cs_from_file, R1CS};
use utils::map_private_inputs;

use super::*;
pub mod dynamic;
pub mod r#static;
mod tests;
pub mod utils;

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};
use circom::witness::compute_witness_from_graph;

pub struct Memory {
  pub rom:      Vec<u64>,
  pub circuits: Vec<RomCircuit>,
}

// TODO: We can impl the traits on this probably and later have an enum, but we can really swap
// circuits internally here by changing the R1CS inside of C1
#[derive(Clone)]
pub struct RomCircuit {
  pub circuit:                C1,
  pub circuit_index:          usize,
  pub rom_size:               usize,
  pub curr_public_input:      Option<Vec<F<G1>>>,
  pub curr_private_input:     Option<HashMap<String, Value>>,
  pub witness_generator_type: WitnessGeneratorType,
}

pub fn run(program_data: ProgramData) {
  info!("Starting SuperNova program...");

  // Get the public inputs needed for circuits
  let mut z0_primary: Vec<F<G1>> =
    program_data.initial_public_input.iter().map(|val| F::<G1>::from(*val)).collect();
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(program_data.rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

  // Get the private inputs needed for circuits
  let private_inputs = map_private_inputs(&program_data);

  let mut circuits = vec![];
  for (circuit_index, (r1cs_path, witness_generator_type)) in
    program_data.r1cs_paths.iter().zip(program_data.witness_generator_types.iter()).enumerate()
  {
    let circuit = CircomCircuit { r1cs: load_r1cs_from_file(&r1cs_path), witness: None };
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

  let mut memory = Memory { rom: program_data.rom.clone(), circuits };

  let pp = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());

  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark_option = None;

  for (idx, &op_code) in program_data.rom.iter().enumerate() {
    info!("Step {} of ROM", idx);
    info!("opcode = {}", op_code);
    memory.circuits[idx].curr_private_input = Some(private_inputs[idx].clone());

    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        &pp,
        &memory,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .unwrap()
    });

    info!("Proving single step...");
    let start = Instant::now();
    recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary).unwrap();
    info!("Single step proof took: {:?}", start.elapsed());

    // dbg!(&recursive_snark.zi_primary()); // TODO: this can be used later if need be.

    info!("Verifying single step...");
    let start = Instant::now();
    recursive_snark.verify(&pp, &z0_primary, &z0_secondary).unwrap();
    info!("Single step verification took: {:?}", start.elapsed());

    // Update everything now for next step
    // z0_primary = recursive_snark.zi_primary().clone();
    let mut next_pub_input = recursive_snark.zi_primary().clone();
    next_pub_input.truncate(circuit_primary.inner_arity());
    memory.circuits[idx].curr_public_input = Some(next_pub_input);

    recursive_snark_option = Some(recursive_snark);
  }
  dbg!(recursive_snark_option.unwrap().zi_primary());
}
