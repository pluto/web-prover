use std::time::Instant;

use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::{circuit::StepCircuit, snark::default_ck_hint},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::r1cs::R1CS;
use handler::map_private_inputs;

use super::*;
mod dynamic;
mod r#static;
mod tests;

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};
use circom::witness::compute_witness_from_graph;

pub struct Memory {
  pub rom:                Vec<u64>,
  pub curr_public_input:  Vec<F<G1>>,
  pub curr_private_input: HashMap<String, Value>,
}

// TODO: We can impl the traits on this probably and later have an enum, but we can really swap
// circuits internally here by changing the R1CS inside of C1
#[derive(Clone)]
pub struct RomCircuit {
  pub circuit:            C1,
  pub circuit_index:      usize,
  pub rom_size:           usize,
  pub curr_public_input:  Vec<F<G1>>,
  pub curr_private_input: HashMap<String, Value>,
}

// // TODO: Consolidate these entrypoints since we have a test now.
// pub fn run_program(circuit_data: CircuitData) {
//   info!("Starting SuperNova program...");
//   let graph_bin = std::fs::read(&circuit_data.graph_path).unwrap();
//   let mut z0_primary: Vec<F<G1>> =
//     circuit_data.initial_public_input.iter().map(|val| F::<G1>::from(*val)).collect();

//   // Map `private_input`
//   let private_inputs = map_private_inputs(&circuit_data);

//   let mut memory = Memory {
//     rom:                ROM.to_vec(),
//     curr_public_input:  z0_primary.clone(),
//     graph_bin:          graph_bin.clone(),
//     curr_private_input: private_inputs[0].clone(),
//   };

//   let pp = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());
//   z0_primary.push(F::<G1>::ZERO); // rom_index = 0
//   z0_primary.extend(memory.rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

//   let z0_secondary = vec![F::<G2>::ZERO];

//   let mut recursive_snark_option = None;

//   for (idx, &op_code) in ROM.iter().enumerate() {
//     info!("Step {} of ROM", idx);
//     info!("opcode = {}", op_code);
//     memory.curr_private_input = private_inputs[idx].clone();

//     let circuit_primary = memory.primary_circuit(op_code as usize);
//     let circuit_secondary = memory.secondary_circuit();

//     let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
//       RecursiveSNARK::new(
//         &pp,
//         &memory,
//         &circuit_primary,
//         &circuit_secondary,
//         &z0_primary,
//         &z0_secondary,
//       )
//       .unwrap()
//     });

//     info!("Proving single step...");
//     let start = Instant::now();
//     recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary).unwrap();
//     info!("Single step proof took: {:?}", start.elapsed());

//     // dbg!(&recursive_snark.zi_primary()); // TODO: this can be used later if need be.

//     info!("Verifying single step...");
//     let start = Instant::now();
//     recursive_snark.verify(&pp, &z0_primary, &z0_secondary).unwrap();
//     info!("Single step verification took: {:?}", start.elapsed());

//     // Update everything now for next step
//     // z0_primary = recursive_snark.zi_primary().clone();
//     let mut next_pub_input = recursive_snark.zi_primary().clone();
//     next_pub_input.truncate(circuit_primary.inner_arity());
//     memory.curr_public_input = next_pub_input;

//     recursive_snark_option = Some(recursive_snark);
//   }
//   dbg!(recursive_snark_option.unwrap().zi_primary());
// }

pub mod utils {
  use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    LinearCombination,
  };
  use itertools::Itertools;

  use super::*;

  #[allow(clippy::type_complexity)]
  pub fn next_rom_index_and_pc<CS: ConstraintSystem<F<G1>>>(
    cs: &mut CS,
    rom_index: &AllocatedNum<F<G1>>,
    allocated_rom: &[AllocatedNum<F<G1>>],
    pc: &AllocatedNum<F<G1>>,
  ) -> Result<(AllocatedNum<F<G1>>, AllocatedNum<F<G1>>), SynthesisError> {
    // Compute a selector for the current rom_index in allocated_rom
    let current_rom_selector =
      get_selector_vec_from_index(cs.namespace(|| "rom selector"), rom_index, allocated_rom.len())?;

    // Enforce that allocated_rom[rom_index] = pc
    for (rom, bit) in allocated_rom.iter().zip_eq(current_rom_selector.iter()) {
      // if bit = 1, then rom = pc
      // bit * (rom - pc) = 0
      cs.enforce(
        || "enforce bit = 1 => rom = pc",
        |lc| lc + &bit.lc(CS::one(), F::<G1>::ONE),
        |lc| lc + rom.get_variable() - pc.get_variable(),
        |lc| lc,
      );
    }

    // Get the index of the current rom, or the index of the invalid rom if no match
    let current_rom_index = current_rom_selector
      .iter()
      .position(|bit| bit.get_value().is_some_and(|v| v))
      .unwrap_or_default();
    let next_rom_index = current_rom_index + 1;

    let rom_index_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next rom index"), || {
      F::<G1>::from(next_rom_index as u64)
    });
    cs.enforce(
      || " rom_index + 1 - next_rom_index_num = 0",
      |lc| lc,
      |lc| lc,
      |lc| lc + rom_index.get_variable() + CS::one() - rom_index_next.get_variable(),
    );

    // Allocate the next pc without checking.
    // The next iteration will check whether the next pc is valid.
    let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next pc"), || {
      allocated_rom.get(next_rom_index).and_then(|v| v.get_value()).unwrap_or(-F::<G1>::ONE)
    });

    Ok((rom_index_next, pc_next))
  }

  pub fn get_selector_vec_from_index<CS: ConstraintSystem<F<G1>>>(
    mut cs: CS,
    target_index: &AllocatedNum<F<G1>>,
    num_indices: usize,
  ) -> Result<Vec<Boolean>, SynthesisError> {
    assert_ne!(num_indices, 0);

    // Compute the selector vector non-deterministically
    let selector = (0..num_indices)
      .map(|idx| {
        // b <- idx == target_index
        Ok(Boolean::Is(AllocatedBit::alloc(
          cs.namespace(|| format!("allocate s_{:?}", idx)),
          target_index.get_value().map(|v| v == F::<G1>::from(idx as u64)),
        )?))
      })
      .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

    // Enforce ∑ selector[i] = 1
    {
      let selected_sum = selector
        .iter()
        .fold(LinearCombination::zero(), |lc, bit| lc + &bit.lc(CS::one(), F::<G1>::ONE));
      cs.enforce(
        || "exactly-one-selection",
        |_| selected_sum,
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
      );
    }

    // Enforce `target_index - ∑ i * selector[i] = 0``
    {
      let selected_value =
        selector.iter().enumerate().fold(LinearCombination::zero(), |lc, (i, bit)| {
          lc + &bit.lc(CS::one(), F::<G1>::from(i as u64))
        });
      cs.enforce(
        || "target_index - ∑ i * selector[i] = 0",
        |lc| lc,
        |lc| lc,
        |lc| lc + target_index.get_variable() - &selected_value,
      );
    }

    Ok(selector)
  }
}
