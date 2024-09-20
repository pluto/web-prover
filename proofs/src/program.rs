use std::time::Instant;

use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::{circuit::StepCircuit, snark::default_ck_hint},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::r1cs::R1CS;
use handler::map_private_inputs;

use super::*;

const ROM: &[u64] = &[0, 0, 0, 0];
const PARSER_R1CS: &[u8] = include_bytes!("../parse_fold_batch.r1cs");

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};
use circom::compute_witness;

struct Memory {
  rom:                Vec<u64>,
  curr_public_input:  Vec<F<G1>>,
  curr_private_input: HashMap<String, Value>,
  graph_bin:          Vec<u8>,
}

#[derive(Clone)]
pub enum CircuitSelector {
  Parser { circuit: C1, circuit_index: usize, rom_size: usize },
}

impl CircuitSelector {
  pub fn inner_arity(&self) -> usize {
    match self {
      Self::Parser { circuit, .. } => circuit.arity(),
    }
  }
}

impl NonUniformCircuit<E1> for Memory {
  type C1 = CircuitSelector;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { 1 }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    let r1cs = R1CS::from(PARSER_R1CS);
    let witness = compute_witness(
      self.curr_public_input.clone(),
      self.curr_private_input.clone(),
      &self.graph_bin,
    );
    match circuit_index {
      0 => CircuitSelector::Parser {
        circuit: CircomCircuit { r1cs, witness: Some(witness) },
        circuit_index,
        rom_size: self.rom.len(),
      },
      _ => panic!("Incorrect circuit index provided!"),
    }
  }

  fn secondary_circuit(&self) -> Self::C2 { Default::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl SNStepCircuit<F<G1>> for CircuitSelector {
  fn arity(&self) -> usize {
    match self {
      Self::Parser { circuit, rom_size, .. } => circuit.arity() + 1 + rom_size, /* underlying
                                                                                 * circuit inputs,
                                                                                 * rom_pc, rom
                                                                                 * len */
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::Parser { circuit_index, .. } => *circuit_index, /* TODO: i believe index is
                                                             * used for z_i */
    }
  }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>, // TODO: idk how to use the program counter lol
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    println!("inside of synthesize with pc: {pc:?}");

    let circuit = match self {
      Self::Parser { circuit, .. } => circuit,
    };
    let rom_index = &z[circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[circuit.arity() + 1..]; // jump to where we pushed rom data into CS

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

pub fn run_program(circuit_data: CircuitData) {
  info!("Starting SuperNova program...");
  let graph_bin = std::fs::read(&circuit_data.graph_path).unwrap();
  let mut z0_primary: Vec<F<G1>> =
    circuit_data.init_step_in.iter().map(|val| F::<G1>::from(*val)).collect();

  // Map `private_input`
  let private_inputs = map_private_inputs(&circuit_data);

  let mut memory = Memory {
    rom:                ROM.to_vec(),
    curr_public_input:  z0_primary.clone(),
    graph_bin:          graph_bin.clone(),
    curr_private_input: private_inputs[0].clone(),
  };

  let pp = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(memory.rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark_option = None;

  for (idx, &op_code) in ROM.iter().enumerate() {
    info!("Step {} of ROM", idx);
    info!("opcode = {}", op_code);
    memory.curr_private_input = private_inputs[idx].clone();

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
    memory.curr_public_input = next_pub_input;

    recursive_snark_option = Some(recursive_snark);
  }
  dbg!(recursive_snark_option.unwrap().zi_primary());
}

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
