use std::time::Instant;

use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::{circuit::StepCircuit, snark::default_ck_hint},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::r1cs::R1CS;
use program::utils::next_rom_index_and_pc;

use super::*;

const ROM: &[u64] = &[0, 1];

const ADD_R1CS: &[u8] = include_bytes!("../examples/add.r1cs");
const ADD_GRAPH: &[u8] = include_bytes!("../examples/add.bin");

const SQUARE_R1CS: &[u8] = include_bytes!("../examples/square.r1cs");
const SQUARE_GRAPH: &[u8] = include_bytes!("../examples/square.bin");

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};
use circom::compute_witness;

struct Memory {
  rom:                Vec<u64>,
  curr_public_input:  Vec<F<G1>>,
  curr_private_input: HashMap<String, Value>,
}

#[derive(Clone)]
pub enum CircuitSelector {
  Add { circuit: C1, circuit_index: usize, rom_size: usize },
  Square { circuit: C1, circuit_index: usize, rom_size: usize },
}

impl CircuitSelector {
  pub fn inner_arity(&self) -> usize {
    match self {
      Self::Add { circuit, .. } => circuit.arity(),
      Self::Square { circuit, .. } => circuit.arity(),
    }
  }
}

impl NonUniformCircuit<E1> for Memory {
  type C1 = CircuitSelector;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { 2 }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    match circuit_index {
      0 => CircuitSelector::Add {
        circuit: CircomCircuit {
          r1cs:    R1CS::from(ADD_R1CS),
          witness: Some(compute_witness(
            self.curr_public_input.clone(),
            self.curr_private_input.clone(),
            ADD_GRAPH,
          )),
        },
        circuit_index,
        rom_size: self.rom.len(),
      },
      1 => CircuitSelector::Square {
        circuit: CircomCircuit {
          r1cs:    R1CS::from(SQUARE_R1CS),
          witness: Some(compute_witness(
            self.curr_public_input.clone(),
            self.curr_private_input.clone(),
            SQUARE_GRAPH,
          )),
        },
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
      Self::Add { circuit, rom_size, .. } => circuit.arity() + 1 + rom_size,
      Self::Square { circuit, rom_size, .. } => circuit.arity() + 1 + rom_size,
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::Add { circuit_index, .. } => *circuit_index,
      Self::Square { circuit_index, .. } => *circuit_index,
    }
  }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    println!("inside of synthesize with pc: {pc:?}");

    let circuit = match self {
      Self::Add { circuit, .. } => circuit,
      Self::Square { circuit, .. } => circuit,
    };
    let rom_index = &z[circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[circuit.arity() + 1..]; // jump to where we pushed rom data into CS

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
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

#[test]
#[tracing_test::traced_test]
fn run_program() {
  info!("Starting SuperNova Add/Square test...");

  let init_step_in = vec![F::<G1>::from(0)];
  //   let init_step_in: Vec<u64> = vec![]; // empty for now because I have no pub inputs which will
  // probably not work

  let mut z0_primary: Vec<F<G1>> = init_step_in.iter().map(|val| F::<G1>::from(*val)).collect();

  // Map `private_input`
  let mut private_inputs = vec![];
  private_inputs
    .push(serde_json::from_str::<HashMap<String, Value>>(r#"{ "x": "2", "y": 3}"#).unwrap());
  private_inputs.push(serde_json::from_str::<HashMap<String, Value>>(r#"{ "x": "1" }"#).unwrap());

  let mut memory = Memory {
    rom:                ROM.to_vec(),
    curr_public_input:  z0_primary.clone(),
    curr_private_input: private_inputs[0].clone(),
  };

  let pp = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());
  // extend z0_primary/secondary with rom content
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(memory.rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

  let z0_secondary = vec![F::<G2>::ONE];

  let mut recursive_snark_option = None;

  for (idx, &op_code) in ROM.iter().enumerate() {
    info!("Step {} of ROM", idx);
    info!("opcode = {}", op_code);
    memory.curr_private_input = private_inputs[idx].clone();

    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      let rs = RecursiveSNARK::new(
        &pp,
        &memory,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .unwrap();
      info!("Instantiated RecursiveSNARK!");
      rs
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
