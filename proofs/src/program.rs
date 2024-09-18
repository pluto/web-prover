use std::{marker::PhantomData, time::Instant};

use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::{circuit::R1CS, r1cs::load_r1cs};
use handler::map_private_inputs;
use serde_json::json;

use super::*;

const ROM: &[u64] = &[0, 0];
const PARSER_R1CS_PATH: &str = "parse_fold_batch.r1cs";

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};
use circom::compute_witness;

struct Memory {
  rom:                Vec<u64>,
  curr_public_input:  Vec<String>,
  curr_private_input: HashMap<String, Value>,
  graph_bin:          Vec<u8>,
}

#[derive(Clone)]
pub enum CircuitSelector {
  Parser(C1), /*   {
               *     r1cs:      R1CS<F<G1>>,
               *     // public_input:  Vec<String>,
               *     // private_input: HashMap<String, Value>,
               *     graph_bin: Vec<u8>,
               *   }, */
}

// TODO: This is a total dummy impl
impl NonUniformCircuit<E1> for Memory {
  type C1 = CircuitSelector;
  type C2 = TrivialTestCircuit<F<G2>>;

  /// TODO: Afaik, total number of circuits in the enum
  fn num_circuits(&self) -> usize { 1 }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    println!("checking primary circuit with index: {circuit_index}");
    let r1cs = load_r1cs(&PathBuf::from(PARSER_R1CS_PATH));
    let witness = compute_witness(
      self.curr_public_input.clone(),
      self.curr_private_input.clone(),
      &self.graph_bin,
    );
    println!("got witness");
    match circuit_index {
      0 => CircuitSelector::Parser(CircomCircuit::<F<G1>> { r1cs, witness: Some(witness) }),
      _ => panic!("Incorrect circuit index provided!"),
    }
  }

  fn secondary_circuit(&self) -> Self::C2 { TrivialTestCircuit::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

// TODO: This field used here might be wrong
impl SNStepCircuit<F<G1>> for CircuitSelector {
  fn arity(&self) -> usize {
    match self {
      Self::Parser(circuit) => circuit.arity(),
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::Parser(_circuit) => 0, // TODO: i believe index is used for z_i
    }
  }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>, // TODO: idk how to use the program counter lol
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    println!("inside of synthesize with pc: {pc:?}");
    match self {
      Self::Parser(circuit) => Ok((pc.cloned(), circuit.vanilla_synthesize(cs, z)?)), /* TODO: certainly justcloning the pc is stupid */
    }
  }
}

pub fn run_program(circuit_data: CircuitData) {
  info!("inside of supernova");
  let r1cs = load_r1cs(&circuit_data.r1cs_path);
  //   dbg!(r1cs.clone().num_inputs); // prints
  //   let circuit = CircomCircuit::<F<G1>> { r1cs: r1cs.clone(), witness: None }; // TODO: idk how
  // to handle witness yet   let circuit_selector = CircuitSelector::Parser(circuit);
  let graph_bin = std::fs::read(&circuit_data.graph_path).unwrap(); // graph data for parser probably, this is getting jankj
  let z0_primary: Vec<String> = circuit_data.init_step_in.iter().map(u64::to_string).collect();
  let z0_primary_fr: Vec<F<G1>> =
    circuit_data.init_step_in.iter().map(|val| F::<G1>::from(*val)).collect();

  // Map `private_input`
  let private_inputs = map_private_inputs(&circuit_data);

  let memory = Memory {
    rom:                ROM.to_vec(),
    curr_public_input:  z0_primary.clone(),
    graph_bin:          graph_bin.clone(),
    curr_private_input: private_inputs[0].clone(),
  };

  let pp = PublicParams::setup(&memory, &*S1::ck_floor(), &*S2::ck_floor());

  let z0_secondary = vec![F::<G2>::ZERO];

  let mut recursive_snark_option: Option<RecursiveSNARK<E1>> = None;

  for (idx, &op_code) in ROM.iter().enumerate() {
    info!("Step {} of ROM", idx);
    info!("opcode = {}", op_code);
    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        &pp,
        &memory,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary_fr,
        &z0_secondary,
      )
      .unwrap()
    });

    info!("Proving single step...");
    let start = Instant::now();
    recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary).unwrap();
    info!("Single step proof took: {:?}", start.elapsed());

    recursive_snark.verify(&pp, &z0_primary_fr, &z0_secondary).unwrap();

    recursive_snark_option = Some(recursive_snark)
  }

  assert!(recursive_snark_option.is_some());
}
