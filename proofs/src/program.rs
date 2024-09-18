use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::snark::RelaxedR1CSSNARKTrait,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::{
  circuit::{self, R1CS},
  r1cs::load_r1cs,
};

use super::*;

const ROM: &[u64] = &[1, 1, 1, 1];

use arecibo::supernova::{NonUniformCircuit, StepCircuit};
use circom::compute_witness;

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
impl NonUniformCircuit<E1> for CircuitSelector {
  type C1 = C1;
  type C2 = TrivialTestCircuit<F<G2>>;

  /// TODO: Afaik, total number of circuits in the enum
  fn num_circuits(&self) -> usize { 2 }

  fn primary_circuit(&self, _circuit_index: usize) -> Self::C1 {
    // Always assume we're using parser just for example, in future use circuit index
    match self {
      Self::Parser(circuit) => circuit.clone(),
    }
  }

  fn secondary_circuit(&self) -> Self::C2 { TrivialTestCircuit::default() }
}

// TODO: This field used here might be wrong
impl StepCircuit<F<G1>> for CircuitSelector {
  fn arity(&self) -> usize {
    match self {
      Self::Parser(circuit) => circuit.arity(),
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::Parser(circuit) => circuit.circuit_index(),
    }
  }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    match self {
      Self::Parser(circuit) => circuit.synthesize(cs, pc, z),
    }
  }
}

pub fn create_public_params(
  r1cs: R1CS<F<G1>>,
  public_input: Vec<String>,
  private_input: HashMap<String, Value>,
  graph_data: &[u8],
) -> PublicParams<E1> {
  let witness = compute_witness(public_input, private_input, graph_data);
  let non_uniform_circuit = CircuitSelector::Parser(CircomCircuit::<F<G1>> {
    r1cs:    r1cs.clone(),
    witness: Some(witness),
  });
  PublicParams::setup(&non_uniform_circuit, &*S1::ck_floor(), &*S2::ck_floor())
}

pub fn run_program(circuit_data: CircuitData) {
  let r1cs = load_r1cs(&circuit_data.r1cs_path);
  let circuit = CircomCircuit::<F<G1>> { r1cs: r1cs.clone(), witness: None }; // TODO: idk how to handle witness yet
  let circuit_selector = CircuitSelector::Parser(circuit);
  let graph_data = std::fs::read(circuit_data.graph_path).unwrap();

  let pp = create_public_params(
    r1cs,
    circuit_data.init_step_in.iter().map(u64::to_string).collect(),
    circuit_data.private_input,
    &graph_data,
  );

  // extend z0_primary with ROM
  let mut z0_primary = vec![F::<G1>::ONE];
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(ROM.iter().map(|opcode| F::<G1>::from(*opcode)));

  // extend z0 secondary with ROM? (not sure i understand this)
  let z0_secondary = vec![F::<G2>::ONE];

  let mut recursive_snark_option: Option<RecursiveSNARK<E1>> = None;

  for &op_code in ROM.iter() {
    let circuit_primary = circuit_selector.primary_circuit(op_code as usize);
    let circuit_secondary = circuit_selector.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        &pp,
        &circuit_selector,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .unwrap()
    });

    recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary).unwrap();
    recursive_snark
      .verify(&pp, &z0_primary, &z0_secondary)
    //   .map_err(|err| {
    //     print_constraints_name_on_error_index(
    //       &err,
    //       &pp,
    //       &circuit_primary,
    //       &circuit_secondary,
    //       test_rom.num_circuits(),
    //     )
    //   })
      .unwrap();

    recursive_snark_option = Some(recursive_snark)
  }

  assert!(recursive_snark_option.is_some());
}
