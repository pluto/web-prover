use arecibo::supernova::{NonUniformCircuit, StepCircuit, TrivialTestCircuit};
use circom::{circuit::R1CS, compute_witness};

use super::*;

pub enum CircuitType {
  Parser {
    r1cs:          R1CS<F<G1>>,
    public_input:  Vec<String>,
    private_input: HashMap<String, Value>,
    graph_bin:     Vec<u8>,
  },
  Extractor(C1),
}

// TODO: This is a total dummy impl
impl NonUniformCircuit<E1> for CircuitType {
  type C1 = C1;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { 4 }

  fn primary_circuit(&self, _circuit_index: usize) -> Self::C1 {
    // Always assume we're using parser just for example, in future use circuit index
    if let CircuitType::Parser { r1cs, public_input, private_input, graph_bin } = self {
      let witness =
        compute_witness(public_input.clone(), private_input.clone(), graph_bin.as_slice());
      CircomCircuit::<F<G1>> { r1cs: r1cs.clone(), witness: Some(witness) }
    } else {
      panic!()
    }
  }

  fn secondary_circuit(&self) -> Self::C2 { TrivialTestCircuit::default() }
}
