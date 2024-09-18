use arecibo::supernova::{NonUniformCircuit, StepCircuit, TrivialTestCircuit};

use super::*;

pub enum CircuitType {
  Parser(C1),
  Extractor(C1),
}

impl StepCircuit<F<G1>> for CircomCircuit<F<G1>> {
  fn arity(&self) -> usize { todo!() }

  fn circuit_index(&self) -> usize { todo!() }

  fn synthesize<CS: bellpepper_core::ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&bellpepper_core::num::AllocatedNum<F<G1>>>,
    z: &[bellpepper_core::num::AllocatedNum<F<G1>>],
  ) -> Result<
    (
      Option<bellpepper_core::num::AllocatedNum<F<G1>>>,
      Vec<bellpepper_core::num::AllocatedNum<F<G1>>>,
    ),
    bellpepper_core::SynthesisError,
  > {
    todo!()
  }
}

impl NonUniformCircuit<E1> for CircuitType {
  type C1 = C1;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { todo!() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 { todo!() }

  fn secondary_circuit(&self) -> Self::C2 { todo!() }
}
