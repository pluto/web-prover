use super::*;

// TODO:Likely need some function that allows for initialization from a list of data like a "setup"
// or something

#[derive(Clone)]
pub struct RomCircuit<C: Circuit> {
  pub circuit:                C,
  pub circuit_index:          usize,
  pub rom_size:               usize,
  pub nivc_io:                Option<Vec<F<G1>>>,
  pub private_input:          Option<HashMap<String, Value>>,
  pub witness_generator_type: C::WitnessGenerator,
}

// TODO: This name is honestly overused, maybe should just enforce the trait itself takes Clone +...
pub trait Circuit {
  type WitnessGenerator: Clone + Send + Sync;

  fn arity(&self) -> usize;
  fn vanilla_synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError>;
}
