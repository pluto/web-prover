use super::*;

// TODO:Likely need some function that allows for initialization from a list of data like a "setup"
// or something

#[derive(Clone)]
pub struct RomCircuit<C: Circuit> {
  pub circuit:       C,
  pub circuit_index: usize,
  pub rom_size:      usize,
  pub nivc_io:       Option<Vec<F<G1>>>,
  pub private_input: Option<HashMap<String, Value>>,
}

// TODO: This name is honestly overused, maybe should just enforce the trait itself takes Clone +...
pub trait Circuit: Clone + Send + Sync {
  type WitnessGenerator: Clone + Send + Sync;
  type Constructor;

  fn construct(constructor: Self::Constructor) -> Self;

  fn arity(&self) -> usize;

  fn vanilla_synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError>;

  fn witness_generator_type(&self) -> Option<&Self::WitnessGenerator>;
}
