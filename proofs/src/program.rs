use arecibo::{
  supernova::{PublicParams, RecursiveSNARK, TrivialTestCircuit},
  traits::snark::RelaxedR1CSSNARKTrait,
};
use builder::CircuitType;
use circom::circuit::R1CS;

use super::*;

pub fn create_public_params(r1cs: R1CS<F<<E1 as Engine>::GE>>) -> PublicParams<E1> {
  // let circuit_primary = CircomCircuit::<<E1 as Engine>::Scalar> { r1cs, witness: None };
  // let circuit_secondary = TrivialTestCircuit::<<E2 as Engine>::Scalar>::default();

  // PublicParams::setup(&circuit_primary, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())
  //   .unwrap() // nova setup
  let non_uniform_circuit = CircuitType::Parser {
    r1cs:          r1cs.clone(),
    public_input:  todo!(),
    private_input: todo!(),
    graph_bin:     todo!(),
  };
  PublicParams::setup(&non_uniform_circuit, &*S1::ck_floor(), &*S2::ck_floor())
}
