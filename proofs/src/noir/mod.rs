use acvm::{
  acir::{
    acir_field::GenericFieldElement,
    circuit::{brillig::BrilligBytecode, Circuit, Opcode, Program},
    native_types::{Witness, WitnessMap},
  },
  blackbox_solver::StubbedBlackBoxSolver,
  pwg::ACVM,
  AcirField,
};
use ark_bn254::Fr;
use bellpepper_core::{
  num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use ff::PrimeField;
use halo2curves::serde::SerdeObject;

use super::*;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode: Program<GenericFieldElement<Fr>>,
  pub inputs:   Option<Vec<F<G1>>>,
}

impl NoirProgram {
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  pub fn solve(
    &self,
    instance_variables: &[Fr],
    witness_variables: &[Fr],
  ) -> WitnessMap<GenericFieldElement<Fr>> {
    let mut acvm = ACVM::new(
      &StubbedBlackBoxSolver(false),
      &self.circuit().opcodes,
      WitnessMap::new(),
      self.unconstrained_functions(),
      &[],
    );

    self.circuit().public_parameters.0.iter().for_each(|witness| {
      let f = GenericFieldElement::<Fr>::from_repr(instance_variables[witness.as_usize()]);
      acvm.overwrite_witness(*witness, f);
    });

    // write witness values for external_inputs
    self.circuit().private_parameters.iter().for_each(|witness| {
      let idx = witness.as_usize() - instance_variables.len();

      let f = GenericFieldElement::<Fr>::from_repr(witness_variables[idx]);
      acvm.overwrite_witness(*witness, f);
    });
    let _status = acvm.solve();
    acvm.finalize()
  }

  pub fn vanilla_synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    let mut witness_map: HashMap<Witness, Variable> = match &self.inputs {
      Some(inputs) => {
        let mut acvm = ACVM::new(
          &StubbedBlackBoxSolver(false),
          &self.circuit().opcodes,
          WitnessMap::new(),
          self.unconstrained_functions(),
          &[],
        );

        // self.circuit().public_parameters.0.iter().for_each(|witness| {
        //   let f = GenericFieldElement::<Fr>::fr(&inputs[witness.as_usize()].to_bytes());
        //   acvm.overwrite_witness(*witness, f);
        // });

        // // write witness values for external_inputs
        // self.circuit().private_parameters.iter().for_each(|witness| {
        //   let idx = witness.as_usize() - instance_variables.len();

        //   let f = GenericFieldElement::<Fr>::from_repr(witness_variables[idx]);
        //   acvm.overwrite_witness(*witness, f);
        // });
        // let _status = acvm.solve();
        // acvm.finalize()

        HashMap::new()
      },
      None => HashMap::new(),
    };

    // First, allocate all public inputs
    let public_inputs = &self.circuit().public_inputs().0;
    for &witness in public_inputs {
      // TODO: In Circom, we hold the witness in the circuit struct as an option and match on
      // whether it is Some or not to get the value we put in here.
      // TODO: could use alloc_empty_*
      let var =
        cs.alloc_input(|| format!("public_{}", witness.as_usize()), || Ok(F::<G1>::ONE)).unwrap();
      witness_map.insert(witness, var);
    }

    // Then, allocate known private witnesses
    let private_params = &self.circuit().private_parameters;
    for &witness in private_params {
      // TODO: In Circom, we hold the witness in the circuit struct as an option and match on
      // whether it is Some or not to get the value we put in here.
      let var =
        cs.alloc(|| format!("private_{}", witness.as_usize()), || Ok(F::<G1>::ONE)).unwrap();
      witness_map.insert(witness, var);
    }

    // c_m0 q_L0 * q_R0 + c_m1 q_L * q_R1 + ... + c_a0 (q_La0 + q_Ra1) + ... + q_c == 0
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ mul        ^^^^^^^^^^^^^ add           ^^ const

    // Process gates
    for (gate_idx, opcode) in self.circuit().opcodes.iter().enumerate() {
      if let Opcode::AssertZero(gate) = opcode {
        let mut left_terms = LinearCombination::zero();
        let mut right_terms = LinearCombination::zero();

        // Handle multiplication terms more efficiently
        for mul_term in &gate.mul_terms {
          let coeff = {
            let bytes = mul_term.0.to_be_bytes();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[..32]);
            F::<G1>::from_repr(arr).unwrap()
          };

          let left_var = get_or_allocate_var(
            &mut witness_map,
            mul_term.1,
            || format!("mul_left_{}", gate_idx),
            cs,
          )?;
          let right_var = get_or_allocate_var(
            &mut witness_map,
            mul_term.2,
            || format!("mul_right_{}", gate_idx),
            cs,
          )?;

          // Directly combine into linear combination
          left_terms = left_terms + (coeff, left_var);
          right_terms = right_terms + (F::<G1>::one(), right_var);
        }

        // Handle linear combinations more efficiently
        let mut final_terms = LinearCombination::zero();
        for add_term in &gate.linear_combinations {
          let coeff = {
            let bytes = add_term.0.to_be_bytes();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[..32]);
            F::<G1>::from_repr(arr).unwrap()
          };
          let var =
            get_or_allocate_var(&mut witness_map, add_term.1, || format!("add_{}", gate_idx), cs)?;
          final_terms = final_terms + (coeff, var);
        }

        // Handle constant term
        if !gate.q_c.is_zero() {
          let bytes = gate.q_c.to_be_bytes();
          let mut arr = [0u8; 32];
          arr.copy_from_slice(&bytes[..32]);
          let const_coeff = F::<G1>::from_repr(arr).unwrap();
          // SUBTRACT HERE TO MOVE TO LHS: Az o Bz - Cz = 0
          final_terms = final_terms - (const_coeff, Variable::new_unchecked(Index::Input(0)));
        }

        // Enforce: left_terms * right_terms + final_terms = 0
        cs.enforce(
          || format!("gate_{}", gate_idx),
          |lc| left_terms.clone(),
          |lc| right_terms.clone(),
          |lc| final_terms,
        );
      }
    }

    Ok(vec![]) // Return appropriate outputs if needed
  }
}

// Helper function to allocate variables in the constraint system
fn get_or_allocate_var<CS: ConstraintSystem<F<G1>>>(
  witness_map: &mut HashMap<Witness, Variable>,
  witness: Witness,
  ns: impl FnOnce() -> String,
  cs: &mut CS,
) -> Result<Variable, SynthesisError> {
  if let Some(var) = witness_map.get(&witness) {
    Ok(var.clone())
  } else {
    let var = AllocatedNum::alloc(
      cs.namespace(ns),
      || Ok(F::<G1>::ONE), // Replace with actual witness value
    )?;
    witness_map.insert(witness, var.get_variable());
    Ok(var.get_variable())
  }
}

fn convert_to_halo2_field(f: GenericFieldElement<Fr>) -> F<G1> {
  let bytes = f.to_be_bytes();
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes[..32]);
  arr.reverse();
  F::<G1>::from_repr(arr).unwrap()
}

// why the fuck is this fucking big endian?
fn convert_to_acir_field(f: F<G1>) -> GenericFieldElement<Fr> {
  let mut bytes = f.to_bytes();
  bytes.reverse();
  GenericFieldElement::from_be_bytes_reduce(&bytes)
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use client_side_prover::bellpepper::shape_cs::ShapeCS;

  use super::*;

  // This is fucking stupid. Why can't we all be sane. i'm not anymore
  #[test]
  fn test_conversions() {
    let f = F::<G1>::from(5);
    let acir_f = convert_to_acir_field(f);
    assert_eq!(acir_f, GenericFieldElement::from_repr(Fr::from(5)));

    let f = GenericFieldElement::from_repr(Fr::from(3));
    let halo2_f = convert_to_halo2_field(f);
    assert_eq!(halo2_f, F::<G1>::from(3));
  }

  // TODO: Should probably have a check here, but I believe this is correct!
  #[test]
  fn test_mock_noir_circuit() {
    // Circuit definition:
    // x_0 * w_0 + w_1 + 2 == 0
    let json_path = Path::new("./mock").join(format!("mock.json"));
    let noir_json = std::fs::read(&json_path).unwrap();
    let program = NoirProgram::new(&noir_json);

    let mut cs = ShapeCS::<E1>::new();

    program.vanilla_synthesize(&mut cs, &[]);

    dbg!(cs.num_constraints());

    dbg!(&cs.constraints);
    dbg!(cs.num_aux());
    dbg!(cs.num_inputs());
  }

  #[test]
  fn test_mock_noir_solve() {
    // Circuit definition:
    // x_0 * w_0 + w_1 + 2 == 0
    let json_path = Path::new("./mock").join(format!("mock.json"));
    let noir_json = std::fs::read(&json_path).unwrap();

    let program = NoirProgram::new(&noir_json);
    // NOTE: Don't need to have the instance assignment set to 1 here, so we need a method to handle
    // this if we were sticking with this CS.
    let witness_map = program.solve(&[Fr::from(2)], &[Fr::from(3), -Fr::from(8)]);

    let mut cs = ShapeCS::<E1>::new();

    program.vanilla_synthesize(&mut cs, &[]);
  }
}
