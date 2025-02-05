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
  num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use ff::PrimeField;

use super::*;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode: Program<GenericFieldElement<Fr>>,
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
      let idx = dbg!(witness.as_usize()) - dbg!(instance_variables.len());

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
    let mut witness_map: HashMap<Witness, AllocatedNum<F<G1>>> = HashMap::new();

    // First, allocate all public inputs
    let public_inputs = &self.circuit().public_inputs().0;
    for &witness in public_inputs {
      // TODO: In Circom, we hold the witness in the circuit struct as an option and match on
      // whether it is Some or not to get the value we put in here.
      let var = cs.alloc_input(|| format!("public_{}", witness.as_usize()), || Ok(F::<G1>::ONE));
      // witness_map.insert(witness, var);
    }

    // Then, allocate known private witnesses
    let private_params = &self.circuit().private_parameters;
    for &witness in private_params {
      // TODO: In Circom, we hold the witness in the circuit struct as an option and match on
      // whether it is Some or not to get the value we put in here.
      let var = cs.alloc(|| format!("private_{}", witness.as_usize()), || Ok(F::<G1>::ONE));
      // witness_map.insert(witness, var);
    }

    // c_m0 q_L0 * q_R0 + c_m1 q_L * q_R1 + ... + c_a0 (q_La0 + q_Ra1) + ... + q_c == 0
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ mul        ^^^^^^^^^^^^^ add           ^^ const

    for (gate_idx, opcode) in self.circuit().opcodes.iter().enumerate() {
      if let Opcode::AssertZero(gate) = opcode {
        let mut terms = LinearCombination::zero();

        // Handle multiplication terms
        for (mul_idx, mul_term) in gate.mul_terms.iter().enumerate() {
          let mut arr = [0u8; 32];
          arr.copy_from_slice(&mul_term.0.to_be_bytes()[..32]);
          let coeff = F::<G1>::from_repr(arr).unwrap();

          let left_var = get_or_allocate_var(
            &mut witness_map,
            mul_term.1,
            || format!("mul_{}_left_{}", gate_idx, mul_idx),
            cs,
          )?;
          let right_var = get_or_allocate_var(
            &mut witness_map,
            mul_term.2,
            || format!("mul_{}_right_{}", gate_idx, mul_idx),
            cs,
          )?;

          // Create multiplication constraint
          let mul_result = AllocatedNum::alloc(
            cs.namespace(|| format!("mul_result_{}_{}", gate_idx, mul_idx)),
            || Ok(F::<G1>::ONE), // Replace with actual computation when available
          )?;

          cs.enforce(
            || format!("mul_constraint_{}_{}", gate_idx, mul_idx),
            |lc| lc + left_var.get_variable(),
            |lc| lc + right_var.get_variable(),
            |lc| lc + mul_result.get_variable(),
          );

          terms = terms + (coeff, mul_result.get_variable());
        }

        // Handle linear combinations (add terms)
        for (add_idx, add_term) in gate.linear_combinations.iter().enumerate() {
          let mut arr = [0u8; 32];
          arr.copy_from_slice(&add_term.0.to_be_bytes()[..32]);
          let coeff = F::<G1>::from_repr(arr).unwrap();

          let var = get_or_allocate_var(
            &mut witness_map,
            add_term.1,
            || format!("add_{}_{}", gate_idx, add_idx),
            cs,
          )?;
          terms = terms + (coeff, var.get_variable());
        }

        // Add constant term if present
        if !gate.q_c.is_zero() {
          let mut arr = [0u8; 32];
          arr.copy_from_slice(&gate.q_c.to_be_bytes()[..32]);
          let const_term = F::<G1>::from_repr(arr).unwrap();
          terms = terms + (const_term, CS::one());
        }

        // Enforce final constraint: terms = 0
        cs.enforce(
          || format!("gate_constraint_{}", gate_idx),
          |lc| terms.clone(),
          |lc| lc + CS::one(),
          |lc| lc,
        );
      }
    }

    Ok(vec![]) // Return appropriate outputs if needed
  }
}

// Helper function to allocate variables in the constraint system
fn get_or_allocate_var<CS: ConstraintSystem<F<G1>>>(
  witness_map: &mut HashMap<Witness, AllocatedNum<F<G1>>>,
  witness: Witness,
  ns: impl FnOnce() -> String,
  cs: &mut CS,
) -> Result<AllocatedNum<F<G1>>, SynthesisError> {
  if let Some(var) = witness_map.get(&witness) {
    Ok(var.clone())
  } else {
    let var = AllocatedNum::alloc(
      cs.namespace(ns),
      || Ok(F::<G1>::ONE), // Replace with actual witness value
    )?;
    witness_map.insert(witness, var.clone());
    Ok(var)
  }
}
