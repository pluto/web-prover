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
}

// impl ConstraintSynthesizer<Fr> for NoirProgram {
//   fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
//     let mut witness_map: HashMap<Witness, Variable> = HashMap::new();

//     // First, allocate all public inputs
//     let public_inputs = &self.circuit().public_inputs().0;
//     for &witness in public_inputs {
//       let var = cs.new_input_variable(|| Ok(Fr::ZERO))?;
//       witness_map.insert(witness, var);
//     }

//     // Then, allocate known private witnesses
//     let private_params = &self.circuit().private_parameters;
//     for &witness in private_params {
//       let var = cs.new_witness_variable(|| Ok(Fr::ZERO))?;
//       witness_map.insert(witness, var);
//     }

//     // c_m0 q_L0 * q_R0 + c_m1 q_L * q_R1 + ... + c_a0 (q_La0 + q_Ra1) + ... + q_c == 0
//     //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ mul        ^^^^^^^^^^^^^ add           ^^ const

//     for opcode in &self.circuit().opcodes {
//       if let Opcode::AssertZero(gate) = opcode {
//         let mut left_terms = LinearCombination::<Fr>::new();
//         let mut right_terms = LinearCombination::<Fr>::new();
//         let mut output_terms = LinearCombination::<Fr>::new();

//         // Handle multiplication terms
//         for mul_term in &gate.mul_terms {
//           let coeff = Fr::from(mul_term.0.into_repr());
//           let left_var = allocate_variable(&mut witness_map, mul_term.1, &cs)?;
//           let right_var = allocate_variable(&mut witness_map, mul_term.2, &cs)?;

//           left_terms += (coeff, left_var);
//           right_terms += (Fr::ONE, right_var);
//         }

//         // Handle linear combinations (add terms)
//         for add_term in &gate.linear_combinations {
//           let coeff = Fr::from(add_term.0.into_repr());
//           let var = allocate_variable(&mut witness_map, add_term.1, &cs)?;

//           // Add to the output terms
//           output_terms += (coeff, var);
//         }

//         // Add constant term if present
//         if !gate.q_c.is_zero() {
//           output_terms += (Fr::from(gate.q_c.into_repr()), Variable::One);
//         }

//         // The constraint becomes: left_terms * right_terms + output_terms = 0
//         //                                                         Az o Bz = Cz
//         cs.enforce_constraint(left_terms, right_terms, -output_terms)?;
//       }
//       if let Opcode::MemoryInit { .. } | Opcode::MemoryOp { .. } = opcode {
//         panic!("Memory Opcode was used! This is not currently supported.");
//       }
//     }

//     Ok(())
//   }
// }

// // Helper function to allocate variables in the constraint system
// fn allocate_variable(
//   witness_map: &mut HashMap<Witness, Variable>,
//   witness: Witness,
//   cs: &ConstraintSystemRef<Fr>,
// ) -> ark_relations::r1cs::Result<Variable> {
//   if let Some(&var) = witness_map.get(&witness) {
//     Ok(var)
//   } else {
//     // Create a new variable without needing concrete witness values
//     let var = cs.new_witness_variable(|| Ok(Fr::ZERO))?;
//     witness_map.insert(witness, var);
//     Ok(var)
//   }
// }
