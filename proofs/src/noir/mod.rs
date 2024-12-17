use std::collections::HashMap;

use acvm::{
  acir::{
    acir_field::GenericFieldElement,
    circuit::{Circuit, Program},
    native_types::{Witness as AcvmWitness, WitnessMap},
  },
  blackbox_solver::StubbedBlackBoxSolver,
  pwg::ACVM,
  AcirField,
};
use bellpepper_core::{num::AllocatedNum, SynthesisError};
use client_side_prover::supernova::StepCircuit;
// use ark_ff::PrimeField;
// use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
// use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
// use folding_schemes::{frontend::FCircuit, utils::PathOrBin, Error};
use serde::{self, Deserialize, Serialize};

use super::*;

// use self::bridge::AcirCircuitSonobe;

mod bridge;

// TODO (autoparallel): I'm pretty confident on my understanding of the `state_len` and
// `external_inputs_len` but not 100%.
#[derive(Clone, Debug)]
pub struct NoirCircuit {
  // NOTE (autoparallel): For now just use bn254 scalar
  pub circuit:             Circuit<GenericFieldElement<ark_bn254::Fr>>,
  pub witness:             Option<Vec<F<G1>>>,
  /// The number of `step_in`/`step_out` variables
  pub state_len:           usize,
  /// The number of private input variables
  pub external_inputs_len: usize,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProgramArtifactGeneric {
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode: Program<GenericFieldElement<ark_bn254::Fr>>,
}

impl NoirCircuit {
  // TODO (autoparallel): In the future remove the unwraps
  pub fn new(
    bytecode: Vec<u8>,
    state_len: usize,
    external_inputs_len: usize,
  ) -> Result<Self, ProofError> {
    // let (source, state_len, external_inputs_len) = params;
    let program: ProgramArtifactGeneric = serde_json::from_slice(&bytecode).unwrap();
    let circuit: Circuit<GenericFieldElement<ark_bn254::Fr>> =
      program.bytecode.functions[0].clone();
    let ivc_input_length = circuit.public_parameters.0.len();
    let ivc_return_length = circuit.return_values.0.len();

    assert!(
      ivc_input_length == ivc_return_length,
      "IVC input: {ivc_input_length:?}\nIVC output: {ivc_return_length:?}"
    );

    Ok(Self { circuit, state_len, external_inputs_len, witness: None })
  }

  pub fn arity(&self) -> usize { self.state_len }

  // NOTE (autoparallel): We could include the program counter in this input (we also could with
  // circom)

  // TODO: I think this was actually confused with witness solving to some extent tbh. Trying to
  // connect the dots
  pub fn vanilla_synthesize<CS: bellpepper_core::ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[bellpepper_core::num::AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    let mut acvm =
      ACVM::new(&StubbedBlackBoxSolver, &self.circuit.opcodes, WitnessMap::new(), &[], &[]);

    let mut already_assigned_witness_values = HashMap::new();

    self
      .circuit
      .public_parameters
      .0
      .iter()
      .map(|witness| {
        let idx: usize = witness.as_usize();
        let witness = AcvmWitness(witness.witness_index());
        already_assigned_witness_values.insert(witness, &z[idx]);
        let val = z[idx].get_value().unwrap(); // TODO (colin): unwrapping here

        let f = GenericFieldElement::<ark_bn254::Fr>::from_be_bytes_reduce(
          &val.to_bytes().into_iter().rev().collect::<Vec<u8>>(),
        );

        acvm.overwrite_witness(witness, f);
        Ok(())
      })
      .collect::<Result<Vec<()>, SynthesisError>>()?;

    // write witness values for external_inputs
    let external_inputs = match self.witness {
      // Mimic what we do in the `CircomCircuit` case so our witness looks the same
      Some(w) => &w[self.state_len..],
      // If `None`, we must not have set the witness and this is only for the initialization, so we
      // just make all the inputs zero
      None => &vec![F::<G1>::ZERO; self.circuit.private_parameters.len()],
    };
    self
      .circuit
      .private_parameters
      .iter()
      .map(|witness| {
        let idx = witness.as_usize() - z.len();
        let witness = AcvmWitness(witness.witness_index());

        let val = external_inputs[idx];

        // Push this into the ACVM
        // TODO (autoparellel): We might not want to do the actual witness calculation if the
        // `self.witness == None`
        let f = GenericFieldElement::<ark_bn254::Fr>::from_be_bytes_reduce(
          &val.to_bytes().into_iter().rev().collect::<Vec<u8>>(),
        );
        acvm.overwrite_witness(witness, f);

        // Push this onto the bellpepper CS
        let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", idx)), || Ok(val))?;
        already_assigned_witness_values.insert(witness, &v);
        Ok(())
      })
      .collect::<Result<Vec<()>, SynthesisError>>()?;

    // TODO (autoparallel): This is where I'm not sure we need to actually solve the witness
    // // computes the witness
    // let _ = acvm.solve();
    // let witness_map = acvm.finalize();

    // // get the z_{i+1} output state
    // let assigned_z_i1 = self
    //   .circuit
    //   .return_values
    //   .0
    //   .iter()
    //   .map(|witness| {
    //     let noir_field_element =
    //       witness_map.get(witness).ok_or(SynthesisError::AssignmentMissing)?;
    //     FpVar::<F>::new_witness(cs.clone(), || Ok(noir_field_element.into_repr()))
    //   })
    //   .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()?;

    // // initialize circuit and set already assigned values
    // let mut acir_circuit = AcirCircuitSonobe::from((&self.circuit, witness_map));
    // acir_circuit.already_assigned_witnesses = already_assigned_witness_values;

    // acir_circuit.generate_constraints(cs.clone())?;

    // Ok(assigned_z_i1)
  }
}

// impl NoirCircuit {
//   fn step_native(
//     &self,
//     _i: usize,
//     z_i: Vec<F>,
//     external_inputs: Vec<F>, // inputs that are not part of the state
//   ) -> Result<Vec<F>, Error> {
//     let mut acvm =
//       ACVM::new(&StubbedBlackBoxSolver, &self.circuit.opcodes, WitnessMap::new(), &[], &[]);

//     self
//       .circuit
//       .public_parameters
//       .0
//       .iter()
//       .map(|witness| {
//         let idx: usize = witness.as_usize();
//         let value = z_i[idx].to_string();
//         let witness = AcvmWitness(witness.witness_index());
//         let f =
//           GenericFieldElement::<F>::try_from_str(&value).ok_or(SynthesisError::Unsatisfiable)?;
//         acvm.overwrite_witness(witness, f);
//         Ok(())
//       })
//       .collect::<Result<Vec<()>, SynthesisError>>()?;

//     // write witness values for external_inputs
//     self
//       .circuit
//       .private_parameters
//       .iter()
//       .map(|witness| {
//         let idx = witness.as_usize() - z_i.len();
//         let value = external_inputs[idx].to_string();
//         let f =
//           GenericFieldElement::<F>::try_from_str(&value).ok_or(SynthesisError::Unsatisfiable)?;
//         acvm.overwrite_witness(AcvmWitness(witness.witness_index()), f);
//         Ok(())
//       })
//       .collect::<Result<Vec<()>, SynthesisError>>()?;
//     let _ = acvm.solve();

//     let witness_map = acvm.finalize();

//     // get the z_{i+1} output state
//     let assigned_z_i1 = self
//       .circuit
//       .return_values
//       .0
//       .iter()
//       .map(|witness| {
//         let noir_field_element =
//           witness_map.get(witness).ok_or(SynthesisError::AssignmentMissing)?;
//         Ok(noir_field_element.into_repr())
//       })
//       .collect::<Result<Vec<F>, SynthesisError>>()?;

//     Ok(assigned_z_i1)
//   }

//   fn generate_step_constraints(
//     &self,
//     cs: ConstraintSystemRef<F>,
//     z_i: Vec<FpVar<F>>,
//     external_inputs: Vec<FpVar<F>>, // inputs that are not part of the state
//   ) -> Result<Vec<FpVar<F>>, SynthesisError> {
//   }
// }

// #[cfg(test)]
// mod tests {
//   use std::env;

//   use ark_bn254::Fr;

//   //   use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
//   //   use ark_relations::r1cs::ConstraintSystem;
//   //   use folding_schemes::{frontend::FCircuit, Error};
//   use crate::noir::NoirFCircuit;

//   #[test]
//   fn test_step_native() -> Result<(), Error> {
//     let cur_path = env::current_dir()?;
//     let noirfcircuit = NoirFCircuit::new((
//       cur_path.join("src/noir/test_folder/test_circuit/target/test_circuit.json").into(),
//       2,
//       2,
//     ))?;
//     let inputs = vec![Fr::from(2), Fr::from(5)];
//     let res = noirfcircuit.step_native(0, inputs.clone(), inputs);
//     assert!(res.is_ok());
//     assert_eq!(res?, vec![Fr::from(4), Fr::from(25)]);
//     Ok(())
//   }

//   #[test]
//   fn test_step_constraints() -> Result<(), Error> {
//     let cs = ConstraintSystem::<Fr>::new_ref();
//     let cur_path = env::current_dir()?;
//     let noirfcircuit = NoirFCircuit::new((
//       cur_path.join("src/noir/test_folder/test_circuit/target/test_circuit.json").into(),
//       2,
//       2,
//     ))?;
//     let inputs = vec![Fr::from(2), Fr::from(5)];
//     let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs.clone()))?;
//     let external_inputs = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs))?;
//     let output = noirfcircuit.generate_step_constraints(cs.clone(), 0, z_i, external_inputs)?;
//     assert_eq!(output[0].value()?, Fr::from(4));
//     assert_eq!(output[1].value()?, Fr::from(25));
//     Ok(())
//   }

//   #[test]
//   fn test_step_constraints_no_external_inputs() -> Result<(), Error> {
//     let cs = ConstraintSystem::<Fr>::new_ref();
//     let cur_path = env::current_dir()?;
//     let noirfcircuit = NoirFCircuit::new((
//       cur_path
//         .join("src/noir/test_folder/test_no_external_inputs/target/test_no_external_inputs.json")
//         .into(),
//       2,
//       0,
//     ))?;
//     let inputs = vec![Fr::from(2), Fr::from(5)];
//     let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs.clone()))?;
//     let external_inputs = vec![];
//     let output = noirfcircuit.generate_step_constraints(cs.clone(), 0, z_i, external_inputs)?;
//     assert_eq!(output[0].value()?, Fr::from(4));
//     assert_eq!(output[1].value()?, Fr::from(25));
//     Ok(())
//   }
// }
