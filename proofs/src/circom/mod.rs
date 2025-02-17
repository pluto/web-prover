//! # Circom Module
//!
//! The `circom` module provides utilities for working with Circom circuits within the `proofs`
//! crate. It includes functionalities for handling R1CS (Rank-1 Constraint System) representations
//! of circuits, managing circuit inputs, and generating witnesses for the circuits.
//!
//! ## Modules
//!
//! - `r1cs`: Contains the implementation and utilities for working with R1CS representations of
//!   Circom circuits.
//! - `wasm_witness`: Provides functionalities for generating witnesses using WebAssembly (only
//!   available for `wasm32` target).
//! - `witness`: Contains utilities for generating witnesses for Circom circuits.
//!
//! ## Structs
//!
//! - `CircomInput`: Represents the input structure for Circom circuits, including step inputs and
//!   additional parameters.
//! - `CircuitJson`: Represents the JSON structure of a Circom circuit, including constraints,
//!   number of inputs, outputs, and variables.
//! - `CircomCircuit`: Represents a Circom circuit, including its R1CS representation and optional
//!   witness data.

use std::{
  collections::{BTreeMap, HashMap},
  env::current_dir,
  fs,
  io::{BufReader, Cursor, Read, Seek, SeekFrom},
  path::PathBuf,
  process::Command,
  sync::Arc,
};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use byteorder::{LittleEndian, ReadBytesExt};
use ff::PrimeField;
use r1cs::R1CS;
use serde::{Deserialize, Serialize};

use super::*;

pub mod r1cs;
#[cfg(target_arch = "wasm32")] pub mod wasm_witness;
pub mod witness;

/// Circom input
#[derive(Debug, Serialize, Deserialize)]
pub struct CircomInput {
  /// Step inputs
  pub step_in: Vec<String>,
  /// Extra parameters
  #[serde(flatten)]
  pub extra:   HashMap<String, Value>,
}

/// Circuit JSON
#[derive(Serialize, Deserialize)]
pub struct CircuitJson {
  /// Constraints
  pub constraints:   Vec<Vec<BTreeMap<String, String>>>,
  /// Number of inputs
  #[serde(rename = "nPubInputs")]
  pub num_inputs:    usize,
  /// Number of outputs
  #[serde(rename = "nOutputs")]
  pub num_outputs:   usize,
  /// Number of variables
  #[serde(rename = "nVars")]
  pub num_variables: usize,
}

/// Circom circuit
#[derive(Clone)]
pub struct CircomCircuit {
  /// R1CS
  pub r1cs:    Arc<R1CS>,
  /// Witness
  pub witness: Option<Vec<F<G1>>>,
}

// NOTE (Colin): This is added so we can cache only the active circuits we are using.
#[allow(clippy::derivable_impls)]
impl Default for CircomCircuit {
  fn default() -> Self { Self { r1cs: Arc::new(R1CS::default()), witness: None } }
}

impl CircomCircuit {
  /// Return the arity of the circuit ie the number of public inputs
  pub fn arity(&self) -> usize { self.r1cs.num_public_inputs }

  /// Vanilla synthesize
  ///
  /// This function synthesizes the circuit using the provided constraint system.
  ///
  /// # Arguments
  ///
  /// * `cs`: The constraint system to use for synthesis.
  /// * `z`: The witness values to use for synthesis.
  pub fn vanilla_synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    let witness = &self.witness;

    let mut vars: Vec<AllocatedNum<F<G1>>> = vec![];
    let mut z_out: Vec<AllocatedNum<F<G1>>> = vec![];
    let pub_output_count = self.r1cs.num_public_outputs;

    for i in 1..self.r1cs.num_inputs {
      // Public inputs do not exist, so we alloc, and later enforce equality from z values
      let f: F<G1> = {
        match witness {
          None => F::<G1>::ONE,
          Some(w) => w[i],
        }
      };
      let v = AllocatedNum::alloc(cs.namespace(|| format!("public_{}", i)), || Ok(f))?;

      vars.push(v.clone());
      if i <= pub_output_count {
        // public output
        z_out.push(v);
      }
    }
    for i in 0..self.r1cs.num_aux {
      // Private witness trace
      let f: F<G1> = {
        match witness {
          None => F::<G1>::ONE,
          Some(w) => w[i + self.r1cs.num_inputs],
        }
      };

      let v = AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || Ok(f))?;
      vars.push(v);
    }

    let make_lc = |lc_data: Vec<(usize, F<G1>)>| {
      let res = lc_data.iter().fold(
        LinearCombination::<F<G1>>::zero(),
        |lc: LinearCombination<F<G1>>, (index, coeff)| {
          lc + if *index > 0 {
            (*coeff, vars[*index - 1].get_variable())
          } else {
            (*coeff, CS::one())
          }
        },
      );
      res
    };
    for (i, constraint) in self.r1cs.constraints.iter().enumerate() {
      cs.enforce(
        || format!("constraint {}", i),
        |_| make_lc(constraint.0.clone()),
        |_| make_lc(constraint.1.clone()),
        |_| make_lc(constraint.2.clone()),
      );
    }

    for i in (pub_output_count + 1)..self.r1cs.num_inputs {
      cs.enforce(
        || format!("pub input enforce {}", i),
        |lc| lc + z[i - 1 - pub_output_count].get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + vars[i - 1].get_variable(),
      );
    }

    Ok(z_out)
  }
}
