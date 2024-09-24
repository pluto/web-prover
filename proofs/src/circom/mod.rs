use std::{
  collections::{BTreeMap, HashMap},
  env::current_dir,
  fs,
  io::{BufReader, Cursor, Read, Seek, SeekFrom},
  path::PathBuf,
  process::Command,
  sync::{Arc, Mutex},
};

use anyhow::Result;
use arecibo::{
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait},
  PublicParams,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use byteorder::{LittleEndian, ReadBytesExt};
use ff::{Field, PrimeField};
use r1cs::R1CS;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;

pub mod r1cs;
pub mod witness;

#[derive(Serialize, Deserialize)]
pub struct CircomInput {
  pub step_in: Vec<String>,

  #[serde(flatten)]
  pub extra: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize)]
pub struct CircuitJson {
  pub constraints:   Vec<Vec<BTreeMap<String, String>>>,
  #[serde(rename = "nPubInputs")]
  pub num_inputs:    usize,
  #[serde(rename = "nOutputs")]
  pub num_outputs:   usize,
  #[serde(rename = "nVars")]
  pub num_variables: usize,
}

#[derive(Clone)]
pub struct CircomCircuit {
  pub r1cs:    R1CS,
  pub witness: Option<Vec<F<G1>>>,
}

impl CircomCircuit {
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

// TODO: We can delete this eventually
impl arecibo::traits::circuit::StepCircuit<F<G1>> for CircomCircuit {
  fn arity(&self) -> usize { self.r1cs.num_public_inputs }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    // synthesize the circuit
    self.vanilla_synthesize(cs, z)
  }
}

pub fn create_public_params(r1cs: R1CS) -> PublicParams<E1> {
  let circuit_primary = CircomCircuit { r1cs, witness: None };
  let circuit_secondary = TrivialCircuit::<F<G2>>::default();

  PublicParams::setup(&circuit_primary, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())
    .unwrap() // nova setup
}
