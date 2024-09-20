use std::{collections::BTreeMap, str};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use serde::{Deserialize, Serialize};

use super::*;

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

pub type Constraint<Fr> = (Vec<(usize, Fr)>, Vec<(usize, Fr)>, Vec<(usize, Fr)>);

#[derive(Clone)]
pub struct CircomCircuit {
  pub r1cs:    R1CS,
  pub witness: Option<Vec<F<G1>>>,
}

impl CircomCircuit {
  pub fn get_public_outputs(&self) -> Vec<F<G1>> {
    // NOTE: assumes exactly half of the (public inputs + outputs) are outputs
    let pub_output_count = (self.r1cs.num_inputs - 1) / 2;
    let mut z_out: Vec<F<G1>> = vec![];
    for i in 1..self.r1cs.num_inputs {
      // Public inputs do not exist, so we alloc, and later enforce equality from z values
      let f: F<G1> = {
        match &self.witness {
          None => F::<G1>::ONE,
          Some(w) => w[i],
        }
      };

      if i <= pub_output_count {
        // public output
        z_out.push(f);
      }
    }

    z_out
  }

  pub fn vanilla_synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    let witness = &self.witness;

    let mut vars: Vec<AllocatedNum<F<G1>>> = vec![];
    let mut z_out: Vec<AllocatedNum<F<G1>>> = vec![];
    let pub_output_count = (self.r1cs.num_inputs - 1) / 2;

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

impl arecibo::traits::circuit::StepCircuit<F<G1>> for CircomCircuit {
  fn arity(&self) -> usize { (self.r1cs.num_inputs - 1) / 2 }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    // synthesize the circuit
    self.vanilla_synthesize(cs, z)
  }
}
