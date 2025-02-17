//! # Utils Module
//!
//! The `utils` module contains utility functions used throughout the proof system.
//!
//! ## Functions
//!
//! - `next_rom_index_and_pc`: Computes the next ROM index and program counter.
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  LinearCombination,
};
use itertools::Itertools;
use num_bigint::BigInt;

use super::*;
use crate::circom::CircomInput;

/// Computes the next ROM index and program counter.
#[allow(clippy::type_complexity)]
pub fn next_rom_index_and_pc<CS: ConstraintSystem<F<G1>>>(
  cs: &mut CS,
  rom_index: &AllocatedNum<F<G1>>,
  allocated_rom: &[AllocatedNum<F<G1>>],
  pc: &AllocatedNum<F<G1>>,
) -> Result<(AllocatedNum<F<G1>>, AllocatedNum<F<G1>>), SynthesisError> {
  // Compute a selector for the current rom_index in allocated_rom
  let current_rom_selector =
    get_selector_vec_from_index(cs.namespace(|| "rom selector"), rom_index, allocated_rom.len())?;

  // Enforce that allocated_rom[rom_index] = pc
  for (rom, bit) in allocated_rom.iter().zip_eq(current_rom_selector.iter()) {
    // if bit = 1, then rom = pc
    // bit * (rom - pc) = 0
    cs.enforce(
      || "enforce bit = 1 => rom = pc",
      |lc| lc + &bit.lc(CS::one(), F::<G1>::ONE),
      |lc| lc + rom.get_variable() - pc.get_variable(),
      |lc| lc,
    );
  }

  // Get the index of the current rom, or the index of the invalid rom if no match
  let current_rom_index = current_rom_selector
    .iter()
    .position(|bit| bit.get_value().is_some_and(|v| v))
    .unwrap_or_default();
  let next_rom_index = current_rom_index + 1;

  let rom_index_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next rom index"), || {
    F::<G1>::from(next_rom_index as u64)
  });
  cs.enforce(
    || " rom_index + 1 - next_rom_index_num = 0",
    |lc| lc,
    |lc| lc,
    |lc| lc + rom_index.get_variable() + CS::one() - rom_index_next.get_variable(),
  );

  // Allocate the next pc without checking.
  // The next iteration will check whether the next pc is valid.
  let pc_next = AllocatedNum::alloc(cs.namespace(|| "next pc"), || {
    let next_value = allocated_rom
      .get(next_rom_index)
      .and_then(|v| v.get_value())
      .and_then(|value| if value == F::<G1>::from(u64::MAX) { None } else { Some(value) });

    let current_value = allocated_rom
      .get(current_rom_index)
      .and_then(|v| v.get_value())
      .ok_or(SynthesisError::AssignmentMissing)?;

    Ok(next_value.unwrap_or(current_value))
  })?;

  Ok((rom_index_next, pc_next))
}

/// Computes the selector vector from the given index.
pub fn get_selector_vec_from_index<CS: ConstraintSystem<F<G1>>>(
  mut cs: CS,
  target_index: &AllocatedNum<F<G1>>,
  num_indices: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  // TODO (Colin): This breaks currently with the hacky way of handling circuit in pp
  // assert_ne!(num_indices, 0);

  // Compute the selector vector non-deterministically
  let selector = (0..num_indices)
    .map(|idx| {
      // b <- idx == target_index
      Ok(Boolean::Is(AllocatedBit::alloc(
        cs.namespace(|| format!("allocate s_{:?}", idx)),
        target_index.get_value().map(|v| v == F::<G1>::from(idx as u64)),
      )?))
    })
    .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

  // Enforce ∑ selector[i] = 1
  {
    let selected_sum = selector
      .iter()
      .fold(LinearCombination::zero(), |lc, bit| lc + &bit.lc(CS::one(), F::<G1>::ONE));
    cs.enforce(
      || "exactly-one-selection",
      |_| selected_sum,
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );
  }

  // Enforce `target_index - ∑ i * selector[i] = 0``
  {
    let selected_value =
      selector.iter().enumerate().fold(LinearCombination::zero(), |lc, (i, bit)| {
        lc + &bit.lc(CS::one(), F::<G1>::from(i as u64))
      });
    cs.enforce(
      || "target_index - ∑ i * selector[i] = 0",
      |lc| lc,
      |lc| lc,
      |lc| lc + target_index.get_variable() - &selected_value,
    );
  }

  Ok(selector)
}

/// Converts the given public and private inputs into a `CircomInput` struct.
pub fn into_circom_input(
  public_input: &[F<G1>],
  private_input: &HashMap<String, Value>,
) -> CircomInput {
  let decimal_stringified_input: Vec<String> = public_input
    .iter()
    .map(|x| BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.to_bytes()).to_str_radix(10))
    .collect();

  CircomInput { step_in: decimal_stringified_input, extra: private_input.clone() }
}

/// Converts the given public and private inputs into a JSON string.
pub fn into_input_json(
  public_input: &[F<G1>],
  private_input: &HashMap<String, Value>,
) -> Result<String, ProofError> {
  let decimal_stringified_input: Vec<String> = public_input
    .iter()
    .map(|x| BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.to_bytes()).to_str_radix(10))
    .collect();

  let input = CircomInput { step_in: decimal_stringified_input, extra: private_input.clone() };
  Ok(serde_json::to_string(&input)?)
}

/// Remaps the given input JSON string into a vector of tuples containing the key and value.
pub fn remap_inputs(input_json: &str) -> Result<Vec<(String, Vec<BigInt>)>, ProofError> {
  let circom_input: CircomInput = serde_json::from_str(input_json)?;
  let mut remapped = vec![];

  let step_in_values: Result<Vec<BigInt>, _> = circom_input
    .step_in
    .into_iter()
    .map(|s| BigInt::from_str(&s).map_err(ProofError::from))
    .collect();
  remapped.push(("step_in".to_string(), step_in_values?));

  for (k, v) in circom_input.extra {
    let val = v
      .as_array()
      .ok_or_else(|| ProofError::Other(format!("Expected array for key {}", k)))?
      .iter()
      .map(|x| {
        x.as_str()
          .ok_or_else(|| ProofError::Other(format!("Expected string for key {}", k)))
          .and_then(|s| BigInt::from_str(s).map_err(ProofError::from))
      })
      .collect::<Result<Vec<BigInt>, ProofError>>()?;
    remapped.push((k, val));
  }

  Ok(remapped)
}
