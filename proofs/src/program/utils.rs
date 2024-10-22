use std::str::FromStr;

use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  LinearCombination,
};
use itertools::Itertools;
use num_bigint::BigInt;

use super::*;
use crate::circom::CircomInput;

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
  let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next pc"), || {
    allocated_rom
      .get(next_rom_index)
      .and_then(|v| v.get_value())
      .and_then(|value| if value == F::<G1>::from(u64::MAX) { None } else { Some(value) })
      .unwrap_or_else(|| allocated_rom.get(current_rom_index).unwrap().get_value().unwrap())
  });

  Ok((rom_index_next, pc_next))
}

pub fn get_selector_vec_from_index<CS: ConstraintSystem<F<G1>>>(
  mut cs: CS,
  target_index: &AllocatedNum<F<G1>>,
  num_indices: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  assert_ne!(num_indices, 0);

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

pub fn into_input_json(public_input: &[F<G1>], private_input: &HashMap<String, Value>) -> String {
  let decimal_stringified_input: Vec<String> = public_input
    .iter()
    .map(|x| BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.to_bytes()).to_str_radix(10))
    .collect();

  let input = CircomInput { step_in: decimal_stringified_input, extra: private_input.clone() };
  serde_json::to_string(&input).unwrap()
}

pub fn remap_inputs(input_json: &str) -> Vec<(String, Vec<BigInt>)> {
  let circom_input: CircomInput = serde_json::from_str(input_json).unwrap();
  let mut remapped = vec![];
  remapped.push((
    "step_in".to_string(),
    circom_input.step_in.into_iter().map(|s| BigInt::from_str(&s).unwrap()).collect(),
  ));
  for (k, v) in circom_input.extra {
    let val = v
      .as_array()
      .unwrap()
      .iter()
      .map(|x| BigInt::from_str(&x.as_number().unwrap().to_string()).unwrap())
      .collect::<Vec<BigInt>>();
    remapped.push((k, val));
  }
  remapped
}
