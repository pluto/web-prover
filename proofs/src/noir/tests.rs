// TODO: This module is so I can see if we can actually fold these noir circuits properly. I'm going
// to write code here to make it work that doesn't effect the circom build at all. I found bringing
// those together in some generic way is quite painful and truth be told would likely be easier to
// just completely rebuild.

use std::path::Path;

use client_side_prover::{
  bellpepper::shape_cs::ShapeCS,
  supernova::{NonUniformCircuit, RecursiveSNARK, StepCircuit},
  traits::snark::default_ck_hint,
};
use tracing::trace;

use super::*;
use crate::program::utils;

#[derive(Debug, Clone)]
pub struct NoirMemory {
  pub circuits:     Vec<NoirRomCircuit>,
  pub rom:          Vec<u64>,
  pub public_input: Vec<F<G1>>,
}

#[derive(Clone, Debug)]
pub struct NoirRomCircuit {
  pub circuit:       NoirProgram,
  pub circuit_index: usize,
  pub rom_size:      usize,
  //   pub private_input: Vec<F<G1>>,
}

impl NonUniformCircuit<E1> for NoirMemory {
  type C1 = NoirRomCircuit;
  type C2 = TrivialCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { self.circuits.len() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  fn secondary_circuit(&self) -> Self::C2 { Default::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl StepCircuit<F<G1>> for NoirRomCircuit {
  fn arity(&self) -> usize { dbg!(self.circuit.arity() + 1 + self.rom_size) }

  fn circuit_index(&self) -> usize { self.circuit_index }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    let rom_index = &z[self.circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[self.circuit.arity() + 1..]; // jump to where we pushed rom data into C
    let (rom_index_next, pc_next) = utils::next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;
    let mut circuit_constraints = self.circuit.vanilla_synthesize(cs, z)?;
    circuit_constraints.push(rom_index_next);
    circuit_constraints.extend(z[self.circuit.arity() + 1..].iter().cloned());
    Ok((Some(pc_next), circuit_constraints))
  }
}

pub fn run(memory: &NoirMemory) -> Result<RecursiveSNARK<E1>, ProofError> {
  info!("Starting SuperNova program...");

  info!("Setting up PublicParams...");
  // TODO: This is stupid to do, but I need to get around the original setting of the witness.
  // Having separate setup is the way (we already know this)
  let mut memory_clone = memory.clone();
  memory_clone.circuits[0].circuit.witness = None;
  let public_params = PublicParams::setup(&memory_clone, &*default_ck_hint(), &*default_ck_hint());

  let z0_primary = &memory.public_input;
  let z0_secondary = &vec![F::<G2>::ZERO];

  let mut recursive_snark_option = None;

  #[cfg(feature = "timing")]
  let time = std::time::Instant::now();
  for (idx, &op_code) in memory.rom.iter().enumerate() {
    info!("Step {} of ROM", idx);
    debug!("Opcode = {:?}", op_code);

    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        &public_params,
        memory,
        &circuit_primary,
        &circuit_secondary,
        z0_primary,
        z0_secondary,
      )
    })?;

    info!("Proving single step...");
    recursive_snark.prove_step(&public_params, &circuit_primary, &circuit_secondary)?;
    info!("Done proving single step...");

    // info!("Verifying single step...");
    recursive_snark.verify(&public_params, recursive_snark.z0_primary(), z0_secondary)?;
    // info!("Single step verification done");

    recursive_snark_option = Some(Ok(recursive_snark));
  }
  // Note, this unwrap cannot fail
  let recursive_snark = recursive_snark_option.unwrap();
  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  Ok(recursive_snark?)
}

fn noir_mock() -> NoirProgram {
  // Circuit definition:
  // x_0 * w_0 + w_1 + 2 == 0
  let json_path = Path::new("./mock").join(format!("mock.json"));
  let noir_json = std::fs::read(&json_path).unwrap();

  NoirProgram::new(&noir_json)
}

// `fold.json` is:
// pub fn main(x0: Field, w: pub [Field;2]) -> pub [Field;2] {
//   [x0 * w[0] + w[1] + 1, (x0 + 3) * w[1] + w[0]]
// }
fn noir_fold() -> NoirProgram {
  // Circuit definition:
  // x_0 * w_0 + w_1 + 2 == 0
  let json_path = Path::new("./mock").join(format!("fold.json"));
  let noir_json = std::fs::read(&json_path).unwrap();

  NoirProgram::new(&noir_json)
}

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
fn test_mock_noir_synthesize_empty() {
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

// #[test]
// fn test_mock_noir_synthesize_full() {
//   program.set_private_inputs(vec![F::<G1>::from(2), F::<G1>::from(3), -F::<G1>::from(8)]);

//   let mut cs = ShapeCS::<E1>::new();
//   program.vanilla_synthesize(&mut cs, &[]);

//   dbg!(&cs.constraints);
//   dbg!(cs.num_aux());
//   dbg!(cs.num_inputs());
// }

#[test]
fn test_mock_noir_ivc() {
  let mut circuit = noir_fold();
  circuit.set_private_inputs(vec![F::<G1>::from(3)]);

  let rom_circuit = NoirRomCircuit { circuit, circuit_index: 0, rom_size: 3 };

  let memory = NoirMemory {
    circuits:     vec![rom_circuit],
    rom:          vec![0, 0, 0],
    public_input: vec![
      F::<G1>::from(1), // Actual input
      F::<G1>::from(2), // Actual input
      F::<G1>::from(0), // PC
      F::<G1>::from(0), // ROM
      F::<G1>::from(0), // ROM
      F::<G1>::from(0), // ROM
    ],
  };

  let snark = run(&memory);
  dbg!(snark.unwrap().zi_primary());
}

#[test]
fn test_fold_noir_synthesize_empty() {
  let json_path = Path::new("./mock").join(format!("fold.json"));
  let noir_json = std::fs::read(&json_path).unwrap();

  let mut program = NoirProgram::new(&noir_json);

  let mut cs = ShapeCS::<E1>::new();
  program.vanilla_synthesize(&mut cs, &[]);

  dbg!(&cs.constraints);
  dbg!(cs.num_aux());
  dbg!(cs.num_inputs());
}

// TODO: This fails now because we pass in an empty array for `z`
#[test]
fn test_fold_noir_synthesize_full() {
  let json_path = Path::new("./mock").join(format!("fold.json"));
  let noir_json = std::fs::read(&json_path).unwrap();

  let mut program = NoirProgram::new(&noir_json);
  program.set_private_inputs(vec![F::<G1>::from(1), F::<G1>::from(1), F::<G1>::from(1)]);

  // Check:
  // 1 * 1 + 1 + 1 == 3
  // (1 + 3) * 1 + 1 = 4

  let mut cs = ShapeCS::<E1>::new();
  program.vanilla_synthesize(&mut cs, &[]);

  // dbg!(&cs.constraints);
  // dbg!(cs.num_aux());
  // dbg!(cs.num_inputs());
}
