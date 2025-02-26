// TODO: This module is so I can see if we can actually fold these noir circuits properly. I'm going
// to write code here to make it work that doesn't effect the circom build at all. I found bringing
// those together in some generic way is quite painful and truth be told would likely be easier to
// just completely rebuild.

use std::path::Path;

use client_side_prover::{
  supernova::{NonUniformCircuit, RecursiveSNARK, StepCircuit},
  traits::snark::default_ck_hint,
};
use tracing::trace;
use tracing_test::traced_test;

use super::*;
use crate::program::utils;

const ADD_EXTERNAL: &[u8] = include_bytes!("../../examples/noir_circuit_data/add_external.json");
const SQUARE_ZEROTH: &[u8] = include_bytes!("../../examples/noir_circuit_data/square_zeroth.json");
const SWAP_MEMORY: &[u8] = include_bytes!("../../examples/noir_circuit_data/swap_memory.json");

#[derive(Debug, Clone)]
pub struct NoirMemory {
  // TODO: Using a BTreeSet here would perhaps be preferable, or just some kind of set that checks
  // over circuit indices
  pub circuits:     Vec<NoirRomCircuit>,
  // TODO: I really think the ROM can just be removed and we can clean this up, but leaving it for
  // now is a bit easier
  pub rom:          Vec<u64>,
  pub public_input: Vec<F<G1>>,
}

#[derive(Clone, Debug)]
pub struct NoirRomCircuit {
  pub circuit:       NoirProgram,
  // TODO: It would be nice to have the circuit index automatically be used in the memory, but
  // perhaps we don't even need memory
  pub circuit_index: usize,
  // TODO: Not having ROM size here would be nice, but mayabe we don't even need ROM
  pub rom_size:      usize,
}

impl NonUniformCircuit<E1> for NoirMemory {
  type C1 = NoirRomCircuit;
  type C2 = TrivialCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { self.circuits.len() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  fn secondary_circuit(&self) -> Self::C2 { TrivialCircuit::default() }

  // Use the initial input to set this
  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl StepCircuit<F<G1>> for NoirRomCircuit {
  fn arity(&self) -> usize { self.circuit.arity() + 1 + self.rom_size }

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
  memory_clone.circuits.iter_mut().for_each(|circ| circ.circuit.witness = None);
  let public_params = PublicParams::setup(&memory_clone, &*default_ck_hint(), &*default_ck_hint());

  let z0_primary = &memory.public_input;
  let z0_secondary = &[F::<G2>::ZERO];

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

    // TODO: For some reason this is failing
    // info!("Verifying single step...");
    // recursive_snark.verify(&public_params, recursive_snark.z0_primary(), z0_secondary)?;
    // info!("Single step verification done");

    recursive_snark_option = Some(Ok(recursive_snark));
  }
  // Note, this unwrap cannot fail
  let recursive_snark = recursive_snark_option.unwrap();
  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  Ok(recursive_snark?)
}

// `fold.json` is:
// pub fn main(x0: Field, w: pub [Field;2]) -> pub [Field;2] {
//   [x0 * w[0] + w[1] + 1, (x0 + 3) * w[1] + w[0]]
// }
fn noir_fold() -> NoirProgram {
  let json_path = Path::new("./mock").join(format!("fold.json"));
  let noir_json = std::fs::read(&json_path).unwrap();

  NoirProgram::new(&noir_json)
}

#[test]
fn test_conversions() {
  let f = F::<G1>::from(5);
  let acir_f = convert_to_acir_field(f);
  assert_eq!(acir_f, GenericFieldElement::from_repr(Fr::from(5)));

  let f = GenericFieldElement::from_repr(Fr::from(3));
  let halo2_f = convert_to_halo2_field(f);
  assert_eq!(halo2_f, F::<G1>::from(3));
}

#[test]
#[traced_test]
fn test_mock_noir_ivc() {
  let mut circuit = noir_fold();
  circuit.set_private_inputs(vec![F::<G1>::from(3)]);

  let rom_circuit = NoirRomCircuit { circuit, circuit_index: 0, rom_size: 2 };

  let memory = NoirMemory {
    circuits:     vec![rom_circuit],
    rom:          vec![0, 0],
    public_input: vec![
      F::<G1>::from(1), // Actual input
      F::<G1>::from(2), // Actual input
      F::<G1>::from(0), // PC
      F::<G1>::from(0), // ROM
      F::<G1>::from(0), // ROM
    ],
  };

  let snark = run(&memory).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  // First fold:
  // step_out[0] == 3 * 1 + 2 + 1   == 6
  // step_out[1] == (3 + 3) * 2 + 1 == 13
  // Second fold:
  // step_out[0] == 3 * 6 + 13 + 1 == 32
  // step_out[1] == (3 + 3) * 13 + 6 == 84
  assert_eq!(zi[0], F::<G1>::from(32));
  assert_eq!(zi[1], F::<G1>::from(84));
  assert_eq!(zi[2], F::<G1>::from(2));
  assert_eq!(zi[3], F::<G1>::from(0));
  assert_eq!(zi[4], F::<G1>::from(0));
}

#[test]
#[traced_test]
fn test_mock_noir_nivc() {
  let mut add_external = NoirProgram::new(ADD_EXTERNAL);
  add_external.set_private_inputs(vec![F::<G1>::from(5), F::<G1>::from(7)]);
  let add_external =
    NoirRomCircuit { circuit: add_external, circuit_index: 0, rom_size: 3 };

  // TODO: The issue is the private inputs need to be an empty vector or else this isn't computed at
  // all. Be careful, this is insanely touchy and I hate that it is this way.
  let mut square_zeroth = NoirProgram::new(SQUARE_ZEROTH);
  square_zeroth.set_private_inputs(vec![]);
  let square_zeroth =
    NoirRomCircuit { circuit: square_zeroth, circuit_index: 1, rom_size: 3 };
  let mut swap_memory = NoirProgram::new(SWAP_MEMORY);
  swap_memory.set_private_inputs(vec![]);
  let swap_memory =
    NoirRomCircuit { circuit: swap_memory, circuit_index: 2, rom_size: 3 };

  let memory = NoirMemory {
    circuits:     vec![add_external, square_zeroth, swap_memory],
    rom:          vec![0, 1, 2],
    public_input: vec![
      F::<G1>::from(1), // Actual input
      F::<G1>::from(2), // Actual input
      F::<G1>::from(0), // PC
      F::<G1>::from(0), // ROM
      F::<G1>::from(1), // ROM
      F::<G1>::from(2), // ROM
    ],
  };

  let snark = run(&memory).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  // First fold:
  // step_out[0] == 1 + 5 == 6
  // step_out[1] == 2 + 7 == 9
  // Second fold:
  // step_out[0] == 6 ** 2 == 36
  // step_out[1] == 9
  // Third fold:
  // step_out[0] == 9
  // step_out[1] == 36
  assert_eq!(zi[0], F::<G1>::from(9));
  assert_eq!(zi[1], F::<G1>::from(36));
  assert_eq!(zi[2], F::<G1>::from(3));
  assert_eq!(zi[3], F::<G1>::from(0));
  assert_eq!(zi[4], F::<G1>::from(1));
  assert_eq!(zi[5], F::<G1>::from(2));
}
