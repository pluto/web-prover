//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

use arecibo::{supernova::TrivialTestCircuit, traits::circuit::StepCircuit};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom::r1cs::R1CS;
use program::{utils::next_rom_index_and_pc, RomCircuit};
use utils::into_input_json;

use super::*;

const ROM: &[u64] = &[0, 1, 2, 0, 1, 2];

const ADD_INTO_ZEROTH_R1CS: &[u8] = include_bytes!("../../examples/addIntoZeroth.r1cs");
const ADD_INTO_ZEROTH_GRAPH: &[u8] = include_bytes!("../../examples/addIntoZeroth.bin");

const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("../../examples/squareZeroth.r1cs");
const SQUARE_ZEROTH_GRAPH: &[u8] = include_bytes!("../../examples/squareZeroth.bin");

const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("../../examples/swapMemory.r1cs");
const SWAP_MEMORY_GRAPH: &[u8] = include_bytes!("../../examples/swapMemory.bin");

use arecibo::supernova::{NonUniformCircuit, StepCircuit as SNStepCircuit};
use circom::witness::generate_witness_from_graph;

struct TestMemory {
  pub rom:                Vec<u64>,
  pub curr_public_input:  Vec<F<G1>>,
  pub curr_private_input: HashMap<String, Value>,
}

#[derive(Clone)]
enum TestCircuitSelector {
  AddIntoZeroth(RomCircuit),
  SquareZeroth(RomCircuit),
  SwapMemory(RomCircuit),
}

impl TestCircuitSelector {
  pub fn inner_arity(&self) -> usize {
    match self {
      Self::AddIntoZeroth(RomCircuit { circuit, .. }) => circuit.arity(),
      Self::SquareZeroth(RomCircuit { circuit, .. }) => circuit.arity(),
      Self::SwapMemory(RomCircuit { circuit, .. }) => circuit.arity(),
    }
  }
}

impl NonUniformCircuit<E1> for TestMemory {
  type C1 = TestCircuitSelector;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { 3 }

  // TODO: Alright I kinda just wrapped the option in here now which is not ideal
  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    match circuit_index {
      0 => TestCircuitSelector::AddIntoZeroth(RomCircuit {
        circuit: CircomCircuit { r1cs: R1CS::from(ADD_INTO_ZEROTH_R1CS), witness: None },
        curr_public_input: Some(self.curr_public_input.clone()),
        curr_private_input: Some(self.curr_private_input.clone()),
        circuit_index,
        rom_size: self.rom.len(),
        witness_generator_type: WitnessGeneratorType::Raw(ADD_INTO_ZEROTH_GRAPH.to_vec()),
      }),
      1 => TestCircuitSelector::SquareZeroth(RomCircuit {
        circuit: CircomCircuit { r1cs: R1CS::from(SQUARE_ZEROTH_R1CS), witness: None },
        curr_public_input: Some(self.curr_public_input.clone()),
        curr_private_input: Some(self.curr_private_input.clone()),
        circuit_index,
        rom_size: self.rom.len(),
        witness_generator_type: WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
      }),
      2 => TestCircuitSelector::SwapMemory(RomCircuit {
        circuit: CircomCircuit { r1cs: R1CS::from(SWAP_MEMORY_R1CS), witness: None },
        curr_public_input: Some(self.curr_public_input.clone()),
        curr_private_input: Some(self.curr_private_input.clone()),
        circuit_index,
        rom_size: self.rom.len(),
        witness_generator_type: WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
      }),
      _ => panic!("Incorrect circuit index provided!"),
    }
  }

  fn secondary_circuit(&self) -> Self::C2 { Default::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl SNStepCircuit<F<G1>> for TestCircuitSelector {
  fn arity(&self) -> usize {
    match self {
      Self::AddIntoZeroth(RomCircuit { circuit, rom_size, .. }) => circuit.arity() + 1 + rom_size,
      Self::SquareZeroth(RomCircuit { circuit, rom_size, .. }) => circuit.arity() + 1 + rom_size,
      Self::SwapMemory(RomCircuit { circuit, rom_size, .. }) => circuit.arity() + 1 + rom_size,
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::AddIntoZeroth(RomCircuit { circuit_index, .. }) => *circuit_index,
      Self::SquareZeroth(RomCircuit { circuit_index, .. }) => *circuit_index,
      Self::SwapMemory(RomCircuit { circuit_index, .. }) => *circuit_index,
    }
  }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    println!("inside of synthesize with pc: {pc:?}");

    // TODO: We need to set the witness on this properly, so we probably need to put the pub/priv
    // inputs into the CircuitSelector itself...
    let circuit = if let Some(allocated_num) = pc {
      if allocated_num.get_value().is_some() {
        match self {
          Self::AddIntoZeroth(RomCircuit {
            circuit,
            curr_private_input,
            curr_public_input,
            ..
          }) => {
            let mut circuit = circuit.clone();
            let witness = generate_witness_from_graph(
              &into_input_json(
                curr_public_input.as_ref().unwrap(),
                curr_private_input.as_ref().unwrap(),
              ),
              ADD_INTO_ZEROTH_GRAPH,
            );
            circuit.witness = Some(witness);
            circuit
          },
          Self::SquareZeroth(RomCircuit {
            circuit, curr_private_input, curr_public_input, ..
          }) => {
            let mut circuit = circuit.clone();
            let witness = generate_witness_from_graph(
              &into_input_json(
                curr_public_input.as_ref().unwrap(),
                curr_private_input.as_ref().unwrap(),
              ),
              SQUARE_ZEROTH_GRAPH,
            );
            circuit.witness = Some(witness);
            circuit
          },
          Self::SwapMemory(RomCircuit {
            circuit, curr_private_input, curr_public_input, ..
          }) => {
            let mut circuit = circuit.clone();
            let witness = generate_witness_from_graph(
              &into_input_json(
                curr_public_input.as_ref().unwrap(),
                curr_private_input.as_ref().unwrap(),
              ),
              SWAP_MEMORY_GRAPH,
            );
            circuit.witness = Some(witness);
            circuit
          },
        }
      } else {
        match self {
          Self::AddIntoZeroth(RomCircuit { circuit, .. }) => circuit.clone(),
          Self::SquareZeroth(RomCircuit { circuit, .. }) => circuit.clone(),
          Self::SwapMemory(RomCircuit { circuit, .. }) => circuit.clone(),
        }
      }
    } else {
      panic!("allocated num was none?")
    };

    let rom_index = &z[circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[circuit.arity() + 1..]; // jump to where we pushed rom data into CS

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;
    let mut circuit_constraints = circuit.vanilla_synthesize(cs, z)?;
    circuit_constraints.push(rom_index_next);
    circuit_constraints.extend(z[circuit.arity() + 1..].iter().cloned());
    Ok((Some(pc_next), circuit_constraints))
  }
}

#[test]
#[tracing_test::traced_test]
fn run_program() {
  info!("Starting SuperNova Add/Square test...");

  // Initial `step_in`: [0,2]
  let mut z0_primary: Vec<F<G1>> =
    [F::<G1>::from(0), F::<G1>::from(2)].iter().map(|val| F::<G1>::from(*val)).collect();

  // TODO: Should probably test feeding in private inputs
  // Map `private_input`
  //   let mut private_inputs = vec![];
  //   private_inputs
  //     .push(serde_json::from_str::<HashMap<String, Value>>(r#"{ "x": "2", "y": 3}"#).unwrap());
  //   private_inputs.push(serde_json::from_str::<HashMap<String, Value>>(r#"{ "x": "1"
  // }"#).unwrap());

  let mut memory = TestMemory {
    rom:                ROM.to_vec(),
    curr_public_input:  z0_primary.clone(),
    curr_private_input: HashMap::new(),
  };

  let pp = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());
  // extend z0_primary/secondary with rom content
  z0_primary.push(F::<G1>::ZERO); // rom_index = 0
  z0_primary.extend(memory.rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));

  let z0_secondary = vec![F::<G2>::ONE];

  let mut recursive_snark_option = None;

  for (idx, &op_code) in ROM.iter().enumerate() {
    info!("Step {} of ROM", idx);
    info!("opcode = {}", op_code);
    // memory.curr_private_input = private_inputs[idx].clone();

    let circuit_primary = memory.primary_circuit(op_code as usize);
    let circuit_secondary = memory.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      let rs = RecursiveSNARK::new(
        &pp,
        &memory,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .unwrap();
      info!("Instantiated RecursiveSNARK!");
      rs
    });

    info!("Proving single step...");
    let start = Instant::now();
    recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary).unwrap();
    info!("Single step proof took: {:?}", start.elapsed());

    // dbg!(&recursive_snark.zi_primary()); // TODO: this can be used later if need be.

    info!("Verifying single step...");
    let start = Instant::now();
    recursive_snark.verify(&pp, &z0_primary, &z0_secondary).unwrap();
    info!("Single step verification took: {:?}", start.elapsed());

    // Update everything now for next step
    // z0_primary = recursive_snark.zi_primary().clone();
    let mut next_pub_input = recursive_snark.zi_primary().clone();
    next_pub_input.truncate(circuit_primary.inner_arity());
    memory.curr_public_input = next_pub_input;

    recursive_snark_option = Some(recursive_snark);
  }

  //   dbg!(recursive_snark_option.unwrap().zi_primary());
  let final_mem = [
    F::<G1>::from(0),
    F::<G1>::from(16),
    F::<G1>::from(6),
    F::<G1>::from(0),
    F::<G1>::from(1),
    F::<G1>::from(2),
    F::<G1>::from(0),
    F::<G1>::from(1),
    F::<G1>::from(2),
  ];
  assert_eq!(&final_mem.to_vec(), recursive_snark_option.unwrap().zi_primary());
}
