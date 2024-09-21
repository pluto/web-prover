use super::*;

const ROM: &[u64] = &[0, 0, 0, 0];
const PARSER_R1CS: &[u8] = include_bytes!("../../parse_fold_batch.r1cs");
const PARSER_GRAPH: &[u8] = include_bytes!("../../parse_fold.bin");

#[derive(Clone)]
pub enum CircuitSelector {
  Parser(RomCircuit),
}

impl CircuitSelector {
  pub fn inner_arity(&self) -> usize {
    match self {
      Self::Parser(RomCircuit { circuit, .. }) => circuit.arity(),
    }
  }
}

// TODO: This and the test implementation are so close together that it honestly would probably be
// worth consolidating this better and having some macro handle unwinding this impl.
// That is, if we want to have this be a more general tool. For now this is fine!
impl NonUniformCircuit<E1> for Memory {
  type C1 = CircuitSelector;
  type C2 = TrivialTestCircuit<F<G2>>;

  fn num_circuits(&self) -> usize { 1 }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    match circuit_index {
      0 => CircuitSelector::Parser(RomCircuit {
        circuit: CircomCircuit { r1cs: R1CS::from(PARSER_R1CS), witness: None },
        curr_public_input: self.curr_public_input.clone(),
        curr_private_input: self.curr_private_input.clone(),
        circuit_index,
        rom_size: self.rom.len(),
      }),
      _ => panic!("Incorrect circuit index provided!"),
    }
  }

  fn secondary_circuit(&self) -> Self::C2 { Default::default() }

  fn initial_circuit_index(&self) -> usize { self.rom[0] as usize }
}

impl SNStepCircuit<F<G1>> for CircuitSelector {
  fn arity(&self) -> usize {
    match self {
      Self::Parser(RomCircuit { circuit, rom_size, .. }) => circuit.arity() + 1 + rom_size,
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::Parser(RomCircuit { circuit_index, .. }) => *circuit_index,
    }
  }

  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>, // TODO: idk how to use the program counter lol
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    println!("inside of synthesize with pc: {pc:?}");

    let circuit = match self {
      Self::Parser(RomCircuit { circuit, .. }) => circuit,
    };
    let rom_index = &z[circuit.arity()]; // jump to where we pushed pc data into CS
    let allocated_rom = &z[circuit.arity() + 1..]; // jump to where we pushed rom data into CS

    let (rom_index_next, pc_next) = utils::next_rom_index_and_pc(
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
