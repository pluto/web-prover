use std::{
  fs::{self, File},
  io::Write,
};

use client_side_prover::{fast_serde::FastSerde, supernova::get_circuit_shapes};
use serde_json::json;

use super::*;
use crate::setup::ProvingParams;

/// Fold input for any circuit containing signals name and vector of values. Inputs are distributed
/// evenly across folds after the ROM is finalised by the prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldInput {
  /// circuit name and consolidated values
  #[serde(flatten)]
  pub value: HashMap<String, Vec<Value>>,
}

impl FoldInput {
  /// splits the inputs evenly across folds as per instruction frequency
  pub fn split(&self, freq: usize) -> Vec<HashMap<String, Value>> {
    let mut res = vec![HashMap::new(); freq];

    for (key, value) in self.value.clone().into_iter() {
      debug!("key: {:?}, freq: {}, value_len: {}", key, freq, value.len());
      assert_eq!(value.len() % freq, 0);
      let chunk_size = value.len() / freq;
      let chunks: Vec<Vec<Value>> = value.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect();
      for i in 0..freq {
        res[i].insert(key.clone(), json!(chunks[i].clone()));
      }
    }

    res
  }
}

/// R1CS file type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum R1CSType {
  /// file path
  #[serde(rename = "file")]
  File { path: PathBuf },
  /// raw bytes
  #[serde(rename = "raw")]
  Raw(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum WitnessGeneratorType {
  #[serde(rename = "browser")]
  Browser,
  #[serde(rename = "wasm")]
  Wasm {
    path:      String,
    wtns_path: String,
  },
  Path(PathBuf),
  #[serde(skip)]
  Raw(Vec<u8>), // TODO: Would prefer to not alloc here, but i got lifetime hell lol
}

// Note, the below are typestates that prevent misuse of our current API.
pub trait SetupStatus {
  type PublicParams;
}

pub struct Online;
impl SetupStatus for Online {
  type PublicParams = PublicParams<E1>;
}
pub struct Offline;
impl SetupStatus for Offline {
  type PublicParams = Vec<u8>;
}

pub trait WitnessStatus {
  /// Private input for a circuit containing signals name and vector of values
  /// - For [`Expanded`] status, it is a vector of private inputs for each fold of a circuit
  /// - For [`NotExpanded`] status, it is a tuple of private input and fold input of a circuit
  type PrivateInputs;
}

pub struct Expanded;
impl WitnessStatus for Expanded {
  /// expanded input for each fold of each circuit in the ROM
  type PrivateInputs = Vec<HashMap<String, Value>>;
}
pub struct NotExpanded;
impl WitnessStatus for NotExpanded {
  /// Private input and fold input for each circuit in the ROM
  type PrivateInputs = (Vec<HashMap<String, Value>>, HashMap<String, FoldInput>);
}

/// Circuit setup data containing r1cs and witness generators along with max NIVC ROM length
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetupData {
  /// vector of all circuits' r1cs
  pub r1cs_types:              Vec<R1CSType>,
  /// vector of all circuits' witness generator
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  /// NIVC max ROM length
  pub max_rom_length:          usize,
}

/// Auxillary circuit data required to execute the ROM
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitData {
  /// circuit instruction opcode in [`SetupData`]
  pub opcode: u64,
}

#[derive(Debug)]
pub struct ProgramData<S: SetupStatus, W: WitnessStatus> {
  pub public_params:       S::PublicParams,
  // TODO: Refactor this onto the PublicParams object and share the ProvingParams abstraction
  pub vk_digest_primary:   <E1 as Engine>::Scalar,
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
  pub setup_data:          SetupData,
  pub rom_data:            HashMap<String, CircuitData>,
  pub rom:                 Vec<String>,
  pub initial_nivc_input:  Vec<F<G1>>,
  pub inputs:              W::PrivateInputs,
  pub witnesses:           Vec<Vec<F<G1>>>, // TODO: Ideally remove this
}

impl<S: SetupStatus> ProgramData<S, NotExpanded> {
  /// Converts a program data instance into an expanded form by distributing fold inputs across
  /// their corresponding circuit instances in the ROM.
  ///
  /// This method performs the following steps:
  /// 1. Creates a map of circuit names to their positions in the ROM
  /// 2. Collects private inputs from each ROM opcode configuration
  /// 3. Distributes fold inputs across matching circuit instances based on their labels
  /// 4. Combines the distributed inputs with existing private inputs for each ROM position
  ///
  /// # Arguments
  ///
  /// * `self` - The program data instance to expand
  ///
  /// # Returns
  ///
  /// Returns a `Result` containing either:
  /// * `Ok(ProgramData<S, Expanded>)` - The expanded program data with distributed inputs
  /// * `Err(ProofError)` - If the expansion process fails
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// * A circuit label in the inputs is not found in the ROM
  /// * Input distribution fails
  ///
  /// # Type Parameters
  ///
  /// * `S` - The program status type parameter (Online/Offline) carried over from the original data
  ///
  /// # Details
  ///
  /// The expansion process handles fold inputs, which are inputs that need to be distributed across
  /// multiple instances of the same circuit in the ROM. For each circuit label in the inputs:
  /// 1. Finds all positions of that circuit in the ROM
  /// 2. Splits the fold inputs into equal parts
  /// 3. Assigns each part to the corresponding circuit instance
  ///
  /// The resulting expanded form contains individual private inputs for each ROM position, with
  /// fold inputs properly distributed according to circuit usage.
  pub fn into_expanded(self) -> Result<ProgramData<S, Expanded>, ProofError> {
    assert!(self.inputs.0.len() == self.rom.len());

    let mut instruction_usage: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, circuit) in self.rom.iter().enumerate() {
      if let Some(usage) = instruction_usage.get_mut(circuit.as_str()) {
        usage.push(index);
      } else {
        instruction_usage.insert(circuit.clone(), vec![index]);
      }
    }
    let mut private_inputs: Vec<HashMap<String, Value>> = self.inputs.0;

    // add fold input sliced to chunks and add to private input
    for (circuit_label, fold_inputs) in self.inputs.1.iter() {
      let inputs = match instruction_usage.get(circuit_label) {
        Some(inputs) => inputs,
        None =>
          Err(ProofError::Other(format!("Circuit label '{}' not found in rom", circuit_label)))?,
      };
      let split_inputs = fold_inputs.split(inputs.len());
      for (idx, input) in inputs.iter().zip(split_inputs) {
        private_inputs[*idx].extend(input);
      }
    }

    assert!(private_inputs.len() == self.rom.len());

    let Self {
      public_params,
      vk_digest_primary,
      vk_digest_secondary,
      setup_data,
      rom_data,
      initial_nivc_input,
      witnesses,
      ..
    } = self;
    Ok(ProgramData {
      public_params,
      vk_digest_primary,
      vk_digest_secondary,
      setup_data,
      rom_data,
      rom: self.rom,
      initial_nivc_input,
      witnesses,
      inputs: private_inputs,
    })
  }
}

impl<W: WitnessStatus> ProgramData<Offline, W> {
  /// Converts an offline program data instance back into an online version by decompressing and
  /// deserializing the public parameters and reconstructing the circuit shapes.
  ///
  /// This method performs the following steps:
  /// 1. Deserializes raw bytes into an AuxParams object
  /// 2. Initializes the circuit list from setup data
  /// 3. Generates circuit shapes from the initialized memory
  /// 4. Reconstructs full public parameters from circuit shapes and auxiliary parameters
  /// 5. Constructs a new online program data instance
  ///
  /// # Arguments
  ///
  /// * `self` - The offline program data instance to convert
  ///
  /// # Returns
  ///
  /// Returns a `Result` containing either:
  /// * `Ok(ProgramData<Online, W>)` - The converted online program data
  /// * `Err(ProofError)` - If any step in the conversion process fails
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// * Circuit initialization fails
  /// * Circuit shape generation fails
  ///
  /// # Type Parameters
  ///
  /// * `W: WitnessStatus` - The witness status type parameter carried over from the original
  ///   program data
  ///
  /// # Features
  ///
  /// When compiled with the "timing" feature, this function will output timing information for:
  /// * Reading and deserializing auxiliary parameters
  /// * Generating circuit shapes
  ///
  /// # Example
  pub fn into_online(self) -> Result<ProgramData<Online, W>, ProofError> {
    debug!("loading proving params, proving_param_bytes={:?}", self.public_params.len());
    let proving_params = ProvingParams::from_bytes(&self.public_params).unwrap();
    debug!("done loading proving params");

    // TODO: get the circuit shapes needed
    info!("circuit list");
    let circuits = initialize_circuit_list(&self.setup_data)?;
    let memory = Memory { circuits, rom: vec![0; self.setup_data.max_rom_length] }; // Note, `rom` here is not used in setup, only `circuits`
    info!("circuit shapes");
    let circuit_shapes = get_circuit_shapes(&memory);

    info!("public params from parts");
    let public_params =
      PublicParams::<E1>::from_parts_unchecked(circuit_shapes, proving_params.aux_params);
    let Self { setup_data, rom, initial_nivc_input, inputs, witnesses, rom_data, .. } = self;

    Ok(ProgramData {
      public_params,
      vk_digest_primary: proving_params.vk_digest_primary,
      vk_digest_secondary: proving_params.vk_digest_secondary,
      setup_data,
      rom,
      initial_nivc_input,
      inputs,
      witnesses,
      rom_data,
    })
  }
}

impl<W: WitnessStatus> ProgramData<Online, W> {
  /// Converts an online program data instance into an offline version by serializing
  /// the public parameters to disk.
  ///
  /// This method performs the following steps:
  /// 1. Extracts auxiliary parameters from the public parameters
  /// 2. Serializes the auxiliary parameters to bytes
  /// 3. Writes the compressed data to the specified path
  /// 4. Constructs a new offline program data instance
  ///
  /// # Arguments
  ///
  /// * `self` - The online program data instance to convert
  /// * `path` - The file path where compressed public parameters will be saved
  ///
  /// # Returns
  ///
  /// Returns a `Result` containing either:
  /// * `Ok(ProgramData<Offline, W>)` - The converted offline program data
  /// * `Err(ProofError)` - If any step in the conversion process fails
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// * Bytes serialization fails
  /// * File system operations fail (creating directories or writing file)
  ///
  /// # Type Parameters
  ///
  /// * `W: WitnessStatus` - The witness status type parameter carried over from the original
  ///   program data
  pub fn into_offline(self, path: PathBuf) -> Result<ProgramData<Offline, W>, ProofError> {
    let (_, aux_params) = self.public_params.into_parts();
    let vk_digest_primary = self.vk_digest_primary;
    let vk_digest_secondary = self.vk_digest_secondary;
    let proving_param_bytes =
      ProvingParams { aux_params, vk_digest_primary, vk_digest_secondary }.to_bytes();

    if let Some(parent) = path.parent() {
      fs::create_dir_all(parent)?;
    }

    let bytes_path = path.with_extension("bytes");
    debug!("bytes_path={:?}", bytes_path);
    File::create(&bytes_path)?.write_all(&proving_param_bytes).unwrap();

    let Self { setup_data, rom_data, rom, initial_nivc_input, inputs, witnesses, .. } = self;
    Ok(ProgramData {
      public_params: proving_param_bytes,
      vk_digest_primary,
      vk_digest_secondary,
      setup_data,
      rom_data,
      rom,
      initial_nivc_input,
      witnesses,
      inputs,
    })
  }

  /// Extends and prepares the public inputs for the zero-knowledge proof circuits.
  ///
  /// This function performs two main operations:
  /// 1. Expands the ROM (Read-Only Memory) to the maximum length specified in `setup_data`
  /// 2. Constructs the primary public input vector `z0_primary` by combining:
  ///    - The initial NIVC (Non-Interactive Verifiable Computation) input
  ///    - An initial ROM index of zero
  ///    - The expanded ROM opcodes converted to field elements
  ///
  /// # Arguments
  /// - `input_override`: Optional override for the initial_nivc_input used during verification.
  ///
  /// # Returns
  ///
  /// Returns a tuple containing:
  /// - `Vec<F<G1>>`: The extended primary public input vector (z0_primary)
  /// - `Vec<u64>`: The expanded ROM containing opcodes
  ///
  /// # Errors
  ///
  /// Returns a `ProofError` if:
  /// - Any opcode configuration specified in the ROM is not found in `rom_data`
  pub fn extend_public_inputs(
    &self,
    input_override: Option<Vec<F<G1>>>,
  ) -> Result<(Vec<F<G1>>, Vec<u64>), ProofError> {
    // TODO: This is currently enabled for _either_ Expanded or NotExpanded
    let mut rom = self
      .rom
      .iter()
      .map(|opcode_config| {
        self
          .rom_data
          .get(opcode_config)
          .ok_or_else(|| {
            ProofError::Other(format!("Opcode config '{}' not found in rom_data", opcode_config))
          })
          .map(|config| config.opcode)
      })
      .collect::<Result<Vec<u64>, ProofError>>()?;

    rom.resize(self.setup_data.max_rom_length, u64::MAX);

    let mut z0_primary: Vec<F<G1>> = match input_override {
      Some(input) => input,
      None => self.initial_nivc_input.clone(),
    };
    z0_primary.push(F::<G1>::ZERO); // rom_index = 0
    z0_primary.extend(rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));
    debug!("z0_primary={:?}", z0_primary);
    Ok((z0_primary, rom.clone()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const JSON: &str = r#"
{
    "input": [
      [
      {},{},{}
      ],
      {
        "CIRCUIT_1": {
          "external": [5,7],
          "plaintext": [1,2,3,4]
        },
        "CIRCUIT_2": {
          "ciphertext": [1, 2, 3, 4],
          "external": [2, 4]
        },
        "CIRCUIT_3": {
          "key": [2, 3],
          "value": [4, 5]
        }
      }
    ]
}"#;

  #[derive(Debug, Deserialize)]
  struct MockInputs {
    input: (Vec<HashMap<String, Value>>, HashMap<String, FoldInput>),
  }

  // Helper function to create test program data
  fn create_test_program_data() -> ProgramData<Online, Expanded> {
    // Load add.r1cs from examples
    let add_r1cs = include_bytes!("../../examples/circuit_data/add_external.r1cs");
    let r1cs = R1CSType::Raw(add_r1cs.to_vec());
    // Create ROM data with proper circuit data
    let mut rom_data = HashMap::new();
    rom_data.insert("add".to_string(), CircuitData { opcode: 1u64 });
    rom_data.insert("mul".to_string(), CircuitData { opcode: 2u64 });

    // Rest of the function remains same
    let rom: Vec<String> = vec!["add".to_string(), "mul".to_string()];

    let setup_data = SetupData {
      max_rom_length:          4,
      r1cs_types:              vec![r1cs],
      witness_generator_types: vec![WitnessGeneratorType::Raw(vec![])],
    };

    let public_params = program::setup(&setup_data);
    let (prover_key, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();

    ProgramData {
      public_params,
      setup_data,
      vk_digest_primary: prover_key.pk_primary.vk_digest,
      vk_digest_secondary: prover_key.pk_secondary.vk_digest,
      rom_data,
      rom,
      initial_nivc_input: vec![F::<G1>::ONE],
      inputs: vec![HashMap::new(), HashMap::new()],
      witnesses: vec![vec![F::<G1>::ONE]],
    }
  }

  #[test]
  fn test_extend_public_inputs() {
    // Setup test data
    let program_data = create_test_program_data();

    // Test successful case
    let result = program_data.extend_public_inputs(None);
    assert!(result.is_ok());

    let (z0_primary, expanded_rom) = result.unwrap();

    // Verify z0_primary structure
    assert_eq!(
      z0_primary.len(),
      program_data.initial_nivc_input.len() + 1 + program_data.setup_data.max_rom_length
    );
    assert_eq!(z0_primary[program_data.initial_nivc_input.len()], F::<G1>::ZERO); // Check ROM index is 0

    // Verify ROM expansion
    assert_eq!(expanded_rom.len(), program_data.setup_data.max_rom_length);
    assert_eq!(expanded_rom[0], 1u64); // First opcode
    assert_eq!(expanded_rom[1], 2u64); // Second opcode
    assert_eq!(expanded_rom[2], u64::MAX); // Padding
  }

  #[test]
  fn test_extend_public_inputs_missing_opcode() {
    let mut program_data = create_test_program_data();

    // Add an opcode config that doesn't exist in rom_data
    program_data.rom.push("nonexistent".to_string());

    let result = program_data.extend_public_inputs(None);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ProofError::Other(e) if e.contains("not found in rom_data")
    ));
  }

  #[test]
  #[tracing_test::traced_test]
  fn test_deserialize_inputs() {
    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    dbg!(&mock_inputs.input);
    assert!(mock_inputs.input.1.contains_key("CIRCUIT_1"));
    assert!(mock_inputs.input.1.contains_key("CIRCUIT_2"));
    assert!(mock_inputs.input.1.contains_key("CIRCUIT_3"));
  }

  #[ignore]
  #[test]
  #[tracing_test::traced_test]
  fn test_expand_private_inputs() {
    let setup_data = SetupData {
      r1cs_types:              vec![R1CSType::Raw(vec![])],
      witness_generator_types: vec![WitnessGeneratorType::Raw(vec![])],
      max_rom_length:          3,
    };

    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    let program_data = ProgramData::<Offline, NotExpanded> {
      public_params: vec![],
      setup_data,
      rom_data: HashMap::from([
        (String::from("CIRCUIT_1"), CircuitData { opcode: 0 }),
        (String::from("CIRCUIT_2"), CircuitData { opcode: 1 }),
        (String::from("CIRCUIT_3"), CircuitData { opcode: 2 }),
      ]),
      rom: vec![String::from("CIRCUIT_1"), String::from("CIRCUIT_2"), String::from("CIRCUIT_3")],
      vk_digest_primary: F::<G1>::ZERO,
      vk_digest_secondary: F::<G2>::ZERO,
      initial_nivc_input: vec![],
      inputs: mock_inputs.input,
      witnesses: vec![],
    };
    let program_data = program_data.into_expanded().unwrap();
    dbg!(&program_data.inputs);
    assert!(!program_data.inputs[0].is_empty());
    assert!(!program_data.inputs[1].is_empty());
    assert!(!program_data.inputs[2].is_empty());
  }
}
