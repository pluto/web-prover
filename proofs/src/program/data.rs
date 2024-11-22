use std::{
  io::{Read, Write},
  sync::Arc,
};

use client_side_prover::{
  supernova::{get_circuit_shapes, AuxParams, SuperNovaAugmentedCircuitParams},
  traits::{CurveCycleEquipped, Dual, ROConstants, ROConstantsCircuit},
  CommitmentKey, R1CSWithArity,
};
use serde_json::json;

use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AuxParamsCircuit<E1>
where E1: CurveCycleEquipped {
  ck_primary: Arc<CommitmentKey<E1>>, // This is shared between all circuit params
  augmented_circuit_params_primary: SuperNovaAugmentedCircuitParams,
  ck_secondary: Arc<CommitmentKey<Dual<E1>>>,
  circuit_shape_secondary: R1CSWithArity<Dual<E1>>,
  augmented_circuit_params_secondary: SuperNovaAugmentedCircuitParams,
  digest: E1::Scalar,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AuxParamsHash<E1>
where E1: CurveCycleEquipped {
  ro_consts_primary:           ROConstants<E1>,
  ro_consts_circuit_primary:   ROConstantsCircuit<Dual<E1>>,
  ro_consts_secondary:         ROConstants<Dual<E1>>,
  ro_consts_circuit_secondary: ROConstantsCircuit<E1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldInput {
  #[serde(flatten)]
  pub value: HashMap<String, Vec<Value>>,
}

impl FoldInput {
  pub fn split_values(&self, freq: usize) -> Vec<HashMap<String, Value>> {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum R1CSType {
  #[serde(rename = "file")]
  File { path: PathBuf },
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedParams {
  circuit_params: AuxParamsCircuit<E1>,
  #[serde(with = "serde_bytes")]
  hash_params:    Vec<u8>,
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
  type PublicParams = SerializedParams;
}

pub trait WitnessStatus {
  type PrivateInputs;
}
pub struct Expanded;
impl WitnessStatus for Expanded {
  type PrivateInputs = Vec<HashMap<String, Value>>;
}
pub struct NotExpanded;
impl WitnessStatus for NotExpanded {
  type PrivateInputs = HashMap<String, FoldInput>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetupData {
  pub r1cs_types:              Vec<R1CSType>,
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  pub max_rom_length:          usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitData {
  pub opcode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstructionConfig {
  pub name:          String,
  pub private_input: HashMap<String, Value>,
}

#[derive(Debug)]
pub struct ProgramData<S: SetupStatus, W: WitnessStatus> {
  pub public_params:      S::PublicParams,
  pub setup_data:         SetupData,
  pub rom_data:           HashMap<String, CircuitData>,
  pub rom:                Vec<InstructionConfig>,
  pub initial_nivc_input: Vec<F<G1>>,
  pub inputs:             W::PrivateInputs,
  pub witnesses:          Vec<Vec<F<G1>>>, // TODO: Ideally remove this
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
    let mut instruction_usage: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, circuit) in self.rom.iter().enumerate() {
      if let Some(usage) = instruction_usage.get_mut(&circuit.name) {
        usage.push(index);
      } else {
        instruction_usage.insert(circuit.name.clone(), vec![index]);
      }
    }
    let mut private_inputs: Vec<HashMap<String, Value>> =
      self.rom.iter().map(|opcode_config| opcode_config.private_input.to_owned()).collect();

    // add fold input sliced to chunks and add to private input
    for (circuit_label, fold_inputs) in self.inputs.iter() {
      let inputs = match instruction_usage.get(circuit_label) {
        Some(inputs) => inputs,
        None =>
          Err(ProofError::Other(format!("Circuit label '{}' not found in rom", circuit_label)))?,
      };
      let split_inputs = fold_inputs.split_values(inputs.len());
      for (idx, input) in inputs.iter().zip(split_inputs) {
        private_inputs[*idx].extend(input);
      }
    }

    let Self { public_params, setup_data, rom_data, initial_nivc_input, witnesses, .. } = self;
    Ok(ProgramData {
      public_params,
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
  /// 1. Decompresses the stored zlib-compressed public parameters
  /// 2. Deserializes the auxiliary parameters using bincode
  /// 3. Initializes the circuit list from setup data
  /// 4. Generates circuit shapes from the initialized memory
  /// 5. Reconstructs full public parameters from circuit shapes and auxiliary parameters
  /// 6. Constructs a new online program data instance
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
  /// * Zlib decompression fails
  /// * Bincode deserialization fails
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
    let cp = self.public_params.circuit_params;
    let hp: AuxParamsHash<E1> = bincode::deserialize(&self.public_params.hash_params).unwrap();

    let aux_params = AuxParams {
      ck_primary: cp.ck_primary,
      ck_secondary: cp.ck_secondary,
      augmented_circuit_params_primary: cp.augmented_circuit_params_primary,
      circuit_shape_secondary: cp.circuit_shape_secondary,
      augmented_circuit_params_secondary: cp.augmented_circuit_params_secondary,
      digest: cp.digest,

      ro_consts_primary:           hp.ro_consts_primary,
      ro_consts_circuit_primary:   hp.ro_consts_circuit_primary,
      ro_consts_secondary:         hp.ro_consts_secondary,
      ro_consts_circuit_secondary: hp.ro_consts_circuit_secondary,
    };

    #[cfg(feature = "timing")]
    let aux_params_duration = {
      let aux_params_duration = time.elapsed();
      trace!("Reading in `AuxParams` elapsed: {:?}", aux_params_duration);
      aux_params_duration
    };

    // TODO: get the circuit shapes needed
    info!("circuit list");
    let circuits = initialize_circuit_list(&self.setup_data)?;
    let memory = Memory { circuits, rom: vec![0; self.setup_data.max_rom_length] }; // Note, `rom` here is not used in setup, only `circuits`
    info!("circuit shapes");
    let circuit_shapes = get_circuit_shapes(&memory);
    #[cfg(feature = "timing")]
    {
      let circuit_shapes_duration = time.elapsed() - aux_params_duration;
      trace!("`get_circuit_shapes()` elapsed: {:?}", circuit_shapes_duration);
    }

    info!("public params from parts");
    let public_params = PublicParams::<E1>::from_parts(circuit_shapes, aux_params);
    let Self { setup_data, rom, initial_nivc_input, inputs, witnesses, rom_data, .. } = self;
    Ok(ProgramData {
      public_params,
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
  /// Converts an online program data instance into an offline version by serializing and
  /// compressing the public parameters to disk.
  ///
  /// This method performs the following steps:
  /// 1. Extracts auxiliary parameters from the public parameters
  /// 2. Serializes the auxiliary parameters using bincode
  /// 3. Compresses the serialized data using zlib compression
  /// 4. Writes the compressed data to the specified path
  /// 5. Constructs a new offline program data instance
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
  /// * Bincode serialization fails
  /// * Zlib compression fails
  /// * File system operations fail (creating directories or writing file)
  ///
  /// # Type Parameters
  ///
  /// * `W: WitnessStatus` - The witness status type parameter carried over from the original
  ///   program data
  pub fn into_offline(self, path: PathBuf) -> Result<ProgramData<Offline, W>, ProofError> {
    let (_, aux_params) = self.public_params.into_parts();

    let sp = aux_params.clone();
    let circuit_params = AuxParamsCircuit::<E1> {
      ck_primary: sp.ck_primary,
      ck_secondary: sp.ck_secondary,
      augmented_circuit_params_primary: sp.augmented_circuit_params_primary,
      circuit_shape_secondary: sp.circuit_shape_secondary,
      augmented_circuit_params_secondary: sp.augmented_circuit_params_secondary,
      digest: sp.digest,
    };

    let hash_params = AuxParamsHash::<E1> {
      ro_consts_primary:           sp.ro_consts_primary,
      ro_consts_circuit_primary:   sp.ro_consts_circuit_primary,
      ro_consts_secondary:         sp.ro_consts_secondary,
      ro_consts_circuit_secondary: sp.ro_consts_circuit_secondary,
    };

    let serialized_json = serde_json::to_string(&circuit_params)?;
    let serialized_bin = bincode::serialize(&hash_params)?;
    dbg!(&serialized_json.len(), &serialized_bin.len());

    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }

    let stem = path.file_stem().unwrap();
    let json_path =
      format!("{}/{}.json", path.parent().unwrap().to_str().unwrap(), stem.to_str().unwrap());
    let bin_path =
      format!("{}/{}.bin", path.parent().unwrap().to_str().unwrap(), stem.to_str().unwrap());
    debug!("json_path={:?}, bin_path={:?}", json_path, bin_path);
    let mut json_file = std::fs::File::create(&json_path)?;
    let mut bin_file = std::fs::File::create(&bin_path)?;
    json_file.write_all(&serialized_json.as_bytes())?;
    bin_file.write_all(&serialized_bin)?;

    let Self { setup_data, rom_data, rom, initial_nivc_input, inputs, witnesses, .. } = self;
    Ok(ProgramData {
      public_params: SerializedParams { circuit_params, hash_params: serialized_bin },
      setup_data,
      rom_data,
      rom,
      initial_nivc_input,
      witnesses,
      inputs,
    })
  }
}

impl ProgramData<Online, Expanded> {
  /// Extends and prepares the public inputs for the zero-knowledge proof circuits.
  ///
  /// This function performs two main operations:
  /// 1. Expands the ROM (Read-Only Memory) to the maximum length specified in `setup_data`
  /// 2. Constructs the primary public input vector `z0_primary` by combining:
  ///    - The initial NIVC (Non-Interactive Verifiable Computation) input
  ///    - An initial ROM index of zero
  ///    - The expanded ROM opcodes converted to field elements
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
  pub fn extend_public_inputs(&self) -> Result<(Vec<F<G1>>, Vec<u64>), ProofError> {
    let mut rom = self
      .rom
      .iter()
      .map(|opcode_config| {
        self
          .rom_data
          .get(&opcode_config.name)
          .ok_or_else(|| {
            ProofError::Other(format!(
              "Opcode config '{}' not found in rom_data",
              opcode_config.name
            ))
          })
          .map(|config| config.opcode)
      })
      .collect::<Result<Vec<u64>, ProofError>>()?;

    rom.resize(self.setup_data.max_rom_length, u64::MAX);
    let mut z0_primary: Vec<F<G1>> = self.initial_nivc_input.clone();
    z0_primary.push(F::<G1>::ZERO); // rom_index = 0
    z0_primary.extend(rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));
    Ok((z0_primary, rom.clone()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const JSON: &str = r#"
{
    "input": {
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
}"#;

  #[derive(Debug, Deserialize)]
  struct MockInputs {
    input: HashMap<String, FoldInput>,
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
    let rom: Vec<InstructionConfig> = vec![
      InstructionConfig { name: "add".to_string(), private_input: HashMap::new() },
      InstructionConfig { name: "mul".to_string(), private_input: HashMap::new() },
    ];

    let setup_data = SetupData {
      max_rom_length:          4,
      r1cs_types:              vec![r1cs],
      witness_generator_types: vec![WitnessGeneratorType::Raw(vec![])],
    };

    let public_params = program::setup(&setup_data);

    ProgramData {
      public_params,
      setup_data,
      rom_data,
      rom,
      initial_nivc_input: vec![F::<G1>::ONE],
      inputs: vec![HashMap::new()],
      witnesses: vec![vec![F::<G1>::ONE]],
    }
  }

  #[test]
  fn test_extend_public_inputs() {
    // Setup test data
    let program_data = create_test_program_data();

    // Test successful case
    let result = program_data.extend_public_inputs();
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
    program_data.rom.push(InstructionConfig {
      name:          "nonexistent".to_string(),
      private_input: HashMap::new(),
    });

    let result = program_data.extend_public_inputs();
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
    assert!(mock_inputs.input.contains_key("CIRCUIT_1"));
    assert!(mock_inputs.input.contains_key("CIRCUIT_2"));
    assert!(mock_inputs.input.contains_key("CIRCUIT_3"));
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
    let public_params = program::setup(&setup_data);
    let ap = public_params.aux_params();
    let circuit_params = AuxParamsCircuit::<E1> {
      ck_primary: ap.ck_primary,
      ck_secondary: ap.ck_secondary,
      augmented_circuit_params_primary: ap.augmented_circuit_params_primary,
      circuit_shape_secondary: ap.circuit_shape_secondary,
      augmented_circuit_params_secondary: ap.augmented_circuit_params_secondary,
      digest: ap.digest,
    };

    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    let program_data = ProgramData::<Offline, NotExpanded> {
      public_params: SerializedParams { circuit_params, hash_params: vec![] },
      setup_data,
      rom_data: HashMap::from([
        (String::from("CIRCUIT_1"), CircuitData { opcode: 0 }),
        (String::from("CIRCUIT_2"), CircuitData { opcode: 1 }),
        (String::from("CIRCUIT_3"), CircuitData { opcode: 2 }),
      ]),
      rom: vec![
        InstructionConfig {
          name:          String::from("CIRCUIT_1"),
          private_input: HashMap::new(),
        },
        InstructionConfig {
          name:          String::from("CIRCUIT_2"),
          private_input: HashMap::new(),
        },
        InstructionConfig {
          name:          String::from("CIRCUIT_3"),
          private_input: HashMap::new(),
        },
      ],
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
