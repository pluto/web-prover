use std::io::{Read, Write};

use client_side_prover::supernova::{get_circuit_shapes, AuxParams};
use flate2::{read::ZlibDecoder, write::ZlibEncoder};
use serde_json::json;

use super::*;

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
  // type PublicParams = PathBuf;
  type PublicParams = Vec<u8>;
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
  /// * `W: WitnessStatus` - The witness status type parameter carried over from the original program data
  ///
  /// # Features
  ///
  /// When compiled with the "timing" feature, this function will output timing information for:
  /// * Reading and deserializing auxiliary parameters
  /// * Generating circuit shapes
  ///
  /// # Example
  pub fn into_online(self) -> Result<ProgramData<Online, W>, ProofError> {
    #[cfg(feature = "timing")]
    let time = std::time::Instant::now();

    let file = self.public_params;
    let mut decoder = ZlibDecoder::new(&file[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    info!("starting deserializing");
    let aux_params: AuxParams<E1> = bincode::deserialize(&decompressed)?;

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
  /// Converts an online program data instance into an offline version by serializing and compressing
  /// the public parameters to disk.
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
  /// * `W: WitnessStatus` - The witness status type parameter carried over from the original program data
  pub fn into_offline(self, path: PathBuf) -> Result<ProgramData<Offline, W>, ProofError> {
    let (_, aux_params) = self.public_params.into_parts();
    let serialized = bincode::serialize(&aux_params)?;
    dbg!(&serialized.len());
    // TODO: May not need to do flate2 compression. Need to test this actually shrinks things
    // meaningfully -- otherwise remove.
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&serialized)?;
    let compressed = encoder.finish()?;
    dbg!(&compressed.len());
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&compressed)?;

    let Self { setup_data, rom_data, rom, initial_nivc_input, inputs, witnesses, .. } = self;
    Ok(ProgramData {
      public_params: compressed,
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
    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    let program_data = ProgramData::<Offline, NotExpanded> {
      public_params:      vec![],
      setup_data:         SetupData {
        r1cs_types:              vec![R1CSType::Raw(vec![])],
        witness_generator_types: vec![WitnessGeneratorType::Raw(vec![])],
        max_rom_length:          3,
      },
      rom_data:           HashMap::from([
        (String::from("CIRCUIT_1"), CircuitData { opcode: 0 }),
        (String::from("CIRCUIT_2"), CircuitData { opcode: 1 }),
        (String::from("CIRCUIT_3"), CircuitData { opcode: 2 }),
      ]),
      rom:                vec![
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
      inputs:             mock_inputs.input,
      witnesses:          vec![],
    };
    let program_data = program_data.into_expanded().unwrap();
    dbg!(&program_data.inputs);
    assert!(!program_data.inputs[0].is_empty());
    assert!(!program_data.inputs[1].is_empty());
    assert!(!program_data.inputs[2].is_empty());
  }
}
