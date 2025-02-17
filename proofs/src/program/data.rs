//! # Data Module
//!
//! The `data` module contains data structures and types used in the proof system.
//!
//! ## Structs
//!
//! - `FoldInput`: Represents the fold input for any circuit containing signal names and values.
//! - `R1CSType`: Represents the R1CS file type, which can be either a file path or raw bytes.

use std::{
  fs::{self, File},
  io::Write,
  sync::Arc,
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum R1CSType {
  /// file path to the R1CS file
  #[serde(rename = "file")]
  File(PathBuf),
  /// raw bytes of the R1CS file
  #[serde(rename = "raw")]
  Raw(Vec<u8>),
}

/// Witness generator type
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum WitnessGeneratorType {
  /// Browser witness generator
  #[serde(rename = "browser")]
  Browser,
  /// Wasm witness generator
  #[serde(rename = "wasm")]
  Wasm {
    /// Path to the Wasm binary for witness generation
    path:      String,
    /// Path where the witness files are stored
    wtns_path: String,
  },
  /// Path to the witness generator
  Path(PathBuf),
  /// Raw bytes of the witness generator
  #[serde(skip)]
  Raw(Vec<u8>), // TODO: Would prefer to not alloc here, but i got lifetime hell lol
}

/// Uninitialized Circuit Setup data, in this configuration the R1CS objects have not
/// been initialized and require a bulky initialize process.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct UninitializedSetup {
  /// vector of all circuits' r1cs
  pub r1cs_types:              Vec<R1CSType>,
  /// vector of all circuits' witness generator
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  /// NIVC max ROM length
  pub max_rom_length:          usize,
}

/// Initialized Circuit Setup data, in this configuration the R1CS objects have been
/// fully loaded for proving.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InitializedSetup {
  /// vector of all circuits' r1cs
  pub r1cs:                    Vec<Arc<R1CS>>,
  /// vector of all circuits' witness generator
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  /// NIVC max ROM length
  pub max_rom_length:          usize,
}

// Note, the below are typestates that prevent misuse of our current API.
/// Setup status trait
pub trait SetupStatus {
  /// Public parameters type
  type PublicParams;
  /// Setup data type
  type SetupData;
}

/// Online setup status
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Online;
impl SetupStatus for Online {
  type PublicParams = Arc<PublicParams<E1>>;
  type SetupData = Arc<InitializedSetup>;
}

/// Offline setup status
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Offline;
impl SetupStatus for Offline {
  type PublicParams = Vec<u8>;
  type SetupData = UninitializedSetup;
}

/// Witness status trait
pub trait WitnessStatus {
  /// Private input for a circuit containing signals name and vector of values
  /// - For [`Expanded`] status, it is a vector of private inputs for each fold of a circuit
  /// - For [`NotExpanded`] status, it is a tuple of private input and fold input of a circuit
  type PrivateInputs;
}

/// Expanded witness status
pub struct Expanded;
impl WitnessStatus for Expanded {
  /// expanded input for each fold of each circuit in the ROM
  type PrivateInputs = Vec<HashMap<String, Value>>;
}

/// Not expanded witness status
pub struct NotExpanded;
impl WitnessStatus for NotExpanded {
  /// Private input and fold input for each circuit in the ROM
  type PrivateInputs = (Vec<HashMap<String, Value>>, HashMap<String, FoldInput>);
}

/// Auxiliary circuit data required to execute the ROM
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CircuitData {
  /// circuit instruction opcode in [`S::SetupData`]
  pub opcode: u64,
}

/// ROM data type
pub type RomData = HashMap<String, CircuitData>;
/// ROM type
pub type Rom = Vec<String>;
/// NIVC input type
pub type NivcInput = Vec<F<G1>>;

/// Represents configuration and circuit data required for initializing the proving system.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetupParams<S: SetupStatus> {
  /// Public parameters of the proving system. Maps to the client-side prover parameters.
  pub public_params:       S::PublicParams,
  // TODO: Refactor this onto the PublicParams object and share the ProvingParams abstraction
  /// Setup-specific verification key digest for the primary elliptic curve.
  pub vk_digest_primary:   <E1 as Engine>::Scalar,
  /// Setup-specific verification key digest for the secondary elliptic curve.
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
  /// Describes R1CS configurations used in proving setup.
  pub setup_data:          S::SetupData,
  /// A mapping between ROM opcodes and circuit configuration.
  pub rom_data:            RomData,
}

impl<S: SetupStatus> PartialEq for SetupParams<S>
where S::SetupData: PartialEq
{
  fn eq(&self, other: &Self) -> bool {
    // TODO: Supernova types are not supporting PartialEq
    // self.public_params == other.public_params &&
    self.vk_digest_primary == other.vk_digest_primary
      && self.vk_digest_secondary == other.vk_digest_secondary
      && self.setup_data == other.setup_data
      && self.rom_data == other.rom_data
  }
}

/// Defines the logic of the proof program.
pub struct ProofParams {
  /// Represents sequence of circuit operations (circuit "bytecode")
  pub rom: Rom,
}

/// Contains inputs and state specific to a single proof generation instance.
#[derive(Debug)]
pub struct InstanceParams<W: WitnessStatus> {
  /// Initial public input for NIVC
  pub nivc_input:     NivcInput,
  /// Private inputs for each fold
  pub private_inputs: W::PrivateInputs,
}

impl InstanceParams<NotExpanded> {
  /// Converts proving instance parameters into an expanded form by distributing fold inputs across
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
  /// * `Ok(InstanceParams<Expanded>)` - The expanded instance with distributed inputs
  /// * `Err(ProofError)` - If the expansion process fails
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// * A circuit label in the inputs is not found in the ROM
  /// * Input distribution fails
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
  pub fn into_expanded(
    self,
    proof_params: &ProofParams,
  ) -> Result<InstanceParams<Expanded>, ProofError> {
    assert_eq!(self.private_inputs.0.len(), proof_params.rom.len());

    let mut instruction_usage: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, circuit) in proof_params.rom.iter().enumerate() {
      if let Some(usage) = instruction_usage.get_mut(circuit.as_str()) {
        usage.push(index);
      } else {
        instruction_usage.insert(circuit.clone(), vec![index]);
      }
    }
    let mut private_inputs: Vec<HashMap<String, Value>> = self.private_inputs.0;

    // add fold input sliced to chunks and add to private input
    for (circuit_label, fold_inputs) in self.private_inputs.1.iter() {
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

    assert_eq!(private_inputs.len(), proof_params.rom.len());

    let Self { nivc_input: initial_nivc_input, .. } = self;
    Ok(InstanceParams { nivc_input: initial_nivc_input, private_inputs })
  }
}

impl SetupParams<Offline> {
  /// Converts an offline setup parameters instance back into an online version by decompressing and
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
  /// * `Ok(SetupParams<Online>)` - The converted online program data
  /// * `Err(ProofError)` - If any step in the conversion process fails
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// * Circuit initialization fails
  /// * Circuit shape generation fails
  ///
  /// # Features
  ///
  /// When compiled with the "timing" feature, this function will output timing information for:
  /// * Reading and deserializing auxiliary parameters
  /// * Generating circuit shapes
  pub fn into_online(self) -> Result<SetupParams<Online>, ProofError> {
    debug!("init proving params, proving_param_bytes={:?}", self.public_params.len());
    let proving_params = ProvingParams::from_bytes(&self.public_params).unwrap();

    info!("init setup");
    let initialized_setup = initialize_setup_data(&self.setup_data).unwrap();

    let circuits = initialize_circuit_list(&initialized_setup);
    let memory = Memory { circuits, rom: vec![0; self.setup_data.max_rom_length] };

    // TODO: This converts the r1cs memory into sparse matrices, which doubles
    // the memory usage. Can we re-used these sparse matrices in our constraint
    // system?
    info!("init circuit shapes");
    let circuit_shapes = get_circuit_shapes(&memory);

    info!("init public params from parts");
    let public_params =
      PublicParams::<E1>::from_parts_unchecked(circuit_shapes, proving_params.aux_params);
    let Self { rom_data, .. } = self;

    Ok(SetupParams {
      public_params: Arc::new(public_params),
      vk_digest_primary: proving_params.vk_digest_primary,
      vk_digest_secondary: proving_params.vk_digest_secondary,
      setup_data: Arc::new(initialized_setup),
      rom_data,
    })
  }
}

impl SetupParams<Online> {
  /// Converts an online setup parameters instance into an offline version by serializing
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
  /// * `Ok(SetupParams<Offline>)` - The converted offline program data
  /// * `Err(ProofError)` - If any step in the conversion process fails
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// * Bytes serialization fails
  /// * File system operations fail (creating directories or writing file)
  pub fn into_offline(self, path: PathBuf) -> Result<SetupParams<Offline>, ProofError> {
    let exclusive = Arc::try_unwrap(self.public_params).unwrap();
    let (_, aux_params) = exclusive.into_parts();
    let vk_digest_primary = self.vk_digest_primary;
    let vk_digest_secondary = self.vk_digest_secondary;
    let proving_param_bytes =
      ProvingParams { aux_params, vk_digest_primary, vk_digest_secondary }.to_bytes();

    if let Some(parent) = path.parent() {
      fs::create_dir_all(parent)?;
    }

    let bytes_path = path.with_extension("bytes");
    debug!("bytes_path={:?}", bytes_path);
    File::create(&bytes_path)?.write_all(&proving_param_bytes)?;

    let Self { rom_data, .. } = self;
    Ok(SetupParams {
      public_params: proving_param_bytes,
      vk_digest_primary,
      vk_digest_secondary,
      // TODO: This approach is odd, refactor with #375
      setup_data: Default::default(),
      rom_data,
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
  ///
  /// * `rom` - A reference to the ROM (sequence of circuit operations) containing circuit
  ///   configurations.
  /// * `initial_nivc_input` - The initial public input required for NIVC.
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
    rom: &Rom,
    initial_nivc_input: &NivcInput,
  ) -> Result<(Vec<F<G1>>, Vec<u64>), ProofError> {
    // TODO: This is currently enabled for _either_ Expanded or NotExpanded
    let mut rom = rom
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

    let mut z0_primary: Vec<F<G1>> = initial_nivc_input.clone();
    z0_primary.push(F::<G1>::ZERO); // rom_index = 0
    z0_primary.extend(rom.iter().map(|opcode| <E1 as Engine>::Scalar::from(*opcode)));
    debug!("z0_primary={:?}", z0_primary);
    Ok((z0_primary, rom.clone()))
  }
}

impl SetupParams<Online> {
  /// Generates NIVC proof from [`InstanceParams`]
  /// - run NIVC recursive proving
  /// - run CompressedSNARK to compress proof
  /// - serialize proof
  pub async fn generate_proof(
    &self,
    proof_params: &ProofParams,
    instance_params: &InstanceParams<Expanded>,
  ) -> Result<FoldingProof<Vec<u8>, String>, ProofError> {
    debug!("starting recursive proving");
    let program_output = program::run(self, proof_params, instance_params).await?;

    debug!("starting proof compression");
    let compressed_snark_proof = program::compress_proof_no_setup(
      &program_output,
      &self.public_params,
      self.vk_digest_primary,
      self.vk_digest_secondary,
    )?;
    compressed_snark_proof.serialize()
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
  fn create_test_program_data() -> (SetupParams<Online>, ProofParams, InstanceParams<Expanded>) {
    // Load add.r1cs from examples
    let add_r1cs = crate::tests::inputs::ADD_EXTERNAL_R1CS.to_vec();
    let r1cs = R1CSType::Raw(add_r1cs.to_vec());
    // Create ROM data with proper circuit data
    let mut rom_data = HashMap::new();
    rom_data.insert("add".to_string(), CircuitData { opcode: 1u64 });
    rom_data.insert("mul".to_string(), CircuitData { opcode: 2u64 });

    // Rest of the function remains same
    let rom: Vec<String> = vec!["add".to_string(), "mul".to_string()];

    let setup_data = UninitializedSetup {
      max_rom_length:          4,
      r1cs_types:              vec![r1cs],
      witness_generator_types: vec![WitnessGeneratorType::Raw(vec![])],
    };
    let initialized_setup = initialize_setup_data(&setup_data).unwrap();

    let public_params = program::setup(&setup_data);
    let (prover_key, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();

    let setup_params = SetupParams {
      public_params: Arc::new(public_params),
      setup_data: Arc::new(initialized_setup),
      vk_digest_primary: prover_key.pk_primary.vk_digest,
      vk_digest_secondary: prover_key.pk_secondary.vk_digest,
      rom_data,
    };
    let proof_params = ProofParams { rom };
    let instance_params = InstanceParams {
      nivc_input:     vec![F::<G1>::ONE],
      private_inputs: vec![HashMap::new(), HashMap::new()],
    };

    (setup_params, proof_params, instance_params)
  }

  #[test]
  fn test_extend_public_inputs() {
    // Setup test data
    let (setup_params, proof_params, instance_params) = create_test_program_data();

    // Test successful case
    let result = setup_params.extend_public_inputs(&proof_params.rom, &instance_params.nivc_input);
    assert!(result.is_ok());

    let (z0_primary, expanded_rom) = result.unwrap();

    // Verify z0_primary structure
    assert_eq!(
      z0_primary.len(),
      instance_params.nivc_input.len() + 1 + setup_params.setup_data.max_rom_length
    );
    assert_eq!(z0_primary[instance_params.nivc_input.len()], F::<G1>::ZERO); // Check ROM index is 0

    // Verify ROM expansion
    assert_eq!(expanded_rom.len(), setup_params.setup_data.max_rom_length);
    assert_eq!(expanded_rom[0], 1u64); // First opcode
    assert_eq!(expanded_rom[1], 2u64); // Second opcode
    assert_eq!(expanded_rom[2], u64::MAX); // Padding
  }

  #[test]
  fn test_extend_public_inputs_missing_opcode() {
    let (setup_params, mut proof_params, instance_params) = create_test_program_data();

    // Add an opcode config that doesn't exist in rom_data
    proof_params.rom.push("nonexistent".to_string());

    let result = setup_params.extend_public_inputs(&proof_params.rom, &instance_params.nivc_input);
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

  #[test]
  #[tracing_test::traced_test]
  fn test_expand_private_inputs() {
    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    let proof_params = ProofParams {
      rom: vec![String::from("CIRCUIT_1"), String::from("CIRCUIT_2"), String::from("CIRCUIT_3")],
    };
    let instance_params =
      InstanceParams::<NotExpanded> { nivc_input: vec![], private_inputs: mock_inputs.input }
        .into_expanded(&proof_params)
        .unwrap();
    dbg!(&instance_params.private_inputs);
    assert!(!instance_params.private_inputs[0].is_empty());
    assert!(!instance_params.private_inputs[1].is_empty());
    assert!(!instance_params.private_inputs[2].is_empty());
  }

  #[test]
  fn test_online_to_offline_serialization_round_trip() {
    let temp_dir = tempdir::TempDir::new("setup").unwrap();
    let offline_path = temp_dir.path().join("offline");

    let (setup_params_online, ..) = create_test_program_data();
    let setup_params_offline = setup_params_online.into_offline(offline_path).unwrap();

    // Matches itself
    assert_eq!(setup_params_offline, setup_params_offline);

    // Verify round-trip serialization for `Offline`
    let serialized_offline = serde_json::to_string(&setup_params_offline).unwrap();
    let deserialized_offline: SetupParams<Offline> =
      serde_json::from_str(&serialized_offline).unwrap();
    assert_eq!(setup_params_offline, deserialized_offline);

    // Can be "onlined"
    let result = deserialized_offline.into_online();
    assert!(result.is_ok());
  }
}
