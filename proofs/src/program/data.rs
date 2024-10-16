use std::io::Read;

use flate2::{read::ZlibDecoder, write::ZlibEncoder};
use serde_json::json;

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldInput {
  pub value: HashMap<String, Vec<Value>>,
}

impl FoldInput {
  pub fn split_values(&self, freq: usize) -> Vec<HashMap<String, Value>> {
    assert_eq!(self.value.len() % freq, 0);
    let chunk_size = self.value.len() / freq;

    let mut res = vec![HashMap::new(); freq];

    for (key, value) in self.value.clone().into_iter() {
      let chunks: Vec<Vec<Value>> = value.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect();
      for i in 0..chunk_size {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WitnessGeneratorType {
  #[serde(rename = "wasm")]
  Wasm { path: String, wtns_path: String },
  #[serde(rename = "circom-witnesscalc")]
  CircomWitnesscalc { path: String },
  #[serde(rename = "browser")] // TODO: Can we merge this with Raw?
  Browser,
  #[serde(skip)]
  Raw(Vec<u8>), // TODO: Would prefer to not alloc here, but i got lifetime hell lol
  #[serde(skip)]
  RustWitness(fn(&str) -> Vec<F<G1>>),
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
  type PublicParams = PathBuf;
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
pub struct RomOpcodeConfig {
  pub name:          String,
  pub private_input: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgramData<S: SetupStatus, W: WitnessStatus> {
  pub public_params:      S::PublicParams,
  pub setup_data:         SetupData,
  pub rom_data:           HashMap<String, CircuitData>,
  pub rom:                Vec<RomOpcodeConfig>,
  pub initial_nivc_input: Vec<u64>,
  pub inputs:             W::PrivateInputs,
  pub witnesses:          Vec<Vec<F<G1>>>, // TODO: Ideally remove this
}

impl<S: SetupStatus> ProgramData<S, NotExpanded> {
  pub fn into_expanded(self) -> ProgramData<S, Expanded> {
    // build circuit usage map from rom
    let mut circuit_usage: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, circuit) in self.rom.iter().enumerate() {
      if let Some(usage) = circuit_usage.get_mut(&circuit.name) {
        usage.push(index);
      } else {
        circuit_usage.insert(circuit.name.clone(), vec![index]);
      }
    }

    // TODO: remove clone
    let roms = self.rom.clone();

    let mut private_inputs: Vec<HashMap<String, Value>> =
      self.rom.into_iter().map(|opcode_config| opcode_config.private_input.to_owned()).collect();

    // add fold input sliced to chunks and add to private input
    for (circuit, fold_inputs) in self.inputs.iter() {
      let inputs = circuit_usage.get(circuit).unwrap();
      let split_inputs = fold_inputs.split_values(inputs.len());
      for (idx, input) in inputs.iter().zip(split_inputs) {
        private_inputs[*idx].extend(input);
      }
    }

    let Self {
      public_params, setup_data, rom_data: romData, initial_nivc_input, witnesses, ..
    } = self;
    ProgramData {
      public_params,
      setup_data,
      rom_data: romData,
      rom: roms,
      initial_nivc_input,
      witnesses,
      inputs: private_inputs,
    }
  }
}

impl<W: WitnessStatus> ProgramData<Offline, W> {
  pub fn into_online(self) -> ProgramData<Online, W> {
    let file = std::fs::read(&self.public_params).unwrap();
    let mut decoder = ZlibDecoder::new(&file[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    let public_params = bincode::deserialize(&decompressed).unwrap();
    let Self { setup_data, rom_data: romData, rom, initial_nivc_input, inputs, witnesses, .. } =
      self;
    ProgramData {
      public_params,
      setup_data,
      rom_data: romData,
      rom,
      initial_nivc_input,
      inputs,
      witnesses,
    }
  }
}

impl<W: WitnessStatus> ProgramData<Online, W> {
  pub fn into_offline(self, path: PathBuf) -> ProgramData<Offline, W> {
    let serialized = bincode::serialize(&self.public_params).unwrap();
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&serialized).unwrap();
    let compressed = encoder.finish().unwrap();
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).unwrap();
    }
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&compressed).unwrap();

    let Self { setup_data, rom_data: romData, rom, initial_nivc_input, inputs, witnesses, .. } =
      self;
    ProgramData {
      public_params: path,
      setup_data,
      rom_data: romData,
      rom,
      initial_nivc_input,
      witnesses,
      inputs,
    }
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
    assert!(mock_inputs.input.contains_key("external"));
    assert!(mock_inputs.input.contains_key("plaintext"));
  }

  #[test]
  #[tracing_test::traced_test]
  fn test_expand_private_inputs() {
    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    let program_data = ProgramData::<Offline, NotExpanded> {
      public_params:      PathBuf::new(),
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
        RomOpcodeConfig { name: String::from("CIRCUIT_1"), private_input: HashMap::new() },
        RomOpcodeConfig { name: String::from("CIRCUIT_2"), private_input: HashMap::new() },
        RomOpcodeConfig { name: String::from("CIRCUIT_3"), private_input: HashMap::new() },
      ],
      initial_nivc_input: vec![],
      inputs:             mock_inputs.input,
      witnesses:          vec![],
    };
    let program_data = program_data.into_expanded();
    dbg!(&program_data.inputs);
    assert!(!program_data.inputs[0].is_empty());
    assert!(!program_data.inputs[1].is_empty());
    assert!(!program_data.inputs[2].is_empty());
  }
}
