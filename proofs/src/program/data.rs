use std::io::Read;

use flate2::{read::ZlibDecoder, write::ZlibEncoder};
use proving_ground::supernova::{get_circuit_shapes, AuxParams};
use serde_json::json;

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
  pub start_index: usize,
  pub end_index:   usize,
  pub value:       Vec<Value>,
}

impl Input {
  pub fn split_values(&self) -> (Vec<usize>, Vec<Vec<Value>>) {
    assert_eq!(self.value.len() % (self.end_index - self.start_index + 1), 0);
    let chunk_size = self.value.len() / (self.end_index - self.start_index + 1);
    (
      (self.start_index..self.end_index + 1).collect(),
      self.value.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect(),
    )
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
  type PrivateInputs = HashMap<String, Input>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetupData {
  pub r1cs_types:              Vec<R1CSType>,
  pub witness_generator_types: Vec<WitnessGeneratorType>,
  pub max_rom_length:          usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgramData<S: SetupStatus, W: WitnessStatus> {
  pub public_params:      S::PublicParams,
  pub setup_data:         SetupData,
  pub rom:                Vec<u64>,
  pub initial_nivc_input: Vec<u64>,
  pub private_inputs:     W::PrivateInputs,
  pub witnesses:          Vec<Vec<F<G1>>>, // TODO: Ideally remove this
}

impl<S: SetupStatus> ProgramData<S, NotExpanded> {
  pub fn into_expanded(self) -> ProgramData<S, Expanded> {
    let mut private_inputs: Vec<HashMap<String, Value>> = vec![HashMap::new(); self.rom.len()];

    for (label, input) in self.private_inputs.iter() {
      let (indices, split_inputs) = input.split_values();
      for (idx, input) in indices.into_iter().zip(split_inputs) {
        private_inputs[idx].insert(label.to_owned(), json!(input));
      }
    }

    let Self { public_params, setup_data, rom, initial_nivc_input, witnesses, .. } = self;
    ProgramData { public_params, setup_data, rom, initial_nivc_input, witnesses, private_inputs }
  }
}

impl<W: WitnessStatus> ProgramData<Offline, W> {
  pub fn into_online(self) -> ProgramData<Online, W> {
    #[cfg(feature = "timing")]
    let time = std::time::Instant::now();

    let file = std::fs::read(&self.public_params).unwrap();
    let mut decoder = ZlibDecoder::new(&file[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    let aux_params: AuxParams<E1> = bincode::deserialize(&decompressed).unwrap();

    #[cfg(feature = "timing")]
    let aux_params_duration = {
      let aux_params_duration = time.elapsed();
      trace!("Reading in `AuxParams` elapsed: {:?}", aux_params_duration);
      aux_params_duration
    };

    // TODO: get the circuit shapes needed
    let circuits = initialize_circuit_list(&self.setup_data);
    let memory = Memory { circuits, rom: vec![0; self.setup_data.max_rom_length] }; // Note, `rom` here is not used in setup, only `circuits`
    let circuit_shapes = get_circuit_shapes(&memory);
    #[cfg(feature = "timing")]
    {
      let circuit_shapes_duration = time.elapsed() - aux_params_duration;
      trace!("`get_circuit_shapes()` elapsed: {:?}", circuit_shapes_duration);
    }

    let public_params = PublicParams::<E1>::from_parts(circuit_shapes, aux_params);
    let Self { setup_data, rom, initial_nivc_input, private_inputs, witnesses, .. } = self;
    ProgramData { public_params, setup_data, rom, initial_nivc_input, private_inputs, witnesses }
  }
}

impl<W: WitnessStatus> ProgramData<Online, W> {
  pub fn into_offline(self, path: PathBuf) -> ProgramData<Offline, W> {
    let (_, aux_params) = self.public_params.into_parts();
    let serialized = bincode::serialize(&aux_params).unwrap();
    dbg!(&serialized.len());
    // TODO: May not need to do flate2 compression. Need to test this actually shrinks things
    // meaningfully -- otherwise remove.
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&serialized).unwrap();
    let compressed = encoder.finish().unwrap();
    dbg!(&compressed.len());
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).unwrap();
    }
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&compressed).unwrap();

    let Self { setup_data, rom, initial_nivc_input, private_inputs, witnesses, .. } = self;
    ProgramData {
      public_params: path,
      setup_data,
      rom,
      initial_nivc_input,
      witnesses,
      private_inputs,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const JSON: &str = r#"
{
    "private_inputs": {
        "external": {
            "start_index": 0,
            "end_index": 0,
            "value": [5,7]
        },
        "plaintext": {
            "start_index": 1,
            "end_index": 2,
            "value": [1,2,3,4]
        }
    }
}"#;

  #[derive(Debug, Deserialize)]
  struct MockInputs {
    private_inputs: HashMap<String, Input>,
  }

  #[test]
  #[tracing_test::traced_test]
  fn test_deserialize_inputs() {
    let mock_inputs: MockInputs = serde_json::from_str(JSON).unwrap();
    dbg!(&mock_inputs.private_inputs);
    assert!(mock_inputs.private_inputs.contains_key("external"));
    assert!(mock_inputs.private_inputs.contains_key("plaintext"));
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
      rom:                vec![0, 0, 0],
      initial_nivc_input: vec![],
      private_inputs:     mock_inputs.private_inputs,
      witnesses:          vec![],
    };
    let program_data = program_data.into_expanded();
    dbg!(&program_data.private_inputs);
    assert!(!program_data.private_inputs[0].is_empty());
    assert!(!program_data.private_inputs[1].is_empty());
    assert!(!program_data.private_inputs[2].is_empty());
  }
}
