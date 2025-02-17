//! # Witness Module
//!
//! The `witness` module provides functionalities for generating and loading witnesses from various
//! sources. It includes functions for generating witnesses from browser types, WASM files, and
//! witnesscalc files.
//!
//! ## Functions
//!
//! - `generate_witness_from_browser_type`: Generates a witness from a browser type.
//! - `generate_witness_from_generator_type`: Generates a witness from a generator type.
//! - `generate_witness_from_graph`: Generates a witness from a graph.
//! - `generate_witness_from_witnesscalc_file`: Generates a witness from a witnesscalc file.
//! - `load_witness_from_bin_reader`: Loads a witness from a bin reader.
//! - `read_field`: Reads a field from a reader.

use fs::OpenOptions;

use super::*;

/// Generates a witness from a browser type
///
/// # Arguments
///
/// * `circom_input` - A `CircomInput` struct.
/// * `opcode` - A `u64` representing the opcode.
///
/// # Returns
///
/// A `Result` containing a vector of field elements.
#[allow(unused_variables)]
pub async fn generate_witness_from_browser_type(
  circom_input: CircomInput,
  opcode: u64,
) -> Result<Vec<F<G1>>, ProofError> {
  #[cfg(target_arch = "wasm32")]
  {
    let js_witness_input = serde_wasm_bindgen::to_value(&circom_input).map_err(ProofError::from)?;

    let js_witness =
      crate::circom::wasm_witness::create_witness(js_witness_input, opcode).await.unwrap();

    let js_computed_witnesses: Vec<u8> = js_witness.data.to_vec();
    let witnesses =
      load_witness_from_bin_reader(BufReader::new(Cursor::new(js_computed_witnesses)))?;

    return Ok(witnesses);
  }
  #[cfg(not(target_arch = "wasm32"))]
  Err(ProofError::Other(String::from(
    "Browser type witness generation cannot be generated in process",
  )))
}

/// Generates a witness from a generator type
///
/// # Arguments
///
/// * `input_json` - A string slice that holds the input JSON.
/// * `witness_generator_type` - A `WitnessGeneratorType` enum.
///
/// # Returns
///
/// A `Result` containing a vector of field elements.
pub fn generate_witness_from_generator_type(
  input_json: &str,
  witness_generator_type: &WitnessGeneratorType,
) -> Result<Vec<F<G1>>, ProofError> {
  match witness_generator_type {
    WitnessGeneratorType::Browser => {
      panic!("browser type witness generation cannot be generated in process")
    },
    WitnessGeneratorType::Wasm { path, wtns_path } =>
      generate_witness_from_wasm_file(input_json, &PathBuf::from(path), &PathBuf::from(wtns_path)),
    WitnessGeneratorType::Path(path) => generate_witness_from_witnesscalc_file(input_json, path),
    WitnessGeneratorType::Raw(graph_data) => generate_witness_from_graph(input_json, graph_data),
  }
}

/// Generates a witness from a graph
///
/// # Arguments
///
/// * `input_json` - A string slice that holds the input JSON.
/// * `graph_data` - A reference to the graph data.
///
/// # Returns
///
/// A `Result` containing a vector of field elements.
pub fn generate_witness_from_graph(
  input_json: &str,
  graph_data: &[u8],
) -> Result<Vec<<G1 as Group>::Scalar>, ProofError> {
  #[cfg(not(target_arch = "wasm32"))]
  {
    let witness = circom_witnesscalc::calc_witness(input_json, graph_data)?;
    let result = witness
      .iter()
      .map(|elem| {
        <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str())
          .ok_or_else(|| ProofError::Other("Failed to parse field element".to_string()))
      })
      .collect::<Result<Vec<F<G1>>, ProofError>>()?;
    Ok(result)
  }
  #[cfg(target_arch = "wasm32")]
  todo!("circom_witnesscalc not supported in wasm");
}

/// Generates a witness from a witnesscalc file
///
/// # Arguments
///
/// * `witness_input_json` - A string slice that holds the witness input JSON.
/// * `graph_path` - A reference to the path of the witnesscalc file.
///
/// # Returns
///
/// A `Result` containing a vector of field elements.
pub fn generate_witness_from_witnesscalc_file(
  witness_input_json: &str,
  graph_path: &PathBuf,
) -> Result<Vec<F<G1>>, ProofError> {
  #[cfg(not(target_arch = "wasm32"))]
  {
    let mut file = std::fs::File::open(graph_path)?;
    let mut graph_data = Vec::new();
    file.read_to_end(&mut graph_data)?;

    let witness = circom_witnesscalc::calc_witness(witness_input_json, &graph_data)?;
    let result = witness
      .iter()
      .map(|elem| {
        <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str())
          .ok_or_else(|| ProofError::Other("Failed to parse field element".to_string()))
      })
      .collect::<Result<Vec<F<G1>>, ProofError>>()?;
    Ok(result)
  }
  #[cfg(target_arch = "wasm32")]
  todo!("circom_witnesscalc not supported in wasm");
}

#[warn(missing_docs, clippy::missing_docs_in_private_items)]
/// Generates a witness from a WASM file.
///
/// # Arguments
///
/// * `input_json` - A string slice that holds the input JSON.
/// * `wasm_path` - A reference to the path of the WASM file.
/// * `wtns_path` - A reference to the path of the witness file.
///
/// # Returns
///
/// A vector of field elements.
pub fn generate_witness_from_wasm_file(
  input_json: &str,
  wasm_path: &PathBuf,
  wtns_path: &PathBuf,
) -> Result<Vec<F<G1>>, ProofError> {
  let root = current_dir()?;
  let witness_generator_input = root.join("circom_input.json");
  fs::write(&witness_generator_input, input_json)?;

  let witness_js = wasm_path
    .parent()
    .ok_or_else(|| ProofError::Other("Invalid wasm path".to_string()))?
    .join("generate_witness.js");

  let output = Command::new("node")
    .arg(witness_js)
    .arg(wasm_path)
    .arg(&witness_generator_input)
    .arg(wtns_path)
    .output()
    .expect("failed to execute process");
  if !output.stdout.is_empty() || !output.stderr.is_empty() {
    debug!(
      "{}",
      std::str::from_utf8(&output.stdout).map_err(|e| ProofError::Other(e.to_string()))?
    );
    error!(
      "{}",
      std::str::from_utf8(&output.stderr).map_err(|e| ProofError::Other(e.to_string()))?
    );
  }
  fs::remove_file(witness_generator_input)?;
  let reader = OpenOptions::new().read(true).open(wtns_path).expect("unable to open.");
  let witness = load_witness_from_bin_reader(BufReader::new(reader));
  fs::remove_file(wtns_path)?;
  witness
}

/// Loads a witness from a bin reader
///
/// # Arguments
///
/// * `reader` - A reference to the reader.
///
/// # Returns
///
/// A `Result` containing a vector of field elements.
pub fn load_witness_from_bin_reader<R: Read>(mut reader: R) -> Result<Vec<F<G1>>, ProofError> {
  let mut wtns_header = [0u8; 4];
  reader.read_exact(&mut wtns_header)?;
  assert_eq!(wtns_header, [119, 116, 110, 115]);

  let version = reader.read_u32::<LittleEndian>()?;
  assert!(version <= 2);

  let num_sections = reader.read_u32::<LittleEndian>()?;
  assert_eq!(num_sections, 2);

  // read the first section
  let sec_type = reader.read_u32::<LittleEndian>()?;
  assert_eq!(sec_type, 1);

  let sec_size = reader.read_u64::<LittleEndian>()?;
  assert_eq!(sec_size, 4 + 32 + 4);

  let field_size = reader.read_u32::<LittleEndian>()?;
  assert_eq!(field_size, 32);

  let mut prime = vec![0u8; field_size as usize];
  reader.read_exact(&mut prime)?;

  let witness_len = reader.read_u32::<LittleEndian>()?;

  let sec_type = reader.read_u32::<LittleEndian>()?;
  assert_eq!(sec_type, 2);

  let sec_size = reader.read_u64::<LittleEndian>()?;
  assert_eq!(sec_size, (witness_len * field_size) as u64);

  let mut result = Vec::with_capacity(witness_len as usize);
  for _ in 0..witness_len {
    result.push(read_field(&mut reader)?);
  }
  Ok(result)
}

/// Reads a field from a reader
///
/// # Arguments
///
/// * `reader` - A reference to the reader.
///
/// # Returns
///
/// A `Result` containing a field element.
pub(crate) fn read_field<R: Read>(mut reader: R) -> Result<F<G1>, ProofError> {
  let mut repr = F::<G1>::ZERO.to_repr();
  for digit in repr.as_mut().iter_mut() {
    *digit = reader.read_u8()?;
  }
  let fr = F::<G1>::from_repr(repr);
  if fr.is_some().into() {
    Ok(fr.unwrap())
  } else {
    Err(ProofError::Other("Failed to convert representation to field element".to_string()))
  }
}
