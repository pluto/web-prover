use fs::OpenOptions;

use super::*;

pub fn generate_witness_from_generator_type(
  input_json: &str,
  witness_generator_type: &WitnessGeneratorType,
) -> Vec<F<G1>> {
  match witness_generator_type {
    WitnessGeneratorType::Browser => {
      panic!("browser type witness generation cannot be generated in process")
    },
    WitnessGeneratorType::Mobile { circuit } => {
      panic!("mobile type witgen not supported")
    },
    WitnessGeneratorType::Wasm { path, wtns_path } =>
      generate_witness_from_wasm_file(input_json, &PathBuf::from(path), &PathBuf::from(wtns_path)),
    WitnessGeneratorType::CircomWitnesscalc { path } =>
      generate_witness_from_witnesscalc_file(input_json, &PathBuf::from(path)),

    WitnessGeneratorType::Raw(graph_data) => generate_witness_from_graph(input_json, graph_data),
    WitnessGeneratorType::RustWitness(f) => f(input_json),
  }
}

pub fn remap_inputs(input_json: &str) -> Vec<(String, Vec<BigInt>)> {
  let circom_input: CircomInput = serde_json::from_str(input_json).unwrap();
  let mut unfuckulated = vec![];
  unfuckulated.push((
    "step_in".to_string(),
    circom_input.step_in.into_iter().map(|s| BigInt::from_str(&s).unwrap()).collect(),
  ));
  for (k, v) in circom_input.extra {
    let val = v
      .as_array()
      .unwrap()
      .iter()
      .map(|x| BigInt::from_str(&x.as_number().unwrap().to_string()).unwrap())
      .collect::<Vec<BigInt>>();
    unfuckulated.push((k, val));
  }
  unfuckulated
}

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
rust_witness::witness!(aesgcm);
pub fn aes_gcm_fold_wrapper(input_json: &str) -> Vec<F<G1>> {
  #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
  {
    let r = aesgcm_witness(remap_inputs(input_json))
      .into_iter()
      .map(|bigint| F::<G1>::from_str_vartime(&bigint.to_string()).unwrap())
      .collect();
    return r;
  }
  panic!("rust-witness only supported on arm")
}

pub fn generate_witness_from_graph(
  input_json: &str,
  graph_data: &[u8],
) -> Vec<<G1 as Group>::Scalar> {
  #[cfg(not(target_arch = "wasm32"))]
  {
    let witness = circom_witnesscalc::calc_witness(input_json, graph_data).unwrap();
    // Note: this captures stdout in this function call into `trace` logs
    // let witness =
    //   capture_and_log(|| circom_witnesscalc::calc_witness(input_json, graph_data).unwrap());

    witness
      .iter()
      .map(|elem| <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str()).unwrap())
      .collect()
  }
  #[cfg(target_arch = "wasm32")]
  todo!("circom_witnesscalc not supported in wasm");
}

pub fn generate_witness_from_witnesscalc_file(
  witness_input_json: &str,
  graph_path: &PathBuf,
) -> Vec<F<G1>> {
  #[cfg(not(target_arch = "wasm32"))]
  {
    let mut file = std::fs::File::open(graph_path).unwrap();
    let mut graph_data = Vec::new();
    file.read_to_end(&mut graph_data).unwrap();

    let witness = circom_witnesscalc::calc_witness(witness_input_json, &graph_data).unwrap();
    let r = witness
      .iter()
      .map(|elem| <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str()).unwrap())
      .collect();
    r
  }
  #[cfg(target_arch = "wasm32")]
  todo!("circom_witnesscalc not supported in wasm");
}

pub fn generate_witness_from_wasm_file(
  input_json: &str,
  wasm_path: &PathBuf,
  wtns_path: &PathBuf,
) -> Vec<F<G1>> {
  let root = current_dir().unwrap();
  let witness_generator_input = root.join("circom_input.json");
  fs::write(&witness_generator_input, input_json).unwrap();

  let witness_js = wasm_path.parent().unwrap().join("generate_witness.js");

  let output = Command::new("node")
    .arg(witness_js)
    .arg(wasm_path)
    .arg(&witness_generator_input)
    .arg(wtns_path)
    .output()
    .expect("failed to execute process");
  if !output.stdout.is_empty() || !output.stderr.is_empty() {
    debug!("{}", std::str::from_utf8(&output.stdout).unwrap());
    error!("{}", std::str::from_utf8(&output.stderr).unwrap());
  }
  fs::remove_file(witness_generator_input).unwrap();
  let reader = OpenOptions::new().read(true).open(wtns_path).expect("unable to open.");
  let witness = load_witness_from_bin_reader(BufReader::new(reader));
  fs::remove_file(wtns_path).unwrap();
  witness
}

pub fn load_witness_from_bin_reader<R: Read>(mut reader: R) -> Vec<F<G1>> {
  let mut wtns_header = [0u8; 4];
  reader.read_exact(&mut wtns_header).unwrap();
  assert_eq!(wtns_header, [119, 116, 110, 115]);

  let version = reader.read_u32::<LittleEndian>().unwrap();
  assert!(version <= 2);

  let num_sections = reader.read_u32::<LittleEndian>().unwrap();
  assert_eq!(num_sections, 2);

  // read the first section
  let sec_type = reader.read_u32::<LittleEndian>().unwrap();
  assert_eq!(sec_type, 1);

  let sec_size = reader.read_u64::<LittleEndian>().unwrap();
  assert_eq!(sec_size, 4 + 32 + 4);

  let field_size = reader.read_u32::<LittleEndian>().unwrap();
  assert_eq!(field_size, 32);

  let mut prime = vec![0u8; field_size as usize];
  reader.read_exact(&mut prime).unwrap();

  let witness_len = reader.read_u32::<LittleEndian>().unwrap();

  let sec_type = reader.read_u32::<LittleEndian>().unwrap();
  assert_eq!(sec_type, 2);

  let sec_size = reader.read_u64::<LittleEndian>().unwrap();
  assert_eq!(sec_size, (witness_len * field_size) as u64);

  let mut result = Vec::with_capacity(witness_len as usize);
  for _ in 0..witness_len {
    result.push(read_field(&mut reader).unwrap());
  }
  result
}

pub(crate) fn read_field<R: Read>(mut reader: R) -> Result<F<G1>> {
  let mut repr = F::<G1>::ZERO.to_repr();
  for digit in repr.as_mut().iter_mut() {
    // TODO: may need to reverse order?
    *digit = reader.read_u8()?;
  }
  let fr = F::<G1>::from_repr(repr).unwrap();
  Ok(fr)
}

// fn capture_and_log<F, T>(f: F) -> T
// where F: FnOnce() -> T {
//   // Create a buffer to capture stdout
//   let output_buffer = Arc::new(Mutex::new(Vec::new()));

//   // Capture the stdout into this buffer
//   std::io::set_output_capture(Some(output_buffer.clone()));

//   // Call the function that generates the output
//   let result = f();

//   // Release the capture and flush
//   std::io::set_output_capture(None);

//   // Get the captured output
//   let captured_output = output_buffer.lock().unwrap();
//   let output_str = String::from_utf8_lossy(&captured_output);

//   // Log the captured output using tracing
//   trace!("{}", output_str);

//   result
// }
