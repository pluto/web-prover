use std::{
  collections::HashMap,
  env::current_dir,
  fs,
  fs::{File, OpenOptions},
  io,
  io::{BufReader, Read},
  path::{Path, PathBuf},
  process::Command,
  sync::{Arc, Mutex},
  time::Instant,
};

use anyhow::{bail, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use circom::circuit::{CircomCircuit, R1CS};
use ff::{Field, PrimeField};
use nova_snark::{
  traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
  PublicParams, RecursiveSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;

pub mod circuit;
pub mod r1cs;

pub fn create_public_params(r1cs: R1CS<F<<E1 as Engine>::GE>>) -> PublicParams<E1, E2, C1, C2> {
  let circuit_primary = CircomCircuit::<<E1 as Engine>::Scalar> { r1cs, witness: None };
  let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

  PublicParams::setup(&circuit_primary, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())
    .unwrap()
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
  step_in: Vec<String>,

  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

fn compute_witness_witnesscalc(
  current_public_input: Vec<String>,
  private_input: HashMap<String, Value>,
  graph_data: &[u8],
) -> Vec<<G1 as Group>::Scalar> {
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let input_json = serde_json::to_string(&input).unwrap();

  // let witness = circom_witnesscalc::calc_witness(&input_json, graph_data).unwrap();
  let witness =
    capture_and_log(|| circom_witnesscalc::calc_witness(&input_json, graph_data).unwrap());

  witness
    .iter()
    .map(|elem| <F<G1> as PrimeField>::from_str_vartime(elem.to_string().as_str()).unwrap())
    .collect()
}

pub fn generate_witness_from_wasm<Fr: PrimeField>(
  witness_wasm: &PathBuf,
  witness_input_json: &String,
  witness_output: &Path,
) -> Vec<Fr> {
  let root = current_dir().unwrap();
  let witness_generator_input = root.join("circom_input.json");
  fs::write(&witness_generator_input, witness_input_json).unwrap();

  let witness_js = witness_wasm.parent().unwrap().join("generate_witness.js");
  // let witness_js =
  // Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/circom/wasm_deps/generate_witness.js"));
  let output = Command::new("node")
    .arg(witness_js)
    .arg(witness_wasm)
    .arg(&witness_generator_input)
    .arg(witness_output)
    .output()
    .expect("failed to execute process");
  if !output.stdout.is_empty() || !output.stderr.is_empty() {
    print!("stdout: {}", std::str::from_utf8(&output.stdout).unwrap());
    print!("stderr: {}", std::str::from_utf8(&output.stderr).unwrap());
  }
  let _ = fs::remove_file(witness_generator_input);
  load_witness_from_bin_file::<Fr>(witness_output)
}

fn compute_witness<G1, G2>(
  current_public_input: Vec<String>,
  private_input: HashMap<String, Value>,
  witness_generator_file: &PathBuf,
  witness_generator_output: &Path,
) -> Vec<<G1 as Group>::Scalar>
where
  G1: Group<Base = <G2 as Group>::Scalar>,
  G2: Group<Base = <G1 as Group>::Scalar>,
{
  let decimal_stringified_input: Vec<String> = current_public_input
    .iter()
    .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
    .collect();

  let input =
    CircomInput { step_in: decimal_stringified_input.clone(), extra: private_input.clone() };

  let input_json = serde_json::to_string(&input).unwrap();

  generate_witness_from_wasm::<F<G1>>(witness_generator_file, &input_json, witness_generator_output)
}

/// load witness from bin file by filename
pub fn load_witness_from_bin_file<Fr: PrimeField>(filename: &Path) -> Vec<Fr> {
  let reader = OpenOptions::new().read(true).open(filename).expect("unable to open.");
  load_witness_from_bin_reader::<Fr, BufReader<File>>(BufReader::new(reader))
    .expect("read witness failed")
}

/// load witness from u8 array by a reader
pub(crate) fn load_witness_from_bin_reader<Fr: PrimeField, R: Read>(
  mut reader: R,
) -> Result<Vec<Fr>, anyhow::Error> {
  let mut wtns_header = [0u8; 4];
  reader.read_exact(&mut wtns_header)?;
  if wtns_header != [119, 116, 110, 115] {
    // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
    bail!("invalid file header");
  }
  let version = reader.read_u32::<LittleEndian>()?;
  // println!("wtns version {}", version);
  if version > 2 {
    bail!("unsupported file version");
  }
  let num_sections = reader.read_u32::<LittleEndian>()?;
  if num_sections != 2 {
    bail!("invalid num sections");
  }
  // read the first section
  let sec_type = reader.read_u32::<LittleEndian>()?;
  if sec_type != 1 {
    bail!("invalid section type");
  }
  let sec_size = reader.read_u64::<LittleEndian>()?;
  if sec_size != 4 + 32 + 4 {
    bail!("invalid section len")
  }
  let field_size = reader.read_u32::<LittleEndian>()?;
  if field_size != 32 {
    bail!("invalid field byte size");
  }
  let mut prime = vec![0u8; field_size as usize];
  reader.read_exact(&mut prime)?;
  // if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
  //     bail!("invalid curve prime {:?}", prime);
  // }
  let witness_len = reader.read_u32::<LittleEndian>()?;
  // println!("witness len {}", witness_len);
  let sec_type = reader.read_u32::<LittleEndian>()?;
  if sec_type != 2 {
    bail!("invalid section type");
  }
  let sec_size = reader.read_u64::<LittleEndian>()?;
  if sec_size != (witness_len * field_size) as u64 {
    bail!("invalid witness section size {}", sec_size);
  }
  let mut result = Vec::with_capacity(witness_len as usize);
  for _ in 0..witness_len {
    result.push(read_field::<&mut R, Fr>(&mut reader)?);
  }
  Ok(result)
}

pub(crate) fn read_field<R: Read, Fr: PrimeField>(mut reader: R) -> Result<Fr> {
  let mut repr = Fr::ZERO.to_repr();
  for digit in repr.as_mut().iter_mut() {
    // TODO: may need to reverse order?
    *digit = reader.read_u8()?;
  }
  let fr = Fr::from_repr(repr).unwrap();
  Ok(fr)
}

pub fn create_recursive_circuit(
  witness_generator_type: WitnessGenType,
  witness_generator_file: &PathBuf,
  r1cs: R1CS<F<G1>>,
  private_inputs: Vec<HashMap<String, Value>>,
  start_public_input: Vec<F<G1>>,
  pp: &PublicParams<E1, E2, C1, C2>,
) -> std::result::Result<RecursiveSNARK<E1, E2, C1, C2>, std::io::Error> {
  let root = current_dir().unwrap();
  let witness_generator_output = root.join("circom_witness.wtns");

  let iteration_count = private_inputs.len();

  let start_public_input_hex = start_public_input
    .iter()
    .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
    .collect::<Vec<String>>();
  let mut current_public_input = start_public_input_hex.clone();

  let graph_bin = std::fs::read(witness_generator_file)?;

  let mut now = Instant::now();

  let witness_0 = match witness_generator_type {
    WitnessGenType::CircomWitnesscalc => compute_witness_witnesscalc(
      current_public_input.clone(),
      private_inputs[0].clone(),
      &graph_bin,
    ),
    WitnessGenType::Node => compute_witness::<G1, G2>(
      current_public_input.clone(),
      private_inputs[0].clone(),
      witness_generator_file,
      &witness_generator_output,
    ),
  };

  debug!("witness generation for step 0 took: {:?}, {}", now.elapsed(), witness_0.len());

  let circuit_0 =
    CircomCircuit::<<E1 as Engine>::Scalar> { r1cs: r1cs.clone(), witness: Some(witness_0) };
  let circuit_secondary = TrivialCircuit::<<E2 as Engine>::Scalar>::default();
  let z0_secondary = vec![<E2 as Engine>::Scalar::ZERO];

  let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
    pp,
    &circuit_0,
    &circuit_secondary,
    &start_public_input,
    &z0_secondary,
  )
  .unwrap();

  for (i, private_input) in private_inputs.iter().enumerate().take(iteration_count) {
    now = Instant::now();
    let witness = match witness_generator_type {
      WitnessGenType::CircomWitnesscalc =>
        compute_witness_witnesscalc(current_public_input.clone(), private_input.clone(), &graph_bin),
      WitnessGenType::Node => compute_witness::<G1, G2>(
        current_public_input.clone(),
        private_input.clone(),
        witness_generator_file,
        &witness_generator_output,
      ),
    };
    debug!("witness generation for step {} took: {:?}", i, now.elapsed());

    let circuit = CircomCircuit { r1cs: r1cs.clone(), witness: Some(witness) };

    let current_public_output = circuit.get_public_outputs();
    current_public_input = current_public_output
      .iter()
      .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
      .collect();

    now = Instant::now();
    let res = recursive_snark.prove_step(pp, &circuit, &circuit_secondary);
    debug!("proving for step {} took: {:?}", i, now.elapsed());
    assert!(res.is_ok());
  }

  Ok(recursive_snark)
}

fn capture_and_log<F, T>(f: F) -> T
where F: FnOnce() -> T {
  // Create a buffer to capture stdout
  let output_buffer = Arc::new(Mutex::new(Vec::new()));

  // Capture the stdout into this buffer
  io::set_output_capture(Some(output_buffer.clone()));

  // Call the function that generates the output
  let result = f();

  // Release the capture and flush
  io::set_output_capture(None);

  // Get the captured output
  let captured_output = output_buffer.lock().unwrap();
  let output_str = String::from_utf8_lossy(&captured_output);

  // Log the captured output using tracing
  trace!("{}", output_str);

  result
}
