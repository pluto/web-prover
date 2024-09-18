use core::str;
use std::{env::current_dir, ffi::OsStr, time::Instant};

use circom::{create_public_params, create_recursive_circuit, r1cs::load_r1cs};
use nova_snark::CompressedSNARK;
use serde_json::json;

use super::*;

pub fn run_circuit(circuit_data: CircuitData) {
  let folds = circuit_data.num_folds;
  let root = current_dir().unwrap();

  let circuit_file = root.join(circuit_data.r1cs_path);
  let r1cs = load_r1cs(&circuit_file);

  // Map `private_input`
  let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();
  let fold_input = circuit_data.private_input.get("fold_input").unwrap().as_object().unwrap();
  for i in 0..circuit_data.num_folds {
    let mut map = circuit_data.private_input.clone();
    map.remove("fold_input");

    for (key, values) in fold_input {
      let batch_size = values.as_array().unwrap().len() / circuit_data.num_folds;
      info!("key: {}, batch size: {}", key, batch_size);
      for val in values.as_array().unwrap().chunks(batch_size).skip(i).take(1) {
        let mut data: Vec<Value> = Vec::new();
        for individual in val {
          data.push(individual.clone());
        }
        map.insert(key.clone(), json!(data));
      }
    }
    private_inputs.push(map);
  }

  // Map `step_in` public input
  let init_step_in: Vec<F<G1>> = circuit_data.init_step_in.into_iter().map(F::<G1>::from).collect();

  let pp = create_public_params(r1cs.clone());

  info!("Number of constraints per step (primary circuit): {}", pp.num_constraints().0);
  info!("Number of constraints per step (secondary circuit): {}", pp.num_constraints().1);

  info!("Number of variables per step (primary circuit): {}", pp.num_variables().0);
  info!("Number of variables per step (secondary circuit): {}", pp.num_variables().1);

  let output = std::process::Command::new(circuit_data.cbuild_path)
    .args([
      circuit_data.circuit_path.as_os_str(),
      circuit_data.graph_path.as_os_str(),
      OsStr::new("-l"),
      OsStr::new("node_modules"),
    ])
    .output()
    .expect("failed to execute process");
  if !output.stdout.is_empty() || !output.stderr.is_empty() {
    trace!("stdout: {}", str::from_utf8(&output.stdout).unwrap());
    trace!("stderr: {}", str::from_utf8(&output.stderr).unwrap());
  }

  debug!("Creating a RecursiveSNARK...");
  let start = Instant::now();
  let recursive_snark = create_recursive_circuit(
    &circuit_data.graph_path,
    r1cs.clone(),
    private_inputs,
    init_step_in.clone(),
    &pp,
  )
  .unwrap();
  info!("RecursiveSNARK creation took {:?}", start.elapsed());

  // TODO: This seems like it has to be 0 for some reason lol
  let z0_secondary = [F::<G2>::from(0)];

  // verify the recursive SNARK
  debug!("Verifying a RecursiveSNARK...");
  let start = Instant::now();
  let res = recursive_snark.verify(&pp, folds, &init_step_in, &z0_secondary);
  info!("RecursiveSNARK::verify took {:?}", start.elapsed());
  assert!(res.is_ok());

  // produce a compressed SNARK
  debug!("Generating a CompressedSNARK using Spartan with IPA-PC...");
  let start = Instant::now();
  let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
  let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
  info!("CompressedSNARK::prove: {:?}, took {:?}", res.is_ok(), start.elapsed());
  assert!(res.is_ok());
  let compressed_snark = res.unwrap();

  // verify the compressed SNARK
  debug!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = compressed_snark.verify(&vk, folds, &init_step_in, &z0_secondary);
  info!("CompressedSNARK::verify: {:?}, took {:?}", res.is_ok(), start.elapsed());
  assert!(res.is_ok());
}
