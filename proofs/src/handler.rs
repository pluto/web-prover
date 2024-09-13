use super::*;
use std::{env::current_dir, time::Instant};

use nova_scotia::{
  circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};
use nova_snark::{provider, CompressedSNARK, PublicParams};

use crate::CircuitData;

pub fn run_circuit(circuit_data: CircuitData) {
  type G1 = provider::bn256_grumpkin::bn256::Point;
  type G2 = provider::bn256_grumpkin::grumpkin::Point;

  let folds = circuit_data.num_folds;
  let root = current_dir().unwrap();

  let circuit_file = root.join(circuit_data.r1cs_path);
  let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
  let witness_generator_file = root.join(circuit_data.wgen_path);

  // Map `private_input`
  let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();
  for (key, values) in circuit_data.private_input.clone() {
    for val in values.as_array().unwrap() {
      let mut map: HashMap<String, Value> = HashMap::new();
      map.insert(key.clone(), val.clone());
      private_inputs.push(map);
    }
  }

  // Map `step_in` public input
  let init_step_in: Vec<F<G1>> = circuit_data.init_step_in.into_iter().map(F::<G1>::from).collect();

  let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

  println!("Number of constraints per step (primary circuit): {}", pp.num_constraints().0);
  println!("Number of constraints per step (secondary circuit): {}", pp.num_constraints().1);

  println!("Number of variables per step (primary circuit): {}", pp.num_variables().0);
  println!("Number of variables per step (secondary circuit): {}", pp.num_variables().1);

  println!("Creating a RecursiveSNARK...");
  let start = Instant::now();
  let recursive_snark = create_recursive_circuit(
    FileLocation::PathBuf(witness_generator_file.clone()),
    r1cs.clone(),
    private_inputs,
    init_step_in.clone(),
    &pp,
  )
  .unwrap();
  println!("RecursiveSNARK creation took {:?}", start.elapsed());

  // TODO: This seems like it has to be 0 for some reason lol
  let z0_secondary = [F::<G2>::from(0)];

  // verify the recursive SNARK
  println!("Verifying a RecursiveSNARK...");
  let start = Instant::now();
  let res = recursive_snark.verify(&pp, folds, &init_step_in, &z0_secondary);
  println!("RecursiveSNARK::verify: {:?}, took {:?}", res, start.elapsed());
  assert!(res.is_ok());

  // produce a compressed SNARK
  println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
  let start = Instant::now();
  let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
  let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
  println!("CompressedSNARK::prove: {:?}, took {:?}", res.is_ok(), start.elapsed());
  assert!(res.is_ok());
  let compressed_snark = res.unwrap();

  // verify the compressed SNARK
  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = compressed_snark.verify(&vk, folds, init_step_in, z0_secondary.to_vec());
  println!("CompressedSNARK::verify: {:?}, took {:?}", res.is_ok(), start.elapsed());
  assert!(res.is_ok());
}
