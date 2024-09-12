use std::{collections::HashMap, env::current_dir, time::Instant};

use nova_scotia::{
  circom::reader::load_r1cs, continue_recursive_circuit, create_public_params,
  create_recursive_circuit, FileLocation, F, S,
};
use nova_snark::{provider, CompressedSNARK, PublicParams};
use serde_json::json;

fn run_test(circuit_filepath: String, witness_gen_filepath: String) {
  type G1 = provider::bn256_grumpkin::bn256::Point;
  type G2 = provider::bn256_grumpkin::grumpkin::Point;

  println!(
    "Running test with witness generator: {} and group: {}",
    witness_gen_filepath,
    std::any::type_name::<G1>()
  );
  let iteration_count = 5;
  let root = current_dir().unwrap();

  let circuit_file = root.join(circuit_filepath);

  // println!("before load");
  let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
  println!("Loaded r1cs!");
  let witness_generator_file = root.join(witness_gen_filepath);

  println!("r1cs num inputs: {:?}", r1cs.num_inputs);

  let mut private_input = HashMap::new();
  private_input.insert(
    "data".to_string(),
    json!([
      123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 49, 34, 58, 32, 34, 97, 98, 99, 34, 44, 10, 32,
      32, 32, 32, 34, 107, 101, 121, 50, 34, 58, 32, 34, 100, 101, 102, 34, 10, 125
    ]),
  );
  private_input.insert("key1".to_string(), json!([107, 101, 121, 49]));

  let mut private_inputs = Vec::new();
  private_inputs.push(private_input);
  println!("Added private inputs!");

  let start_public_input = [];

  let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

  println!("Number of constraints per step (primary circuit): {}", pp.num_constraints().0);
  println!("Number of constraints per step (secondary circuit): {}", pp.num_constraints().1);

  println!("Number of variables per step (primary circuit): {}", pp.num_variables().0);
  println!("Number of variables per step (secondary circuit): {}", pp.num_variables().1);

  // ------------------------------------------------------------------------------------------ //
  // RECURSIVE STUFF
  println!("Creating a RecursiveSNARK...");
  let start = Instant::now();
  let mut recursive_snark = create_recursive_circuit(
    FileLocation::PathBuf(witness_generator_file.clone()),
    r1cs.clone(),
    private_inputs,
    start_public_input.to_vec(),
    &pp,
  )
  .unwrap();
  println!("RecursiveSNARK creation took {:?}", start.elapsed());

  // TODO: empty?
  let z0_secondary = [];

  // verify the recursive SNARK
  println!("Verifying a RecursiveSNARK...");
  let start = Instant::now();
  let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &z0_secondary);
  println!("RecursiveSNARK::verify: {:?}, took {:?}", res, start.elapsed());
  assert!(res.is_ok());

  let z_last = res.unwrap().0;

  assert_eq!(z_last[0], F::<G1>::from(20));
  assert_eq!(z_last[1], F::<G1>::from(70));
  // ------------------------------------------------------------------------------------------ //

  // // produce a compressed SNARK
  // println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
  // let start = Instant::now();
  // let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
  // let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
  // println!("CompressedSNARK::prove: {:?}, took {:?}", res.is_ok(), start.elapsed());
  // assert!(res.is_ok());
  // let compressed_snark = res.unwrap();

  // // verify the compressed SNARK
  // println!("Verifying a CompressedSNARK...");
  // let start = Instant::now();
  // let res = compressed_snark.verify(
  //   &vk,
  //   iteration_count,
  //   start_public_input.to_vec(),
  //   z0_secondary.to_vec(),
  // );
  // println!("CompressedSNARK::verify: {:?}, took {:?}", res.is_ok(), start.elapsed());
  // assert!(res.is_ok());

  // // continue recursive circuit by adding 2 further steps
  // println!("Adding steps to our RecursiveSNARK...");
  // let start = Instant::now();

  // let iteration_count_continue = 2;

  // let mut private_inputs_continue = Vec::new();
  // for i in 0..iteration_count_continue {
  //   let mut private_input = HashMap::new();
  //   private_input.insert("adder".to_string(), json!(5 + i));
  //   private_inputs_continue.push(private_input);
  // }

  // let res = continue_recursive_circuit(
  //   &mut recursive_snark,
  //   z_last,
  //   FileLocation::PathBuf(witness_generator_file),
  //   r1cs,
  //   private_inputs_continue,
  //   start_public_input.to_vec(),
  //   &pp,
  // );
  // assert!(res.is_ok());
  // println!("Adding 2 steps to our RecursiveSNARK took {:?}", start.elapsed());

  // // verify the recursive SNARK with the added steps
  // println!("Verifying a RecursiveSNARK...");
  // let start = Instant::now();
  // let res = recursive_snark.verify(
  //   &pp,
  //   iteration_count + iteration_count_continue,
  //   &start_public_input,
  //   &z0_secondary,
  // );
  // println!("RecursiveSNARK::verify: {:?}, took {:?}", res, start.elapsed());
  // assert!(res.is_ok());

  // assert_eq!(res.clone().unwrap().0[0], F::<G1>::from(31));
  // assert_eq!(res.unwrap().0[1], F::<G1>::from(115));
}

pub fn main() {
  let group_name = "bn254";

  println!("Starting example...");
  let circuit_filepath = run_test(format!("test.r1cs"), format!("test_js/test.wasm"));
  println!("Done!");
}
