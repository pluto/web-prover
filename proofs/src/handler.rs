use super::*;
use std::{env::current_dir, time::Instant};

use nova_scotia::{
  circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F,
};
use nova_snark::{
  provider::{Bn256EngineIPA, GrumpkinEngine},
  traits::Engine,
  CompressedSNARK, PublicParams,
};
use serde_json::json;

use crate::CircuitData;

pub fn run_circuit(circuit_data: CircuitData) {
  // type G1 = provider::bn256_grumpkin::bn256::Point;
  // type G2 = provider::bn256_grumpkin::grumpkin::Point;

  type G1 = <Bn256EngineIPA as Engine>::GE;
  type G2 = <GrumpkinEngine as Engine>::GE;
  type E1 = Bn256EngineIPA;
  type E2 = GrumpkinEngine;
  type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
  type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
  type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
  type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

  // pub type F<G> = <G as Group>::Scalar;
  // pub type C1<G> = CircomCircuit<<G as Group>::Scalar>;
  // pub type C2<G> = TrivialCircuit<<G as Group>::Scalar>;

  let folds = circuit_data.num_folds;
  let root = current_dir().unwrap();

  let circuit_file = root.join(circuit_data.r1cs_path);
  let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
  let witness_generator_file = root.join(circuit_data.wgen_path);

  // Map `private_input`
  let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();
  for (key, values) in circuit_data.private_input.clone() {
    let batch_size = circuit_data.private_input.get(&key).unwrap().as_array().unwrap().len()
      / circuit_data.num_folds;
    println!("batch size: {}", batch_size);
    for val in values.as_array().unwrap().chunks(batch_size) {
      let mut map: HashMap<String, Value> = HashMap::new();
      let mut data: Vec<Value> = Vec::new();
      for individual in val {
        data.push(individual.clone());
      }
      map.insert(key.clone(), json!(data));
      private_inputs.push(map);
    }
  }
  // dbg!(private_inputs.clone());

  // Map `step_in` public input
  let init_step_in: Vec<F<G1>> = circuit_data.init_step_in.into_iter().map(F::<G1>::from).collect();

  let pp = create_public_params(r1cs.clone());

  println!("Number of constraints per step (primary circuit): {}", pp.num_constraints().0);
  println!("Number of constraints per step (secondary circuit): {}", pp.num_constraints().1);

  println!("Number of variables per step (primary circuit): {}", pp.num_variables().0);
  println!("Number of variables per step (secondary circuit): {}", pp.num_variables().1);

  println!("Creating a RecursiveSNARK...");
  let start = Instant::now();
  let recursive_snark = create_recursive_circuit::<G1, G2>(
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
  println!("RecursiveSNARK::verify took {:?}", start.elapsed());
  assert!(res.is_ok());

  // produce a compressed SNARK
  println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
  let start = Instant::now();
  let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
  let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
  println!("CompressedSNARK::prove: {:?}, took {:?}", res.is_ok(), start.elapsed());
  assert!(res.is_ok());
  let compressed_snark = res.unwrap();

  // verify the compressed SNARK
  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = compressed_snark.verify(&vk, folds, &init_step_in, &z0_secondary);
  println!("CompressedSNARK::verify: {:?}, took {:?}", res.is_ok(), start.elapsed());
  assert!(res.is_ok());
}
