use std::{str::FromStr, sync::Arc};

use serde_json::json;

use super::*;
use crate::{
  program::data::{R1CSType, UninitializedSetup, WitnessGeneratorType},
  tests::inputs::{
    ADD_EXTERNAL_GRAPH, ADD_EXTERNAL_R1CS, EXTERNAL_INPUTS, SQUARE_ZEROTH_GRAPH,
    SQUARE_ZEROTH_R1CS, SWAP_MEMORY_GRAPH, SWAP_MEMORY_R1CS,
  },
};

const MAX_ROM_LENGTH: usize = 10;
const TEST_OFFLINE_PATH: &str = "src/tests/test_run_serialized_verify.bytes";

fn get_setup_data() -> UninitializedSetup {
  UninitializedSetup {
    r1cs_types:              vec![
      R1CSType::Raw(ADD_EXTERNAL_R1CS.to_vec()),
      R1CSType::Raw(SQUARE_ZEROTH_R1CS.to_vec()),
      R1CSType::Raw(SWAP_MEMORY_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(ADD_EXTERNAL_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SQUARE_ZEROTH_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(SWAP_MEMORY_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  }
}

async fn run_entry(
  setup_data: UninitializedSetup,
) -> Result<(SetupParams<Online>, RecursiveSNARK<E1>), ProofError> {
  let mut external_input0: HashMap<String, Value> = HashMap::new();
  external_input0.insert("external".to_string(), json!(EXTERNAL_INPUTS[0]));
  let mut external_input1: HashMap<String, Value> = HashMap::new();
  external_input1.insert("external".to_string(), json!(EXTERNAL_INPUTS[1]));
  let rom_data = HashMap::from([
    (String::from("ADD_EXTERNAL"), CircuitData { opcode: 0 }),
    (String::from("SQUARE_ZEROTH"), CircuitData { opcode: 1 }),
    (String::from("SWAP_MEMORY"), CircuitData { opcode: 2 }),
  ]);

  let mut private_inputs = vec![];

  let mut rom = vec![String::from("ADD_EXTERNAL")];
  private_inputs.push(external_input0);

  rom.push(String::from("SQUARE_ZEROTH"));
  private_inputs.push(HashMap::new());

  rom.push(String::from("SWAP_MEMORY"));
  private_inputs.push(HashMap::new());

  rom.push(String::from("ADD_EXTERNAL"));
  private_inputs.push(external_input1);

  rom.push(String::from("SQUARE_ZEROTH"));
  private_inputs.push(HashMap::new());

  rom.push(String::from("SWAP_MEMORY"));
  private_inputs.push(HashMap::new());
  let public_params = program::setup(&setup_data);
  let initialized_setup = initialize_setup_data(&setup_data)?;

  let setup_params = SetupParams::<Online> {
    public_params: Arc::new(public_params),
    setup_data: Arc::new(initialized_setup),
    rom_data,
    vk_digest_primary: F::<G1>::ZERO,
    vk_digest_secondary: F::<G2>::ZERO,
  };
  let proof_params = ProofParams { rom };
  let instance_params = InstanceParams::<NotExpanded> {
    nivc_input:     vec![F::<G1>::from(1), F::<G1>::from(2)],
    private_inputs: (private_inputs, HashMap::new()),
  }
  .into_expanded(&proof_params)?;
  let recursive_snark = program::run(&setup_params, &proof_params, &instance_params).await?;
  Ok((setup_params, recursive_snark))
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_run() {
  let setup_data = get_setup_data();
  let (_, proof) = run_entry(setup_data).await.unwrap();
  // [1,2] + [5,7]
  // --> [6,9]
  // --> [36,9]
  // --> [9,36] + [13,1]
  // --> [22,37]
  // --> [484,37]
  // [37,484]
  let final_mem = [
    F::<G1>::from(37),
    F::<G1>::from(484),
    F::<G1>::from(6),
    F::<G1>::from(0),
    F::<G1>::from(1),
    F::<G1>::from(2),
    F::<G1>::from(0),
    F::<G1>::from(1),
    F::<G1>::from(2),
    F::<G1>::from(u64::MAX),
    F::<G1>::from(u64::MAX),
    F::<G1>::from(u64::MAX),
    F::<G1>::from(u64::MAX),
  ];
  assert_eq!(&final_mem.to_vec(), proof.zi_primary());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_run_serialized_verify() {
  let setup_data = get_setup_data();
  let (instance_params, recursive_snark) = run_entry(setup_data.clone()).await.unwrap();

  // Pseudo-offline the `SetupParams` and regenerate it
  let mut setup_params =
    instance_params.into_offline(PathBuf::from_str(TEST_OFFLINE_PATH).unwrap()).unwrap();
  setup_params.setup_data = setup_data.clone();
  let setup_params = setup_params.into_online().unwrap();

  // Create the compressed proof with the offlined `PublicParams`
  let proof = program::compress_proof(&recursive_snark, &setup_params.public_params).unwrap();
  let serialized_compressed_proof = proof.serialize().unwrap();
  let proof = serialized_compressed_proof.deserialize().unwrap();

  // Extend the initial state input with the ROM (happens internally inside `program::run`, so
  // we do it out here just for the test)
  let mut z0_primary = vec![F::<G1>::ONE, F::<G1>::from(2)];
  z0_primary.push(F::<G1>::ZERO);
  let mut rom = vec![
    F::<G1>::ZERO,
    F::<G1>::ONE,
    F::<G1>::from(2),
    F::<G1>::ZERO,
    F::<G1>::ONE,
    F::<G1>::from(2),
  ];
  rom.resize(MAX_ROM_LENGTH, F::<G1>::from(u64::MAX));
  z0_primary.extend_from_slice(&rom);

  // Check that it verifies with offlined `PublicParams` regenerated pkey vkey
  let (_pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&setup_params.public_params).unwrap();
  let res = proof.proof.verify(&setup_params.public_params, &vk, &z0_primary, &[F::<G2>::ZERO]);
  assert!(res.is_ok());
  std::fs::remove_file(PathBuf::from_str(TEST_OFFLINE_PATH).unwrap()).unwrap();
}
