//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 1024B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON_MASK_OBJECT: Mask object at depth 0
//! - JSON_MASK_ARRAY: Mask array at depth 0
//! - EXTRACT_VALUE: extract final value
use proofs::program::data::{R1CSType, SetupData, WitnessGeneratorType};

pub const JSON_MAX_ROM_LENGTH: usize = 45;
pub const JSON_MAX_ROM_1024B_LENGTH: usize = 80;

// Circuit 0
pub const AES_GCM_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b.r1cs");
pub const AES_GCM_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b.bin");

// Circuit 1
pub const HTTP_NIVC_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_nivc_512b.r1cs");
pub const HTTP_NIVC_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_nivc_512b.bin");

// Circuit 2
pub const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.r1cs");
pub const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.bin");

// Circuit 3
pub const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.r1cs");
pub const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.bin");

// Circuit 4
pub const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.r1cs");
pub const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.bin");

// -------------------------------------------------------------------------------------------- //
// -------------------------------------- 1024B circuits -------------------------------------- //

// CIRCUIT 1
pub const AES_GCM_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/aes_gctr_nivc_1024b.r1cs");
pub const AES_GCM_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/aes_gctr_nivc_1024b.bin");
// CIRCUIT 2
pub const HTTP_NIVC_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_nivc_1024b.bin");
pub const HTTP_NIVC_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_nivc_1024b.r1cs");
// Circuit 3
pub const JSON_MASK_OBJECT_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_object_1024b.r1cs");
pub const JSON_MASK_OBJECT_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_object_1024b.bin");
// Circuit 4
pub const JSON_MASK_ARRAY_INDEX_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_array_index_1024b.r1cs");
pub const JSON_MASK_ARRAY_INDEX_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_array_index_1024b.bin");
// Circuit 5
pub const EXTRACT_VALUE_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extract_value_1024b.r1cs");
pub const EXTRACT_VALUE_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extract_value_1024b.bin");

#[cfg(not(target_arch = "wasm32"))]
/// construct [`SetupData`] with all the required circuits for 512B inputs
pub fn construct_setup_data_512() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_NIVC_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  }
}

#[cfg(not(target_arch = "wasm32"))]
/// construct [`SetupData`] with all the required inputs for 1024B inputs
pub fn construct_setup_data_1024() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_1024_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_1024_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_1024_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_1024_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_1024_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(AES_GCM_1024_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_NIVC_1024_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_1024_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_1024_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_1024_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_1024B_LENGTH,
  }
}

#[cfg(target_arch = "wasm32")]
/// construct [`SetupData`] with all the required inputs for 1024B inputs
pub fn construct_setup_data_512() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  }
}

#[cfg(target_arch = "wasm32")]
/// construct [`SetupData`] with all the required circuits for 512B inputs
pub fn construct_setup_data_1024() -> SetupData {
  SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_1024_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_1024_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_1024_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_1024_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_1024_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
    ],
    max_rom_length:          JSON_MAX_ROM_1024B_LENGTH,
  }
}
