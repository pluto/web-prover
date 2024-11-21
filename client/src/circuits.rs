pub const JSON_MAX_ROM_LENGTH: usize = 28;
pub const AES_CHUNK_LENGTH: usize = 16;

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
