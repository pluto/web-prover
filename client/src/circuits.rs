// Depends on the circuit input sizes
pub const MAX_PLAINTEXT_BYTES: usize = 512;
pub const TOTAL_BYTES_ACROSS_NIVC: usize = MAX_PLAINTEXT_BYTES + 4;

// Circuit 0
pub const AES_GCM_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b.r1cs");
pub const AES_GCM_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b.bin");

// Circuit 1
const HTTP_NIVC_R1CS: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/http_nivc_512b.r1cs");
const HTTP_NIVC_GRAPH: &[u8] =
  include_bytes!("../../web_proof_circuits/target_512b/http_nivc_512b.bin");

// Circuit 1
pub const HTTP_PARSE_AND_LOCK_START_LINE_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/target_512b/http_parse_and_lock_start_line_512b.r1cs"
);
pub const HTTP_PARSE_AND_LOCK_START_LINE_GRAPH: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/target_512b/http_parse_and_lock_start_line_512b.bin"
);

// Circuit 2
pub const HTTP_LOCK_HEADER_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_lock_header_512b.r1cs");
pub const HTTP_LOCK_HEADER_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_lock_header_512b.bin");

// Circuit 3
pub const HTTP_BODY_MASK_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_body_mask_512b.r1cs");
pub const HTTP_BODY_MASK_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_body_mask_512b.bin");

// Circuit 4
pub const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.r1cs");
pub const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.bin");

// Circuit 5
pub const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.r1cs");
pub const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.bin");

// Circuit 6
pub const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.r1cs");
pub const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.bin");

const AES_COUNTER: (&str, [u8; 128]) = ("ctr", [
  0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8,
  0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0, 11, 0, 0, 0, 12, 0, 0, 0, 13, 0, 0, 0, 14, 0, 0, 0, 15, 0, 0,
  0, 16, 0, 0, 0, 17, 0, 0, 0, 18, 0, 0, 0, 19, 0, 0, 0, 20, 0, 0, 0, 21, 0, 0, 0, 22, 0, 0, 0, 23,
  0, 0, 0, 24, 0, 0, 0, 25, 0, 0, 0, 26, 0, 0, 0, 27, 0, 0, 0, 28, 0, 0, 0, 29, 0, 0, 0, 30, 0, 0,
  0, 31, 0, 0, 0, 32,
]);
