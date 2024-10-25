pub const AES_GCM_FOLD_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/aes_gcm_fold/aes_gcm_fold.r1cs");
pub const AES_GCM_WASM: &str =
  "../../proofs/web_proof_circuits/aes_gcm_fold/aes_gcm_fold_js/aes_gcm_fold.wasm";

// Circuit 0
pub const AES_GCM_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/aes_gcm/aes_gcm.r1cs");
pub const AES_GCM_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/aes_gcm/aes_gcm.bin");

// Circuit 1
pub const HTTP_PARSE_AND_LOCK_START_LINE_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.\
   r1cs"
);
pub const HTTP_PARSE_AND_LOCK_START_LINE_WASM: &str =
  "../../proofs/web_proof_circuits/http_parse_and_lock_start_line/\
   http_parse_and_lock_start_line_js/http_parse_and_lock_start_line.wasm";
pub const HTTP_PARSE_AND_LOCK_START_LINE_GRAPH: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.\
   bin"
);
// Circuit 2
pub const HTTP_LOCK_HEADER_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/http_lock_header/http_lock_header.r1cs");
pub const HTTP_LOCK_HEADER_WASM: &str =
  "../../proofs/web_proof_circuits/http_lock_header/http_lock_header_js/http_lock_header.wasm";
pub const HTTP_LOCK_HEADER_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/http_lock_header/http_lock_header.bin");

// Circuit 3
pub const HTTP_BODY_MASK_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/http_body_mask/http_body_mask.r1cs");
pub const HTTP_BODY_MASK_WASM: &str =
  "../../proofs/web_proof_circuits/http_body_mask/http_body_mask_js/http_body_mask.wasm";

pub const HTTP_BODY_MASK_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/http_body_mask/http_body_mask.bin");

// Circuit 4
pub const JSON_PARSE_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/json_parse/json_parse.r1cs");
pub const JSON_PARSE_WASM: &str =
  "../../proofs/web_proof_circuits/json_parse/json_parse_js/json_parse.wasm";
pub const JSON_PARSE_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/json_parse/json_parse.bin");

// Circuit 5
pub const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/json_mask_object/json_mask_object.r1cs");
pub const JSON_MASK_OBJECT_WASM: &str =
  "../../proofs/web_proof_circuits/json_mask_object/json_mask_object_js/json_mask_object.wasm";
pub const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/json_mask_object/json_mask_object.bin");

// Circuit 6
pub const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] = include_bytes!(
  "../../proofs/web_proof_circuits/json_mask_array_index/json_mask_array_index.r1cs"
);
pub const JSON_MASK_ARRAY_INDEX_WASM: &str = "../../proofs/web_proof_circuits/\
                                              json_mask_array_index/json_mask_array_index_js/\
                                              json_mask_array_index.wasm";
pub const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/json_mask_array_index/json_mask_array_index.bin");

// circuit 7
pub const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/extract_value/extract_value.r1cs");
pub const EXTRACT_VALUE_WASM: &str =
  "../../proofs/web_proof_circuits/extract_value/extract_value_js/extract_value.wasm";
pub const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/extract_value/extract_value.bin");
