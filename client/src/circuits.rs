pub const AES_PLAINTEXT: (&str, [u8; 320]) = ("plainText", [
  72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101, 110,
  116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106,
  115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 99,
  111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105,
  112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58,
  32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32, 34, 100, 97, 116,
  97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
  91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115,
  116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114,
  111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119,
  105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13,
  10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
  10, 32, 32, 32, 125, 13, 10, 125,
]);

pub const AES_GCM_FOLD_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/aes_gcm_fold/aes_gcm_fold.r1cs");
pub const AES_GCM_WASM: &str =
  "../../proofs/web_proof_circuits/aes_gcm_fold/aes_gcm_fold_js/aes_gcm_fold.wasm";

// TODO (sambhav): add these circuits later
// Circuit 0
// pub const AES_GCM_R1CS: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/aes_gcm/aes_gcm.r1cs");
// pub const AES_GCM_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/aes_gcm/aes_gcm.bin");

// // Circuit 1
// pub const HTTP_PARSE_AND_LOCK_START_LINE_R1CS: &[u8] = include_bytes!(
//   "../../proofs/web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.
// \    r1cs"
// );
// pub const HTTP_PARSE_AND_LOCK_START_LINE_WASM: &str =
//   "../../proofs/web_proof_circuits/http_parse_and_lock_start_line/\
//    http_parse_and_lock_start_line_js/http_parse_and_lock_start_line.wasm";
// pub const HTTP_PARSE_AND_LOCK_START_LINE_GRAPH: &[u8] = include_bytes!(
//   "../../proofs/web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.
// \    bin"
// );
// // Circuit 2
// pub const HTTP_LOCK_HEADER_R1CS: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/http_lock_header/http_lock_header.r1cs");
// pub const HTTP_LOCK_HEADER_WASM: &str =
//   "../../proofs/web_proof_circuits/http_lock_header/http_lock_header_js/http_lock_header.wasm";
// pub const HTTP_LOCK_HEADER_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/http_lock_header/http_lock_header.bin");

// // Circuit 3
// pub const HTTP_BODY_MASK_R1CS: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/http_body_mask/http_body_mask.r1cs");
// pub const HTTP_BODY_MASK_WASM: &str =
//   "../../proofs/web_proof_circuits/http_body_mask/http_body_mask_js/http_body_mask.wasm";

// pub const HTTP_BODY_MASK_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/http_body_mask/http_body_mask.bin");

// // Circuit 4
// pub const JSON_PARSE_R1CS: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/json_parse/json_parse.r1cs");
// pub const JSON_PARSE_WASM: &str =
//   "../../proofs/web_proof_circuits/json_parse/json_parse_js/json_parse.wasm";
// pub const JSON_PARSE_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/json_parse/json_parse.bin");

// // Circuit 5
// pub const JSON_MASK_OBJECT_R1CS: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/json_mask_object/json_mask_object.r1cs");
// pub const JSON_MASK_OBJECT_WASM: &str =
//   "../../proofs/web_proof_circuits/json_mask_object/json_mask_object_js/json_mask_object.wasm";
// pub const JSON_MASK_OBJECT_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/json_mask_object/json_mask_object.bin");

// // Circuit 6
// pub const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] = include_bytes!(
//   "../../proofs/web_proof_circuits/json_mask_array_index/json_mask_array_index.r1cs"
// );
// pub const JSON_MASK_ARRAY_INDEX_WASM: &str = "../../proofs/web_proof_circuits/\
//                                               json_mask_array_index/json_mask_array_index_js/\
//                                               json_mask_array_index.wasm";
// pub const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/json_mask_array_index/json_mask_array_index.
// bin");

// // circuit 7
// pub const EXTRACT_VALUE_R1CS: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/extract_value/extract_value.r1cs");
// pub const EXTRACT_VALUE_WASM: &str =
//   "../../proofs/web_proof_circuits/extract_value/extract_value_js/extract_value.wasm";
// pub const EXTRACT_VALUE_GRAPH: &[u8] =
//   include_bytes!("../../proofs/web_proof_circuits/extract_value/extract_value.bin");

// pub const HTTP_LOCK_VERSION: (&str, [u8; 8]) = ("beginning", [72, 84, 84, 80, 47, 49, 46, 49]);
// pub const HTTP_LOCK_STATUS: (&str, [u8; 3]) = ("middle", [50, 48, 48]);
// pub const HTTP_LOCK_MESSAGE: (&str, [u8; 2]) = ("final", [79, 75]);

// pub const HTTP_LOCK_HEADER_NAME: (&str, [u8; 12]) =
//   ("header", [99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101]);
// pub const HTTP_LOCK_HEADER_VALUE: (&str, [u8; 31]) = ("value", [
//   97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104,
// 97,   114, 115, 101, 116, 61, 117, 116, 102, 45, 56,
// ]);

// pub const JSON_MASK_KEY_DEPTH_1: (&str, [u8; 10]) =
//   ("key", [104, 101, 108, 108, 111, 0, 0, 0, 0, 0]); // "hello"
// pub const JSON_MASK_KEYLEN_DEPTH_1: (&str, [u8; 1]) = ("keyLen", [5]);
