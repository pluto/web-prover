//! Used for computing the witnesses needed for a Web Proof NIVC chain for the hashchain-based
//! circuits. In theory, we don't need to do this for AES since that is handled elsewhere, so this
//! is solely going to be for the HTTP and JSON elements of the chain.

use ff::PrimeField;
use serde_json::Value;

use super::*;
pub enum JsonMaskType {
  Object(Vec<u8>),
  ArrayIndex(usize),
}

pub fn compute_json_witness(masked_plaintext: &[u8], mask_at: JsonMaskType) -> Vec<u8> {
  let json_bytes = masked_plaintext
    .iter()
    .filter(|&&x| !(x == 0 || x.is_ascii_whitespace()))
    .copied()
    .collect::<Vec<u8>>();
  let json: Value = serde_json::from_slice(&json_bytes).unwrap();
  let data = match mask_at {
    JsonMaskType::Object(key) => json.get(String::from_utf8(key).unwrap()).unwrap(),
    JsonMaskType::ArrayIndex(idx) => json.as_array().unwrap().get(idx).unwrap(),
  };
  let data_bytes = serde_json::to_string(&data).unwrap();
  let data_bytes = data_bytes.as_bytes();

  let filtered_data_bytes = data_bytes
    .iter()
    .filter(|&&x| !(x == 0 || x.is_ascii_whitespace()))
    .copied()
    .collect::<Vec<u8>>();
  let mut start_idx: Option<usize> = None;
  let mut end_idx: Option<usize> = None;
  // Iterate through the original bytes and find the subobject
  for (idx, byte) in masked_plaintext.iter().enumerate() {
    // If we find that the byte we are at matches the first byte of our subobject, then we should
    // see if this string matches
    let mut filtered_body = masked_plaintext[idx..]
      .iter()
      .filter(|&&x| !(x == 0 || x.is_ascii_whitespace()))
      .copied()
      .collect::<Vec<u8>>();
    filtered_body.truncate(filtered_data_bytes.len());
    if filtered_data_bytes == filtered_body && filtered_data_bytes.first().unwrap() == byte {
      start_idx = Some(idx);
    }
  }
  for (idx, byte) in masked_plaintext.iter().enumerate() {
    let mut filtered_body = masked_plaintext[..idx + 1]
      .iter()
      .filter(|&&x| !(x == 0 || x.is_ascii_whitespace()))
      .copied()
      .collect::<Vec<u8>>();
    filtered_body.reverse();
    filtered_body.truncate(filtered_data_bytes.len());
    filtered_body.reverse();
    if filtered_data_bytes == filtered_body && filtered_data_bytes.last().unwrap() == byte {
      end_idx = Some(idx);
    }
  }
  let start_idx = start_idx.unwrap();
  let end_idx = end_idx.unwrap();
  masked_plaintext
    .iter()
    .enumerate()
    .map(|(i, &x)| if i >= start_idx && i <= end_idx { x } else { 0 })
    .collect::<Vec<u8>>()
}

pub enum HttpMaskType {
  StartLine,
  Header(usize),
  Body,
}
pub fn compute_http_witness(plaintext: &[u8], mask_at: HttpMaskType) -> Vec<u8> {
  let mut result = vec![0u8; plaintext.len()];
  match mask_at {
    HttpMaskType::StartLine => {
      // Find the first CRLF sequence
      for i in 1..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          // Copy bytes from start to the end of CRLF
          result[..=i + 1].copy_from_slice(&plaintext[..=i + 1]);
          break;
        }
      }
    },
    HttpMaskType::Header(idx) => {
      let mut current_header = 0;
      let mut start_pos = 0;

      // Skip the start line
      for i in 1..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          start_pos = i + 2;
          break;
        }
      }

      // Find the specified header
      for i in start_pos..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          if current_header == idx {
            // Copy the header line (including CRLF)
            result[start_pos..=i + 1].copy_from_slice(&plaintext[start_pos..=i + 1]);
            break;
          }

          // Check for end of headers (double CRLF)
          if i + 3 < plaintext.len() && plaintext[i + 2] == b'\r' && plaintext[i + 3] == b'\n' {
            break;
          }

          current_header += 1;
          start_pos = i + 2;
        }
      }
    },
    HttpMaskType::Body => {
      // Find double CRLF that marks start of body
      for i in 1..plaintext.len().saturating_sub(3) {
        if plaintext[i] == b'\r'
          && plaintext[i + 1] == b'\n'
          && plaintext[i + 2] == b'\r'
          && plaintext[i + 3] == b'\n'
        {
          // Copy everything after the double CRLF
          let body_start = i + 4;
          if body_start < plaintext.len() {
            result[body_start..].copy_from_slice(&plaintext[body_start..]);
          }
          break;
        }
      }
    },
  }
  result
}

pub fn bytepack(bytes: &[u8]) -> F<G1> {
  let mut output = F::<G1>::ZERO;
  assert!(bytes.len() <= 16);
  for (idx, byte) in bytes.iter().enumerate() {
    let mut pow = F::<G1>::ONE;
    output += F::<G1>::from(*byte as u64) * {
      for _ in 0..(8 * idx) {
        pow *= F::<G1>::from(2);
      }
      pow
    };
  }
  output
}
use light_poseidon::{Poseidon, PoseidonBytesHasher};
pub fn poseidon_chainer(preimage: &[F<G1>]) -> F<G1> {
  let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(2).unwrap();

  // Convert each field element to bytes and collect into a Vec
  let byte_arrays: Vec<[u8; 32]> = preimage.iter().map(|x| x.to_bytes()).collect();

  // Create slice of references to the bytes
  let byte_slices: Vec<&[u8]> = byte_arrays.iter().map(|arr| arr.as_slice()).collect();

  let hash: [u8; 32] = poseidon.hash_bytes_le(&byte_slices).unwrap();

  F::<G1>::from_repr(hash).unwrap()
}

pub fn data_hasher(preimage: &[u8]) -> F<G1> {
  assert_eq!(preimage.len() % 16, 0);

  let packed_inputs = preimage.chunks(16).map(|chunk| bytepack(chunk)).collect::<Vec<F<G1>>>();
  let mut hash_val = F::<G1>::ZERO;
  for packed_input in packed_inputs {
    hash_val = poseidon_chainer(&[hash_val, packed_input]);
  }
  hash_val
}

      // Skip the start line
      for i in 1..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          start_pos = i + 2;
          break;
        }
      }

      // Find the specified header
      for i in start_pos..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          if current_header == idx {
            // Copy the header line (excluding CRLF)
            result[start_pos..=i - 1].copy_from_slice(&plaintext[start_pos..=i - 1]);
            break;
          }

          // Check for end of headers (double CRLF)
          if i + 3 < plaintext.len() && plaintext[i + 2] == b'\r' && plaintext[i + 3] == b'\n' {
            break;
          }

          current_header += 1;
          start_pos = i + 2;
        }
      }
    },
    HttpMaskType::Body => {
      // Find double CRLF that marks start of body
      for i in 1..plaintext.len().saturating_sub(3) {
        if plaintext[i] == b'\r'
          && plaintext[i + 1] == b'\n'
          && plaintext[i + 2] == b'\r'
          && plaintext[i + 3] == b'\n'
        {
          // Copy everything after the double CRLF
          let body_start = i + 4;
          if body_start < plaintext.len() {
            result[body_start..].copy_from_slice(&plaintext[body_start..]);
          }
          break;
        }
      }
    },
  }
  result
}

pub fn bytepack(bytes: &[u8]) -> F<G1> {
  let mut output = F::<G1>::ZERO;
  assert!(bytes.len() <= 16);
  for (idx, byte) in bytes.iter().enumerate() {
    let mut pow = F::<G1>::ONE;
    output += F::<G1>::from(*byte as u64) * {
      for _ in 0..(8 * idx) {
        pow *= F::<G1>::from(2);
      }
      pow
    };
  }
  output
}
use light_poseidon::{Poseidon, PoseidonBytesHasher};
pub fn poseidon_chainer(preimage: &[F<G1>]) -> F<G1> {
  let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(2).unwrap();

  // Convert each field element to bytes and collect into a Vec
  let byte_arrays: Vec<[u8; 32]> = preimage.iter().map(|x| x.to_bytes()).collect();

  // Create slice of references to the bytes
  let byte_slices: Vec<&[u8]> = byte_arrays.iter().map(|arr| arr.as_slice()).collect();

  let hash: [u8; 32] = poseidon.hash_bytes_le(&byte_slices).unwrap();

  //   F::<G1>::from_repr(hash)
  //   todo!()
  F::<G1>::from_repr(hash).unwrap()
}

#[cfg(test)]
mod tests {

  use super::*;

  const TEST_HTTP_BYTES: &[u8] = &[
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101,
    110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
    47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13,
    10, 99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103,
    122, 105, 112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105,
    110, 103, 58, 32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32,
    34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101,
    109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34,
    65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121,
    108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
  ];

  const TEST_HTTP_START_LINE: &[u8] = &[
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
  ];

  const TEST_HTTP_HEADER_0: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 111, 110, 116, 101, 110, 116, 45, 116,
    121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111,
    110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];

  const TEST_HTTP_HEADER_1: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
    105, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];

  #[test]
  fn test_compute_http_witness_start_line() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::StartLine);
    assert_eq!(bytes, TEST_HTTP_START_LINE);
  }

  #[test]
  fn test_compute_http_witness_header_0() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::Header(0));
    assert_eq!(bytes, TEST_HTTP_HEADER_0);
  }

  #[test]
  fn test_compute_http_witness_header_1() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::Header(1));
    assert_eq!(bytes, TEST_HTTP_HEADER_1);
  }

  #[test]
  fn test_compute_http_witness_body() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::Body);
    assert_eq!(bytes, TEST_HTTP_BODY);
  }

  #[test]
  fn test_bytepack() {
    let pack0 = bytepack(&[0, 0, 0]);
    assert_eq!(pack0, F::<G1>::from(0));

    let pack1 = bytepack(&[1, 0, 0]);
    assert_eq!(pack1, F::<G1>::from(1));

    let pack2 = bytepack(&[0, 1, 0]);
    assert_eq!(pack2, F::<G1>::from(256));

    let pack3 = bytepack(&[0, 0, 1]);
    assert_eq!(pack3, F::<G1>::from(65536));
  }

  #[test]
  fn test_poseidon() {
    // let hash = poseidon_chainer(&[bytepack(&[0]), bytepack(&[0])]);
    let hash = poseidon_chainer(&[F::<G1>::from(0), F::<G1>::from(0)]);
    assert_eq!(hash.to_bytes(), [
      100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228, 129, 123,
      242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32
    ]);

    let hash = poseidon_chainer(&[F::<G1>::from(69), F::<G1>::from(420)]);
    assert_eq!(hash.to_bytes(), [
      10, 230, 247, 95, 9, 23, 36, 117, 25, 37, 98, 141, 178, 220, 241, 100, 187, 169, 126, 226,
      80, 175, 17, 100, 232, 1, 29, 0, 165, 144, 139, 2,
    ]);
  }

  const TEST_HTTP_BYTES: &[u8] = &[
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101,
    110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
    47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13,
    10, 99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103,
    122, 105, 112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105,
    110, 103, 58, 32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32,
    34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101,
    109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34,
    65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121,
    108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
  ];

  const TEST_HTTP_START_LINE: &[u8] = &[
    72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
  ];

  const TEST_HTTP_HEADER_0: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 111, 110, 116, 101, 110, 116, 45, 116,
    121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111,
    110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];

  const TEST_HTTP_HEADER_1: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
    105, 112, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];

  #[test]
  fn test_compute_http_witness_start_line() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::StartLine);
    assert_eq!(bytes, TEST_HTTP_START_LINE);
  }

  #[test]
  fn test_compute_http_witness_header_0() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::Header(0));
    assert_eq!(bytes, TEST_HTTP_HEADER_0);
  }

  #[test]
  fn test_compute_http_witness_header_1() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::Header(1));
    assert_eq!(bytes, TEST_HTTP_HEADER_1);
  }

  #[test]
  fn test_compute_http_witness_body() {
    let bytes = compute_http_witness(TEST_HTTP_BYTES, HttpMaskType::Body);
    assert_eq!(bytes, TEST_HTTP_BODY);
  }

  #[test]
  fn test_bytepack() {
    let pack0 = bytepack(&[0, 0, 0]);
    assert_eq!(pack0, F::<G1>::from(0));

    let pack1 = bytepack(&[1, 0, 0]);
    assert_eq!(pack1, F::<G1>::from(1));

    let pack2 = bytepack(&[0, 1, 0]);
    assert_eq!(pack2, F::<G1>::from(256));

    let pack3 = bytepack(&[0, 0, 1]);
    assert_eq!(pack3, F::<G1>::from(65536));
  }

  #[test]
  fn test_poseidon() {
    // let hash = poseidon_chainer(&[bytepack(&[0]), bytepack(&[0])]);
    let hash = poseidon_chainer(&[F::<G1>::from(0), F::<G1>::from(0)]);
    assert_eq!(hash.to_bytes(), [
      100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228, 129, 123,
      242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32
    ]);

    let hash = poseidon_chainer(&[F::<G1>::from(69), F::<G1>::from(420)]);
    assert_eq!(hash.to_bytes(), [
      10, 230, 247, 95, 9, 23, 36, 117, 25, 37, 98, 141, 178, 220, 241, 100, 187, 169, 126, 226,
      80, 175, 17, 100, 232, 1, 29, 0, 165, 144, 139, 2,
    ]);
  }

  #[test]
  fn test_data_hasher() {
    let hash = data_hasher(TEST_HTTP_BYTES);
    dbg!(hash);
  }

  const TEST_HTTP_BODY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 34,
    100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109,
    115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65,
    114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121,
    108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
  ];

  const MASKED_KEY0_ARRAY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
    91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105,
    115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112,
    114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32,
    83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 93, 13, 10, 32, 32, 32, 125, 0, 0, 0,
  ];
  const MASKED_KEY1_ARRAY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 91, 13, 10, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108,
    101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116,
    34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
  ];
  const MASKED_ARR0_ARRAY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34,
    100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32,
    123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109,
    101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];
  const MASKED_KEY2_ARRAY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34,
    110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34,
    13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];

  const MASKED_KEY3_ARRAY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];

  const KEY0: &[u8] = "data".as_bytes();
  const KEY1: &[u8] = "items".as_bytes();
  const KEY2: &[u8] = "profile".as_bytes();
  const KEY3: &[u8] = "name".as_bytes();
  // HTTP/1.1 200 OK
  // content-type: application/json; charset=utf-8
  // content-encoding: gzip
  // Transfer-Encoding: chunked
  //
  // {
  //    "data": {
  //        "items": [
  //            {
  //                "data": "Artist",
  //                "profile": {
  //                    "name": "Taylor Swift"
  //                }
  //            }
  //        ]
  //    }
  // }
  #[test]
  fn test_compute_json_witness() {
    let masked_array = compute_json_witness(TEST_HTTP_BODY, JsonMaskType::Object(KEY0.to_vec()));
    assert_eq!(masked_array, MASKED_KEY0_ARRAY);
  }

  #[test]
  fn test_compute_json_masking_sequence() {
    let masked_array = compute_json_witness(TEST_HTTP_BODY, JsonMaskType::Object(KEY0.to_vec()));
    assert_eq!(masked_array, MASKED_KEY0_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonMaskType::Object(KEY1.to_vec()));
    assert_eq!(masked_array, MASKED_KEY1_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonMaskType::ArrayIndex(0));
    assert_eq!(masked_array, MASKED_ARR0_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonMaskType::Object(KEY2.to_vec()));
    assert_eq!(masked_array, MASKED_KEY2_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonMaskType::Object(KEY3.to_vec()));
    assert_eq!(masked_array, MASKED_KEY3_ARRAY);
  }
}
