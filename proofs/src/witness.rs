//! Used for computing the witnesses needed for HTTP and JSON elements of Web Proof NIVC
//! hashchain-based circuits.

use ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use program::manifest::{JsonKey, Request, Response};
use serde_json::Value;

use super::*;

/// Struct representing a byte or padding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ByteOrPad {
  Byte(u8),
  Pad,
}

impl ByteOrPad {
  /// Converts a slice of bytes to a vector of `ByteOrPad` with padding.
  pub fn from_bytes_with_padding(bytes: &[u8], padding: usize) -> Vec<ByteOrPad> {
    let mut result = bytes.iter().map(|&b| ByteOrPad::Byte(b)).collect::<Vec<_>>();
    result.extend(std::iter::repeat(ByteOrPad::Pad).take(padding));
    result
  }

  pub fn as_bytes(bytes: &[ByteOrPad]) -> Vec<u8> { bytes.iter().map(|b| u8::from(b)).collect() }
}

impl From<u8> for ByteOrPad {
  fn from(b: u8) -> Self { ByteOrPad::Byte(b) }
}

impl From<&u8> for ByteOrPad {
  fn from(b: &u8) -> Self { ByteOrPad::Byte(*b) }
}

impl From<&ByteOrPad> for halo2curves::bn256::Fr {
  fn from(b: &ByteOrPad) -> Self {
    match b {
      ByteOrPad::Byte(b) => halo2curves::bn256::Fr::from(*b as u64),
      ByteOrPad::Pad => -halo2curves::bn256::Fr::one(),
    }
  }
}

impl From<&ByteOrPad> for u8 {
  fn from(b: &ByteOrPad) -> Self {
    match b {
      ByteOrPad::Byte(b) => *b,
      ByteOrPad::Pad => 0,
    }
  }
}

/// Converts a field element to a base10 string.
fn field_element_to_base10_string(fe: F<G1>) -> String {
  BigInt::from_bytes_le(num_bigint::Sign::Plus, &fe.to_bytes()).to_str_radix(10)
}

impl Serialize for ByteOrPad {
  /// converts to field element using `to_field_element` and then to base10 string
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where S: serde::Serializer {
    serializer.serialize_str(field_element_to_base10_string(self.into()).as_str())
  }
}

impl PartialEq<u8> for ByteOrPad {
  fn eq(&self, other: &u8) -> bool {
    match self {
      ByteOrPad::Byte(b) => b == other,
      ByteOrPad::Pad => false,
    }
  }
}

/// compute private inputs for the JSON circuit.
/// # Arguments
/// - `masked_plaintext`: the masked JSON request/response padded with `-1` to nearest power of 2
/// - `mask_at`: the [`JsonMaskType`] of the JSON request/response to mask
/// # Returns
/// - the masked JSON request/response
pub fn compute_json_witness(masked_plaintext: &[ByteOrPad], mask_at: JsonKey) -> Vec<ByteOrPad> {
  // filter out padding and whitespace and convert to serde_json::Value
  let json_bytes = masked_plaintext
    .iter()
    .filter(|&&x| {
      !(matches!(x, ByteOrPad::Pad)
        || x == 0
        || matches!(x, ByteOrPad::Byte(b) if b.is_ascii_whitespace()))
    })
    .copied()
    .filter_map(|x| if let ByteOrPad::Byte(b) = x { Some(b) } else { None })
    .collect::<Vec<u8>>();
  let json: Value = serde_json::from_slice(&json_bytes).unwrap();

  // get the data to mask and convert to bytes
  let data = match mask_at {
    JsonKey::String(key) => json.get(key).unwrap(),
    JsonKey::Num(idx) => json.as_array().unwrap().get(idx).unwrap(),
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
      .filter(|&&x| {
        !(matches!(x, ByteOrPad::Pad)
          || x == 0
          || matches!(x, ByteOrPad::Byte(b) if b.is_ascii_whitespace()))
      })
      .copied()
      .collect::<Vec<ByteOrPad>>();
    filtered_body.truncate(filtered_data_bytes.len());
    if filtered_body == filtered_data_bytes && *byte == (*filtered_data_bytes.first().unwrap()) {
      start_idx = Some(idx);
    }
  }

  for (idx, byte) in masked_plaintext.iter().enumerate() {
    let mut filtered_body = masked_plaintext[..idx + 1]
      .iter()
      .filter(|&&x| {
        !(matches!(x, ByteOrPad::Pad)
          || x == 0
          || matches!(x, ByteOrPad::Byte(b) if b.is_ascii_whitespace()))
      })
      .copied()
      .collect::<Vec<ByteOrPad>>();
    filtered_body.reverse();
    filtered_body.truncate(filtered_data_bytes.len());
    filtered_body.reverse();
    if filtered_body == filtered_data_bytes && *byte == (*filtered_data_bytes.last().unwrap()) {
      end_idx = Some(idx);
    }
  }
  let start_idx = start_idx.unwrap();
  let end_idx = end_idx.unwrap();
  masked_plaintext
    .iter()
    .enumerate()
    .map(|(i, &x)| if i >= start_idx && i <= end_idx { x } else { ByteOrPad::Byte(0) })
    .collect::<Vec<ByteOrPad>>()
}

pub enum HttpMaskType {
  StartLine,
  Header(usize),
  Body,
}

/// compute private inputs for the HTTP circuit.
/// # Arguments
/// - `plaintext`: the plaintext HTTP request/response padded with `-1` to nearest power of 2
/// - `mask_at`: the [`HttpMaskType`] of the HTTP request/response to mask
/// # Returns
/// - the masked HTTP request/response
pub fn compute_http_witness(plaintext: &[ByteOrPad], mask_at: HttpMaskType) -> Vec<ByteOrPad> {
  let mut result = Vec::new();
  match mask_at {
    HttpMaskType::StartLine => {
      // Find the first CRLF sequence
      for i in 0..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          result = plaintext[..i].to_vec();
          break;
        }
      }
    },
    HttpMaskType::Header(idx) => {
      let mut current_header = 0;
      let mut start_pos = 0;

      // Skip the start line
      for i in 0..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          start_pos = i + 2;
          break;
        }
      }

      // Find the specified header
      let mut header_start_pos = start_pos;
      for i in start_pos..plaintext.len().saturating_sub(1) {
        if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
          if current_header == idx {
            // Copy the header line (including CRLF)
            result = plaintext[header_start_pos..i].to_vec();
            break;
          }

          // Check for end of headers (double CRLF)
          if i + 3 < plaintext.len() && plaintext[i + 2] == b'\r' && plaintext[i + 3] == b'\n' {
            break;
          }

          current_header += 1;
          header_start_pos = i + 2;
        }
      }
    },
    HttpMaskType::Body => {
      // Find double CRLF that marks start of body
      for i in 0..plaintext.len().saturating_sub(3) {
        if plaintext[i] == b'\r'
          && plaintext[i + 1] == b'\n'
          && plaintext[i + 2] == b'\r'
          && plaintext[i + 3] == b'\n'
        {
          // Copy everything after the double CRLF
          let body_start = i + 4;
          if body_start < plaintext.len() {
            result = plaintext[body_start..].to_vec();
          }
          break;
        }
      }
    },
  }
  result
}

pub fn compute_http_header_witness(
  plaintext: &[ByteOrPad],
  name: &[u8],
) -> (usize, Vec<ByteOrPad>) {
  let mut result = vec![ByteOrPad::Byte(0); plaintext.len()];

  let mut current_header = 0;
  let mut current_header_name = vec![];
  let mut start_pos = 0;

  // Skip the start line
  for i in 1..plaintext.len().saturating_sub(1) {
    if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
      start_pos = i + 2;
      break;
    }
  }

  // Find the specified header
  let mut header_start_pos = start_pos;
  for i in start_pos..plaintext.len().saturating_sub(1) {
    // find header name
    if plaintext[i] == b':' {
      current_header_name = plaintext[header_start_pos..i].to_vec();
    }
    // find next header line
    if plaintext[i] == b'\r' && plaintext[i + 1] == b'\n' {
      if current_header_name == name {
        // Copy the header line (including CRLF)
        result[header_start_pos..=i + 1].copy_from_slice(&plaintext[header_start_pos..=i + 1]);
        break;
      }

      // Check for end of headers (double CRLF)
      if i + 3 < plaintext.len() && plaintext[i + 2] == b'\r' && plaintext[i + 3] == b'\n' {
        break;
      }

      current_header += 1;
      header_start_pos = i + 2;
    }
  }

  (current_header, result)
}

/// Packs a chunk of 16 bytes into a field element
///
/// **Note**: if the chunk is fully padded, it will be ignored
fn bytepack(bytes: &[ByteOrPad]) -> Option<F<G1>> {
  let mut output = F::<G1>::ZERO;
  let mut is_padded_chunk = 0;
  for (idx, byte) in bytes.iter().enumerate() {
    let mut pow = F::<G1>::ONE;
    match byte {
      ByteOrPad::Byte(byte) => {
        output += F::<G1>::from(*byte as u64) * {
          for _ in 0..(8 * idx) {
            pow *= F::<G1>::from(2);
          }
          pow
        };
      },
      ByteOrPad::Pad => {
        is_padded_chunk += 1;
      },
    }
  }

  if is_padded_chunk == bytes.len() {
    None
  } else {
    Some(output)
  }
}

pub fn poseidon<const N: usize>(preimage: &[F<G1>]) -> F<G1> {
  let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(N).unwrap();

  // Convert each field element to bytes and collect into a Vec
  let byte_arrays: Vec<[u8; 32]> = preimage.iter().map(F::<G1>::to_bytes).collect();

  // Create slice of references to the bytes
  let byte_slices: Vec<&[u8]> = byte_arrays.iter().map(<[u8; 32]>::as_slice).collect();

  let hash: [u8; 32] = poseidon.hash_bytes_le(&byte_slices).unwrap();

  F::<G1>::from_repr(hash).unwrap()
}

/// Hashes byte array padded with -1 with Poseidon
///
/// **Note**:
/// - any chunk of 16 bytes that is fully padded with -1 will be ignored
/// - check [`bytepack`] for more details
pub fn data_hasher(preimage: &[ByteOrPad]) -> F<G1> {
  // Pack the input bytes in chunks of 16 into field elements
  let packed_inputs = preimage.chunks(16).map(bytepack).collect::<Vec<Option<F<G1>>>>();

  // Iterate over the packed inputs and hash them with Poseidon
  let mut hash_val = F::<G1>::ZERO;
  for packed_input in packed_inputs {
    if packed_input.is_none() {
      continue;
    }
    hash_val = poseidon::<2>(&[hash_val, packed_input.unwrap()]);
  }
  hash_val
}

pub fn polynomial_digest(bytes: &[u8], polynomial_input: F<G1>) -> F<G1> {
  let mut monomial = F::<G1>::ONE;
  let mut accumulated = F::<G1>::ZERO;
  for byte in bytes {
    accumulated += F::<G1>::from(u64::from(*byte)) * monomial;
    monomial *= polynomial_input;
  }
  accumulated
}

// TODO: Need to take into account if we enter into a value that is an object inside of object. So
// need a bit more than just `JsonMaskType` maybe.
pub fn json_tree_hasher(
  polynomial_input: F<G1>,
  key_sequence: &[JsonKey],
  max_stack_height: usize,
) -> (Vec<[F<G1>; 2]>, Vec<[F<G1>; 2]>) {
  assert!(key_sequence.len() <= max_stack_height); // TODO: This should be an error
  let mut stack = Vec::new();
  let mut tree_hashes = Vec::new();
  for val_type in key_sequence {
    match val_type {
      JsonKey::String(string) => {
        stack.push([F::<G1>::ONE, F::<G1>::ONE]);
        let mut string_hash = F::<G1>::ZERO;
        let mut monomial = F::<G1>::ONE;
        for byte in string.as_bytes() {
          string_hash += monomial * F::<G1>::from(u64::from(*byte));
          monomial *= polynomial_input;
        }
        tree_hashes.push([string_hash, F::<G1>::ZERO]);
      },
      JsonKey::Num(idx) => {
        tree_hashes.push([F::<G1>::ZERO, F::<G1>::ZERO]);
        stack.push([F::<G1>::from(2), F::<G1>::from(*idx as u64)]);
      },
    }
  }
  (stack, tree_hashes)
}

pub fn compress_tree_hash(
  polynomial_input: F<G1>,
  stack_and_tree_hashes: (Vec<[F<G1>; 2]>, Vec<[F<G1>; 2]>),
) -> F<G1> {
  assert!(stack_and_tree_hashes.0.len() == stack_and_tree_hashes.1.len()); // TODO: This should be an error
  let mut accumulated = F::<G1>::ZERO;
  let mut monomial = F::<G1>::ONE;
  for idx in 0..stack_and_tree_hashes.0.len() {
    accumulated += stack_and_tree_hashes.0[idx][0] * monomial;
    monomial *= polynomial_input;
    accumulated += stack_and_tree_hashes.0[idx][1] * monomial;
    monomial *= polynomial_input;
    accumulated += stack_and_tree_hashes.1[idx][0] * monomial;
    monomial *= polynomial_input;
  }
  accumulated
}

pub fn request_initial_digest(
  manifest_request: &Request,
  ciphertext: &[ByteOrPad],
) -> (F<G1>, F<G1>) {
  // First create a digest of the ciphertext itself
  let ciphertext_digest = data_hasher(&ciphertext);

  // TODO: This assumes the start line format here as well.
  // Then digest the start line using the ciphertext_digest as a random input
  let start_line_bytes =
    format!("{} {} {}", &manifest_request.method, &manifest_request.url, &manifest_request.version)
      .as_bytes()
      .to_vec();
  let start_line_digest = polynomial_digest(&start_line_bytes, ciphertext_digest);

  // Digest all the headers
  let header_bytes = headers_to_bytes(&manifest_request.headers);
  dbg!(&header_bytes);
  let headers_digest = header_bytes.iter().map(|bytes| polynomial_digest(bytes, ciphertext_digest));

  // Put all the digests into a vec
  let mut all_digests = vec![];
  all_digests.push(start_line_digest);
  headers_digest.into_iter().for_each(|d| all_digests.push(d));

  // Iterate through the material and sum up poseidon hashes of each as to not mix polynomials
  let manifest_digest =
    ciphertext_digest + all_digests.into_iter().map(|d| poseidon::<1>(&[d])).sum::<F<G1>>();
  (ciphertext_digest, manifest_digest)
}

// TODO: for now this is just doing the response
pub fn response_initial_digest(
  manifest_response: &Response,
  ciphertext: &[ByteOrPad],
  max_stack_height: usize,
) -> (F<G1>, F<G1>) {
  // First create a digest of the ciphertext itself
  let ciphertext_digest = data_hasher(&ciphertext);

  // TODO: This assumes the start line format here as well.
  // Then digest the start line using the ciphertext_digest as a random input
  let start_line_bytes = format!(
    "{} {} {}",
    &manifest_response.version, &manifest_response.status, &manifest_response.message
  )
  .as_bytes()
  .to_vec();
  let start_line_digest = polynomial_digest(&start_line_bytes, ciphertext_digest);

  // Digest all the headers
  let header_bytes = headers_to_bytes(&manifest_response.headers);
  let headers_digest = header_bytes.iter().map(|bytes| polynomial_digest(bytes, ciphertext_digest));

  // Digest the JSON sequence
  let json_tree_hash =
    json_tree_hasher(ciphertext_digest, &manifest_response.body.json, max_stack_height);
  let json_sequence_digest = compress_tree_hash(ciphertext_digest, json_tree_hash);

  // Put all the digests into a vec
  let mut all_digests = vec![];
  all_digests.push(json_sequence_digest);
  all_digests.push(start_line_digest);
  headers_digest.into_iter().for_each(|d| all_digests.push(d));

  // Iterate through the material and sum up poseidon hashes of each as to not mix polynomials
  let manifest_digest =
    ciphertext_digest + all_digests.into_iter().map(|d| poseidon::<1>(&[d])).sum::<F<G1>>();
  (ciphertext_digest, manifest_digest)
}

// TODO: Note, HTTP does not require a `:` and space between the name and value of a header, so we
// will have to deal with this somehow, but for now I'm assuming there's a space
fn headers_to_bytes(headers: &HashMap<String, String>) -> Vec<Vec<u8>> {
  headers.iter().map(|(k, v)| format!("{}: {}", k.clone(), v.clone()).as_bytes().to_vec()).collect()
}

#[cfg(test)]
mod tests {
  use num_bigint::BigUint;

  use super::*;
  use crate::{program::manifest::JsonKey, tests::mock_manifest};

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

  const TEST_CIPHERTEXT: [u8; 320] = [
    2, 125, 219, 141, 140, 93, 49, 129, 95, 178, 135, 109, 48, 36, 194, 46, 239, 155, 160, 70, 208,
    147, 37, 212, 17, 195, 149, 190, 38, 215, 23, 241, 84, 204, 167, 184, 179, 172, 187, 145, 38,
    75, 123, 96, 81, 6, 149, 36, 135, 227, 226, 254, 177, 90, 241, 159, 0, 230, 183, 163, 210, 88,
    133, 176, 9, 122, 225, 83, 171, 157, 185, 85, 122, 4, 110, 52, 2, 90, 36, 189, 145, 63, 122,
    75, 94, 21, 163, 24, 77, 85, 110, 90, 228, 157, 103, 41, 59, 128, 233, 149, 57, 175, 121, 163,
    185, 144, 162, 100, 17, 34, 9, 252, 162, 223, 59, 221, 106, 127, 104, 11, 121, 129, 154, 49,
    66, 220, 65, 130, 171, 165, 43, 8, 21, 248, 12, 214, 33, 6, 109, 3, 144, 52, 124, 225, 206,
    223, 213, 86, 186, 93, 170, 146, 141, 145, 140, 57, 152, 226, 218, 57, 30, 4, 131, 161, 0, 248,
    172, 49, 206, 181, 47, 231, 87, 72, 96, 139, 145, 117, 45, 77, 134, 249, 71, 87, 178, 239, 30,
    244, 156, 70, 118, 180, 176, 90, 92, 80, 221, 177, 86, 120, 222, 223, 244, 109, 150, 226, 142,
    97, 171, 210, 38, 117, 143, 163, 204, 25, 223, 238, 209, 58, 59, 100, 1, 86, 241, 103, 152,
    228, 37, 187, 79, 36, 136, 133, 171, 41, 184, 145, 146, 45, 192, 173, 219, 146, 133, 12, 246,
    190, 5, 54, 99, 155, 8, 198, 156, 174, 99, 12, 210, 95, 5, 128, 166, 118, 50, 66, 26, 20, 3,
    129, 232, 1, 192, 104, 23, 152, 212, 94, 97, 138, 162, 90, 185, 108, 221, 211, 247, 184, 253,
    15, 16, 24, 32, 240, 240, 3, 148, 89, 30, 54, 161, 131, 230, 161, 217, 29, 229, 251, 33, 220,
    230, 102, 131, 245, 27, 141, 220, 67, 16, 26,
  ];

  const TEST_HTTP_START_LINE: &[u8] = &[72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75];

  const TEST_HTTP_HEADER_0: &[u8] = &[
    99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99,
    97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61,
    117, 116, 102, 45, 56,
  ];

  const TEST_HTTP_HEADER_1: &[u8] = &[
    99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
    105, 112,
  ];

  #[test]
  fn test_compute_http_witness_start_line() {
    let bytes = compute_http_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      HttpMaskType::StartLine,
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_START_LINE);
  }

  #[test]
  fn test_compute_http_witness_header_0() {
    let bytes = compute_http_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Header(0),
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_HEADER_0);
  }

  #[test]
  fn test_compute_http_witness_header_1() {
    let bytes = compute_http_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Header(1),
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_HEADER_1);
  }

  #[test]
  fn test_compute_http_witness_body() {
    let bytes = compute_http_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Body,
    );
    assert_eq!(ByteOrPad::as_bytes(&bytes), TEST_HTTP_BODY);
  }

  #[test]
  fn test_compute_http_witness_name() {
    let (index, bytes_from_name) = compute_http_header_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      "Transfer-Encoding".as_bytes(),
    );
    let bytes_from_index = compute_http_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      HttpMaskType::Header(2),
    );
    assert_eq!(bytes_from_index, bytes_from_name);
    assert_eq!(index, 2);
  }

  #[test]
  fn test_compute_http_witness_name_not_present() {
    let (_, bytes_from_name) = compute_http_header_witness(
      &TEST_HTTP_BYTES.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      "pluto-rocks".as_bytes(),
    );
    assert_eq!(bytes_from_name, vec![0; TEST_HTTP_BYTES.len()]);
  }

  #[test]
  fn test_bytepack() {
    let pack0 = bytepack(&[0, 0, 0].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack0, Some(F::<G1>::from(0)));

    let pack1 = bytepack(&[1, 0, 0].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack1, Some(F::<G1>::from(1)));

    let pack2 = bytepack(&[0, 1, 0].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack2, Some(F::<G1>::from(256)));

    let pack3 = bytepack(&[0, 0, 1].into_iter().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>());
    assert_eq!(pack3, Some(F::<G1>::from(65536)));

    let pack4 = bytepack(&[ByteOrPad::Pad; 3]);
    assert_eq!(pack4, None);
  }

  #[test]
  fn test_poseidon() {
    // let hash = poseidon_chainer(&[bytepack(&[0]), bytepack(&[0])]);
    let hash = poseidon::<2>(&[F::<G1>::from(0), F::<G1>::from(0)]);
    assert_eq!(hash.to_bytes(), [
      100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228, 129, 123,
      242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32
    ]);

    let hash = poseidon::<2>(&[F::<G1>::from(69), F::<G1>::from(420)]);
    assert_eq!(hash.to_bytes(), [
      10, 230, 247, 95, 9, 23, 36, 117, 25, 37, 98, 141, 178, 220, 241, 100, 187, 169, 126, 226,
      80, 175, 17, 100, 232, 1, 29, 0, 165, 144, 139, 2,
    ]);
  }

  #[test]
  fn test_data_hasher() {
    let hash = data_hasher(&[ByteOrPad::Byte(0); 16]);
    assert_eq!(
      hash,
      F::<G1>::from_str_vartime(
        "14744269619966411208579211824598458697587494354926760081771325075741142829156"
      )
      .unwrap()
    );

    let hash = data_hasher(&[ByteOrPad::Pad; 16]);
    assert_eq!(hash, F::<G1>::ZERO);

    let mut hash_input = [ByteOrPad::Byte(0); 16];
    hash_input[0] = ByteOrPad::Byte(1);
    let hash = data_hasher(hash_input.as_ref());
    assert_eq!(hash, poseidon::<2>([F::<G1>::ZERO, F::<G1>::ONE].as_ref()));

    hash_input = [ByteOrPad::Byte(0); 16];
    hash_input[15] = ByteOrPad::Byte(1);
    let hash = data_hasher(hash_input.as_ref());
    assert_eq!(
      hash,
      poseidon::<2>(
        [
          F::<G1>::ZERO,
          F::<G1>::from_str_vartime("1329227995784915872903807060280344576").unwrap()
        ]
        .as_ref()
      )
    );
  }

  const TEST_HTTP_BODY: &[u8] = &[
    123, 13, 10, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97,
    116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13,
    10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34,
    58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
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

  const KEY0: &str = "data";
  const KEY1: &str = "items";
  const KEY2: &str = "profile";
  const KEY3: &str = "name";
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
    let masked_array = compute_json_witness(
      &TEST_HTTP_BODY.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      JsonKey::String(KEY0.to_string()),
    );
    assert_eq!(masked_array, MASKED_KEY0_ARRAY);
  }

  #[test]
  fn test_compute_json_masking_sequence() {
    let masked_array = compute_json_witness(
      &TEST_HTTP_BODY.iter().copied().map(ByteOrPad::from).collect::<Vec<ByteOrPad>>(),
      JsonKey::String(KEY0.to_string()),
    );
    assert_eq!(masked_array, MASKED_KEY0_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonKey::String(KEY1.to_string()));
    assert_eq!(masked_array, MASKED_KEY1_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonKey::Num(0));
    assert_eq!(masked_array, MASKED_ARR0_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonKey::String(KEY2.to_string()));
    assert_eq!(masked_array, MASKED_KEY2_ARRAY);
    let masked_array = compute_json_witness(&masked_array, JsonKey::String(KEY3.to_string()));
    assert_eq!(masked_array, MASKED_KEY3_ARRAY);
  }

  // TODO: This test doesn't actually test anything at all. Fix that.
  #[test]
  fn test_json_tree_hasher() {
    let key_sequence = vec![
      JsonKey::String(KEY0.to_string()),
      JsonKey::String(KEY1.to_string()),
      JsonKey::Num(0),
      JsonKey::String(KEY2.to_string()),
      JsonKey::String(KEY3.to_string()),
    ];
    let target_value = b"Taylor Swift";
    let polynomial_input = poseidon::<2>(&[F::<G1>::from(69), F::<G1>::from(420)]);
    println!("polynomial_input: {:?}", BigUint::from_bytes_le(&polynomial_input.to_bytes()));
    let stack_and_tree_hashes = json_tree_hasher(polynomial_input, &key_sequence, 10);

    println!("Stack (decimal):");
    for (i, pair) in stack_and_tree_hashes.0.iter().enumerate() {
      let num1 = BigUint::from_bytes_le(&pair[0].to_bytes());
      let num2 = BigUint::from_bytes_le(&pair[1].to_bytes());
      println!("  {i}: [{num1}, {num2}]");
    }

    println!("\nTree hashes (decimal):");
    for (i, pair) in stack_and_tree_hashes.1.iter().enumerate() {
      let num1 = BigUint::from_bytes_le(&pair[0].to_bytes());
      let num2 = BigUint::from_bytes_le(&pair[1].to_bytes());
      println!("  {i}: [{num1}, {num2}]");
    }

    let digest = compress_tree_hash(polynomial_input, stack_and_tree_hashes);
    println!("\nDigest (decimal):");
    println!("  {}", BigUint::from_bytes_le(&digest.to_bytes()));
  }

  // TODO: This test doesn't actually test anything at all. Fix that.
  #[test]
  fn test_initial_digest() {
    let test_ciphertext_padded =
      TEST_CIPHERTEXT.iter().map(|x| ByteOrPad::Byte(*x)).collect::<Vec<ByteOrPad>>();

    let (ct_digest, manifest_digest) =
      response_initial_digest(&mock_manifest().response, &test_ciphertext_padded, 5);
    println!("\nManifest Digest (decimal):");
    println!("  {}", BigUint::from_bytes_le(&manifest_digest.to_bytes()));

    assert_eq!(
      BigUint::from_bytes_le(&ct_digest.to_bytes()),
      BigUint::from_str(
        "5947802862726868637928743536818722886587721698845887498686185738472802646104"
      )
      .unwrap()
    );

    let (ct_digest, _manifest_digest) =
      request_initial_digest(&mock_manifest().request, &test_ciphertext_padded);
    assert_eq!(
      BigUint::from_bytes_le(&ct_digest.to_bytes()),
      BigUint::from_str(
        "5947802862726868637928743536818722886587721698845887498686185738472802646104"
      )
      .unwrap()
    );
  }
}
