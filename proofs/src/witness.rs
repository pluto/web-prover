//! Used for computing the witnesses needed for a Web Proof NIVC chain for the hashchain-based
//! circuits. In theory, we don't need to do this for AES since that is handled elsewhere, so this
//! is solely going to be for the HTTP and JSON elements of the chain.

use num_bigint::{BigInt, ToBigInt};

pub enum JsonMaskType {
  Object(Vec<u8>),
  ArrayIndex(usize),
}

pub fn compute_json_witness(masked_plaintext: Vec<u8>, mask_at: JsonMaskType) -> (Vec<u8>, BigInt) {
  todo!()
}

pub fn compute_http_body_mask_witness(masked_plaintext: Vec<u8>) -> (Vec<u8>, BigInt) { todo!() }

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use serde_json::Value;
  use tracing_subscriber::filter;

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

  const TEST_HTTP_BODY: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 123, 13, 10, 32, 32, 32, 34,
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

  const TEST_HTTP_SIZED: [u8; 188] = [
    123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91, 13, 10,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34,
    44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102,
    105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105,
    102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
    10, 32, 32, 32, 125, 13, 10, 125,
  ];

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
    let json_bytes = TEST_HTTP_BODY
      .iter()
      .skip_while(|&&x| x == 0 || x.is_ascii_whitespace())
      .copied()
      .collect::<Vec<u8>>();
    let json: Value = serde_json::from_slice(&json_bytes).unwrap();
    // dbg!(&json);
    let data: &Value = json.get("data").unwrap();
    // dbg!(&data);
    let data_bytes = serde_json::to_string(&data).unwrap();
    let data_bytes = data_bytes.as_bytes();

    let filtered_data_bytes = data_bytes
      .iter()
      .filter(|&&x| !x == 0 || !x.is_ascii_whitespace())
      .copied()
      .collect::<Vec<u8>>();
    dbg!(&filtered_data_bytes);
    let mut start_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    // Iterate through the original bytes and find the subobject
    for (idx, byte) in TEST_HTTP_BODY.iter().enumerate() {
      // If we find that the byte we are at matches the first byte of our subobject, then we should
      // see if this string matches
      let mut filtered_body = TEST_HTTP_BODY[idx..]
        .iter()
        .filter(|&&x| !x == 0 || !x.is_ascii_whitespace())
        .copied()
        .collect::<Vec<u8>>();
      filtered_body.truncate(filtered_data_bytes.len());
      //   if idx == 132 {
      //     dbg!(&filtered_body);
      //   }
      if filtered_data_bytes == filtered_body && filtered_data_bytes.first().unwrap() == byte {
        start_idx = Some(idx);
      }
    }
    for (idx, byte) in TEST_HTTP_BODY.iter().enumerate() {
      let mut filtered_body = TEST_HTTP_BODY[..idx + 1]
        .iter()
        .filter(|&&x| !x == 0 || !x.is_ascii_whitespace())
        .copied()
        .collect::<Vec<u8>>();
      filtered_body.reverse();
      filtered_body.truncate(filtered_data_bytes.len());
      filtered_body.reverse();
      if idx == 319 {
        dbg!(&filtered_body);
        dbg!(filtered_data_bytes.last());
        dbg!(byte);
      }

      if filtered_data_bytes == filtered_body && filtered_data_bytes.last().unwrap() == byte {
        end_idx = Some(idx);
      }
    }
    dbg!(start_idx);
    dbg!(end_idx);
    let start_idx = start_idx.unwrap();
    let end_idx = end_idx.unwrap();
    let masked_array = TEST_HTTP_BODY
      .iter()
      .enumerate()
      .map(|(i, &x)| if i >= start_idx && i <= end_idx { x } else { 0 })
      .collect::<Vec<u8>>();
    // dbg!(&TEST_HTTP_BODY[start_idx..end_idx]);
    dbg!(masked_array);
  }
}

const MASKED_ARRAY: [u8; 320] = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91,
  13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116,
  34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111,
  102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105,
  102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10,
  32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13, 10,
  32, 32, 32, 125, 0, 0, 0,
];
