//! This test module is effectively testing a static (comptime) circuit dispatch supernova program

use ff::PrimeField;
use program::utils::remap_inputs;
use proving_ground::supernova::RecursiveSNARK;

use super::*;

mod rustwitness;
mod witnesscalc;

const ROM: &[u64] = &[0, 1, 2, 0, 1, 2];

const ADD_INTO_ZEROTH_R1CS: &[u8] =
  include_bytes!("../../examples/circuit_data/addIntoZeroth.r1cs");
const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/squareZeroth.r1cs");
const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("../../examples/circuit_data/swapMemory.r1cs");

const INIT_PUBLIC_INPUT: [u64; 2] = [1, 2];
const MAX_ROM_LENGTH: usize = 10;

#[ignore]
#[test]
#[tracing_test::traced_test]
fn test_end_to_end_proofs() {
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

  panic!("TODO: Fix this test.");
  // let read = std::fs::read("examples/aes_http_json_extract.json").unwrap();
  // let read = std::fs::read("examples/universal.json").unwrap();
  // let program_data: ProgramData = serde_json::from_slice(&read).unwrap();

  // let ProgramOutput { recursive_snark, .. } = program::run(&program_data);

  // let res = "\"Taylor Swift\"";
  // let final_mem =
  //   res.as_bytes().into_iter().map(|val| F::<G1>::from(*val as u64)).collect::<Vec<F<G1>>>();

  // assert_eq!(recursive_snark.zi_primary()[..res.len()], final_mem);
}
