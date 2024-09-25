use std::io::{Read, Write};

use arecibo::supernova::{
  snark::{CompressedSNARK, ProverKey, VerifierKey},
  PublicParams, RecursiveSNARK,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

use super::*;

pub struct CompressedVerifier {
  pub proof:        CompressedSNARK<E1, S1, S2>,
  pub prover_key:   ProverKey<E1, S1, S2>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

impl CompressedVerifier {
  pub fn new(
    public_params: &PublicParams<E1>,
    recursive_snark: &RecursiveSNARK<E1>,
  ) -> CompressedVerifier {
    let (prover_key, verifier_key) = CompressedSNARK::<E1, S1, S2>::setup(public_params).unwrap();
    let proof =
      CompressedSNARK::<E1, S1, S2>::prove(public_params, &prover_key, recursive_snark).unwrap();

    CompressedVerifier { proof, prover_key, verifier_key }
  }
}

pub fn serialize_and_compress(compressed_snark: &CompressedSNARK<E1, S1, S2>) -> Vec<u8> {
  let bincode = bincode::serialize(compressed_snark).unwrap();
  let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
  encoder.write_all(&bincode).unwrap();
  encoder.finish().unwrap()
}

pub fn decompress_and_deserialize(compressed_proof: &[u8]) -> CompressedSNARK<E1, S1, S2> {
  let mut decoder = ZlibDecoder::new(compressed_proof);
  let mut decompressed = Vec::new();
  decoder.read_to_end(&mut decompressed).unwrap();

  bincode::deserialize(&decompressed).unwrap()
}
