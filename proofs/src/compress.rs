use std::io::{Read, Write};

use arecibo::supernova::{
  snark::{CompressedSNARK, ProverKey, VerifierKey},
  PublicParams,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use program::ProgramOutput;

use super::*;

pub struct SerializedProof(pub Vec<u8>);

pub struct CompressedVerifier<T> {
  pub proof:         T,
  pub prover_key:    ProverKey<E1, S1, S2>,
  pub verifier_key:  VerifierKey<E1, S1, S2>,
  pub public_params: PublicParams<E1>,
}

impl From<ProgramOutput> for CompressedVerifier<CompressedSNARK<E1, S1, S2>> {
  fn from(program_output: ProgramOutput) -> CompressedVerifier<CompressedSNARK<E1, S1, S2>> {
    let (prover_key, verifier_key) =
      CompressedSNARK::<E1, S1, S2>::setup(&program_output.public_params).unwrap();
    let proof = CompressedSNARK::<E1, S1, S2>::prove(
      &program_output.public_params,
      &prover_key,
      &program_output.recursive_snark,
    )
    .unwrap();

    CompressedVerifier {
      proof,
      prover_key,
      verifier_key,
      public_params: program_output.public_params,
    }
  }
}

impl CompressedVerifier<CompressedSNARK<E1, S1, S2>> {
  pub fn serialize_and_compress(self) -> CompressedVerifier<SerializedProof> {
    let bincode = bincode::serialize(&self.proof).unwrap();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&bincode).unwrap();

    CompressedVerifier {
      proof:         SerializedProof(encoder.finish().unwrap()),
      prover_key:    self.prover_key,
      verifier_key:  self.verifier_key,
      public_params: self.public_params,
    }
  }
}

impl CompressedVerifier<SerializedProof> {
  pub fn decompress_and_serialize(self) -> CompressedVerifier<CompressedSNARK<E1, S1, S2>> {
    let mut decoder = ZlibDecoder::new(&self.proof.0[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();

    CompressedVerifier {
      proof:         bincode::deserialize(&decompressed).unwrap(),
      prover_key:    self.prover_key,
      verifier_key:  self.verifier_key,
      public_params: self.public_params,
    }
  }
}
