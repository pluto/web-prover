use std::io::{Read, Write};

use arecibo::supernova::snark::CompressedSNARK;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

use super::*;

pub struct Proof<T>(pub T);

impl Proof<CompressedSNARK<E1, S1, S2>> {
  pub fn serialize_and_compress(self) -> Proof<Vec<u8>> {
    let bincode = bincode::serialize(&self.0).unwrap();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&bincode).unwrap();

    Proof(encoder.finish().unwrap())
  }
}

impl Proof<Vec<u8>> {
  pub fn decompress_and_serialize(self) -> Proof<CompressedSNARK<E1, S1, S2>> {
    let mut decoder = ZlibDecoder::new(&self.0[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();

    Proof(bincode::deserialize(&decompressed).unwrap())
  }
}
