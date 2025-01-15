use hex;

use super::*;

#[derive(Debug, Serialize)]
pub struct FoldingProof<T, V> {
  pub proof:           T,
  pub verifier_digest: V,
}

impl FoldingProof<CompressedSNARK<E1, S1, S2>, F<G1>> {
  pub fn serialize(self) -> FoldingProof<Vec<u8>, String> {
    let proof = bincode::serialize(&self.proof).unwrap();

    FoldingProof { proof, verifier_digest: hex::encode(self.verifier_digest.to_bytes()) }
  }
}

impl FoldingProof<Vec<u8>, String> {
  pub fn deserialize(self) -> FoldingProof<CompressedSNARK<E1, S1, S2>, F<G1>> {
    // TODO: move unwrap => err.
    let proof = bincode::deserialize(&self.proof[..]).unwrap();

    FoldingProof {
      proof,
      verifier_digest: F::<G1>::from_bytes(
        &hex::decode(&self.verifier_digest).unwrap().try_into().unwrap(),
      )
      .unwrap(),
    }
  }
}
