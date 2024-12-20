use super::*;
use hex;


#[derive(Debug, Serialize)]
pub struct Proof<T, V> {
  pub proof: T,
  pub verifier_digest: V,
}

impl Proof<CompressedSNARK<E1, S1, S2>, F<G1>> {
  pub fn serialize(self) -> Proof<Vec<u8>, String> {
    let proof = bincode::serialize(&self.proof).unwrap();

    Proof{
      proof,
      verifier_digest: hex::encode(self.verifier_digest.to_bytes())
    }
  }
}

impl Proof<Vec<u8>, String> {
  pub fn deserialize(self) -> Proof<CompressedSNARK<E1, S1, S2>, F<G1>> {
    // TODO: move unwrap => err. 
    let proof = bincode::deserialize(&self.proof[..]).unwrap();

    Proof{
      proof,
      verifier_digest: F::<G1>::from_bytes(&hex::decode(&self.verifier_digest).unwrap().try_into().unwrap()).unwrap()
    }
  }
}
