use super::*;

pub struct Proof<T>(pub T);

impl Proof<CompressedSNARK<E1, S1, S2>> {
  pub fn serialize(self) -> Proof<Vec<u8>> {
    let bincode = bincode::serialize(&self.0).unwrap();
    Proof(bincode)
  }
}

// TODO (autoparallel): This needs renamed but I don't want to do it in this PR.
impl Proof<Vec<u8>> {
  pub fn deserialize(self) -> Proof<CompressedSNARK<E1, S1, S2>> {
    Proof(bincode::deserialize(&self.0[..]).unwrap())
  }
}
