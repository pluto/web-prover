use tiny_keccak::{Hasher, Keccak};

pub fn keccak_digest(bytes: &[u8]) -> [u8; 32] {
  let mut hasher = Keccak::v256();
  let mut output = [0u8; 32];

  hasher.update(&bytes);
  hasher.finalize(&mut output);

  output
}
