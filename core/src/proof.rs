use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedVerificationReply {
  pub merkle_leaves: Vec<String>,
  pub digest:        String,
  pub signature:     String,
  pub signature_r:   String,
  pub signature_s:   String,
  pub signature_v:   u8,
  pub signer:        String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeeProof {
  pub data:      TeeProofData,
  pub signature: SignedVerificationReply,
}

impl TryFrom<&[u8]> for TeeProof {
  type Error = serde_json::Error;

  fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> { serde_json::from_slice(bytes) }
}

impl TryFrom<TeeProof> for Vec<u8> {
  type Error = serde_json::Error;

  fn try_from(proof: TeeProof) -> Result<Self, Self::Error> { serde_json::to_vec(&proof) }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeeProofData {
  pub value:         String,
  pub manifest_hash: Vec<u8>,
}
