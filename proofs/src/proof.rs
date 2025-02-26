//! # Proof Module
//!
//! This module provides the implementation for generating and verifying proofs.
//! It includes functionalities for serializing and deserializing folding proofs,
//! which are used in the proof system to ensure the integrity and correctness of computations.
//!
//! ## Structs
//!
//! - `FoldingProof<T, V>`: Represents a folding proof with a generic proof type `T` and verifier
//!   digest type `V`.
//!
//! ## Functions
//!
//! - `serialize`: Serializes a `FoldingProof` into a format suitable for storage or transmission.
//! - `deserialize`: Deserializes a `FoldingProof` from a stored or transmitted format back into its
//!   original form.

use hex;

use super::*;
use crate::program::CompressedProof;

/// Folding proof``
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FoldingProof<T, V> {
  /// Proof
  pub proof:           T,
  /// Verifier digest
  pub verifier_digest: V,
}

impl CompressedProof {
  /// Serializes a `FoldingProof` into a format suitable for storage or transmission.
  ///
  /// # Returns
  ///
  /// A `FoldingProof` with a `Vec<u8>` proof and a `String` verifier digest.
  pub fn serialize(self) -> Result<FoldingProof<Vec<u8>, String>, ProofError> {
    let proof = bincode::serialize(&self.proof)?;

    Ok(FoldingProof { proof, verifier_digest: hex::encode(self.verifier_digest.to_bytes()) })
  }
}

/// Folding proof implementation
impl FoldingProof<Vec<u8>, String> {
  /// Deserializes a `FoldingProof` from a stored or transmitted format back into its original form.
  ///
  /// # Returns
  ///
  /// A `FoldingProof` with a `CompressedSNARK<E1, S1, S2>` proof and a `F<G1>` verifier digest.
  pub fn deserialize(self) -> Result<CompressedProof, ProofError> {
    let proof = bincode::deserialize(&self.proof[..])?;

    Ok(FoldingProof {
      proof,
      verifier_digest: F::<G1>::from_bytes(
        &hex::decode(&self.verifier_digest).unwrap().try_into().unwrap(),
      )
      .unwrap(),
    })
  }
}
