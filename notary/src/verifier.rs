use std::sync::Arc;

use alloy_primitives::utils::keccak256;
use client::SignedVerificationReply;
use proofs::program::manifest::Manifest;
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::errors::ProxyError;

pub struct Verifier {
  pub setup_params: SetupParams<Online>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

use crate::{errors::NotaryServerError, SharedState, State};

#[derive(Clone)]
struct KeccakHasher;

impl Hasher for KeccakHasher {
  type Hash = [u8; 32];

  fn hash(data: &[u8]) -> Self::Hash { keccak256(data).into() }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyQuery<T: AsRef<[u8]>> {
  pub value:    T,
  pub manifest: Manifest,
}

pub fn sign_verification<T: AsRef<[u8]>>(
  query: VerifyQuery<T>,
  State(state): State<Arc<SharedState>>,
) -> Result<SignedVerificationReply, NotaryServerError> {
  // TODO check OSCP and CT (maybe)
  // TODO check target_name matches SNI and/or cert name (let's discuss)

  let leaf_hashes = vec![
    KeccakHasher::hash(query.value.as_ref()),
    KeccakHasher::hash(serde_json::to_string(&query.manifest)?.as_bytes()),
  ];
  let merkle_tree = MerkleTree::<KeccakHasher>::from_leaves(&leaf_hashes);
  let merkle_root = merkle_tree.root().unwrap();

  // need secp256k1 here for Solidity
  let (signature, recover_id) =
    state.origo_signing_key.0.sign_prehash_recoverable(&merkle_root).unwrap();

  let signer_address =
    alloy_primitives::Address::from_public_key(state.origo_signing_key.0.verifying_key());

  let verifying_key =
    k256::ecdsa::VerifyingKey::recover_from_prehash(&merkle_root.clone(), &signature, recover_id)
      .unwrap();

  assert_eq!(state.origo_signing_key.0.verifying_key(), &verifying_key);

  // TODO is this right? we need lower form S for sure though
  let s = if signature.normalize_s().is_some() {
    hex::encode(signature.normalize_s().unwrap().to_bytes())
  } else {
    hex::encode(signature.s().to_bytes())
  };

  let response = SignedVerificationReply {
    merkle_leaves: vec![
      "0x".to_string() + &hex::encode(leaf_hashes[0]),
      "0x".to_string() + &hex::encode(leaf_hashes[1]),
    ],
    digest:        "0x".to_string() + &hex::encode(merkle_root),
    signature:     "0x".to_string() + &hex::encode(signature.to_der().as_bytes()),
    signature_r:   "0x".to_string() + &hex::encode(signature.r().to_bytes()),
    signature_s:   "0x".to_string() + &s,

    // the good old +27
    // https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA-tryRecover-bytes32-bytes-
    signature_v: recover_id.to_byte() + 27,
    signer:      "0x".to_string() + &hex::encode(signer_address),
  };

  Ok(response)
}
