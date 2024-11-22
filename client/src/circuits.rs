use proofs::program::manifest::AESEncryptionInput;
use tls_client2::{
  origo::{OrigoConnection, WitnessData},
  CipherSuite, Decrypter2, ProtocolVersion,
};
use tls_core::msgs::{base::Payload, enums::ContentType, message::OpaqueMessage};
use tracing::{debug, trace};

use crate::errors::ClientErrors;

pub const JSON_MAX_ROM_LENGTH: usize = 45;
pub const JSON_MAX_ROM_1024B_LENGTH: usize = 75;

// Circuit 0
pub const AES_GCM_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b.r1cs");
pub const AES_GCM_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/aes_gctr_nivc_512b.bin");

// Circuit 1
pub const HTTP_NIVC_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_nivc_512b.r1cs");
pub const HTTP_NIVC_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/http_nivc_512b.bin");

// Circuit 2
pub const JSON_MASK_OBJECT_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.r1cs");
pub const JSON_MASK_OBJECT_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_object_512b.bin");

// Circuit 3
pub const JSON_MASK_ARRAY_INDEX_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.r1cs");
pub const JSON_MASK_ARRAY_INDEX_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_mask_array_index_512b.bin");

// Circuit 4
pub const EXTRACT_VALUE_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.r1cs");
pub const EXTRACT_VALUE_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_512b/json_extract_value_512b.bin");

// -------------------------------------------------------------------------------------------- //
// -------------------------------------- 1024B circuits -------------------------------------- //

// CIRCUIT 1
pub const AES_GCM_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/aes_gctr_nivc_1024b.r1cs");
pub const AES_GCM_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/aes_gctr_nivc_1024b.bin");
// CIRCUIT 2
pub const HTTP_NIVC_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_nivc_1024b.bin");
pub const HTTP_NIVC_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/http_nivc_1024b.r1cs");
// Circuit 3
pub const JSON_MASK_OBJECT_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_object_1024b.r1cs");
pub const JSON_MASK_OBJECT_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_object_1024b.bin");
// Circuit 4
pub const JSON_MASK_ARRAY_INDEX_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_array_index_1024b.r1cs");
pub const JSON_MASK_ARRAY_INDEX_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_mask_array_index_1024b.bin");
// Circuit 5
pub const EXTRACT_VALUE_1024_R1CS: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extract_value_1024b.r1cs");
pub const EXTRACT_VALUE_1024_GRAPH: &[u8] =
  include_bytes!("../../proofs/web_proof_circuits/target_1024b/json_extract_value_1024b.bin");

pub(crate) fn get_circuit_inputs_from_witness(
  witness: &WitnessData,
) -> Result<(AESEncryptionInput, AESEncryptionInput), ClientErrors> {
  // - get AES key, IV, request ciphertext, request plaintext, and AAD -
  let key: [u8; 16] = witness.request.aes_key[..16].try_into()?;
  let iv: [u8; 12] = witness.request.aes_iv[..12].try_into()?;

  // Get the request ciphertext, request plaintext, and AAD
  let request_ciphertext = hex::decode(witness.request.ciphertext[0].as_bytes())?;

  let request_decrypter = Decrypter2::new(key, iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = request_decrypter.decrypt_tls13_aes(
    &OpaqueMessage {
      typ:     ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_3,
      payload: Payload::new(request_ciphertext.clone()), /* TODO (autoparallel): old way didn't
                                                          * introduce a clone */
    },
    0,
  )?;

  let aad = hex::decode(meta.additional_data.to_owned())?;
  let mut padded_aad = vec![0; 16 - aad.len()];
  padded_aad.extend(aad);

  let request_plaintext = plaintext.payload.0.to_vec();
  let request_ciphertext = request_ciphertext[..request_plaintext.len()].to_vec();
  trace!("Raw request plaintext: {:?}", request_plaintext);

  // ----------------------------------------------------------------------------------------------------------------------- //
  // response preparation
  let mut response_plaintext = vec![];
  let mut response_ciphertext = vec![];
  let response_key: [u8; 16] = witness.response.aes_key[..16].try_into().unwrap();
  let response_iv: [u8; 12] = witness.response.aes_iv[..12].try_into().unwrap();
  let response_dec =
    Decrypter2::new(response_key, response_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);

  for (i, ct_chunk) in witness.response.ciphertext.iter().enumerate() {
    let ct_chunk = hex::decode(ct_chunk).unwrap();

    // decrypt ciphertext
    let (plaintext, meta) = response_dec
      .decrypt_tls13_aes(
        &OpaqueMessage {
          typ:     ContentType::ApplicationData,
          version: ProtocolVersion::TLSv1_3,
          payload: Payload::new(ct_chunk.clone()),
        },
        (i + 1) as u64,
      )
      .unwrap();

    // push ciphertext
    let pt = plaintext.payload.0.to_vec();
    response_ciphertext.extend_from_slice(&ct_chunk[..pt.len()]);

    response_plaintext.extend(pt);
    let aad = hex::decode(meta.additional_data.to_owned()).unwrap();
    let mut padded_aad = vec![0; 16 - aad.len()];
    padded_aad.extend(&aad);
  }
  debug!("response plaintext: {:?}", response_plaintext);

  Ok((
    AESEncryptionInput {
      key,
      iv,
      aad: padded_aad.clone(),
      plaintext: request_plaintext,
      ciphertext: request_ciphertext,
    },
    AESEncryptionInput {
      key:        response_key,
      iv:         response_iv,
      aad:        padded_aad, // TODO: use response's AAD
      plaintext:  response_plaintext,
      ciphertext: response_ciphertext,
    },
  ))
}
