use std::{
  fs,
  sync::{Arc, Mutex},
};

use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use client::origo::{SignBody, VerifyBody};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use k256::{
  ecdsa::SigningKey as Secp256k1SigningKey, elliptic_curve::rand_core, pkcs8::DecodePrivateKey,
};
use proofs::{
  circuits::{CIRCUIT_SIZE_512, MAX_STACK_HEIGHT},
  errors::ProofError,
  program::manifest::{compute_ciphertext_digest, InitialNIVCInputs},
  proof::FoldingProof,
  F, G1, G2,
};
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info};
use uuid::Uuid;
use web_proof_circuits_witness_generator::polynomial_digest;
use web_prover_core::proof::SignedVerificationReply;
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  errors::{NotaryServerError, ProxyError},
  origo_verifier,
  tls_parser::{Direction, Transcript, UnparsedMessage},
  tlsn::ProtocolUpgrade,
  verifier::VerifyOutput,
  SharedState,
};

pub struct OrigoSigningKey(pub(crate) Secp256k1SigningKey);

impl OrigoSigningKey {
  pub fn load(private_key_pem_path: &str) -> Self {
    if private_key_pem_path.is_empty() {
      info!("Using ephemeral origo signing key");
      Self::ephemeral()
    } else {
      info!("Using origo signing key: {}", private_key_pem_path);
      let raw = fs::read_to_string(private_key_pem_path).unwrap();
      Self(Secp256k1SigningKey::from_pkcs8_pem(&raw).unwrap())
    }
  }

  pub fn ephemeral() -> Self { Self(Secp256k1SigningKey::random(&mut rand_core::OsRng)) }
}

#[derive(Deserialize)]
pub struct SignQuery {
  session_id: Uuid,
}

#[derive(Serialize, Debug, Clone)]
pub struct VerifierInputs {
  request_messages:  Vec<Vec<u8>>,
  response_messages: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id:  Uuid,
  target_host: String,
  target_port: u16,
}

fn find_ciphertext_permutation<const CIRCUIT_SIZE: usize>(
  expected_ciphertext_digest: F<G1>,
  request_messages: Vec<Vec<u8>>,
  response_messages: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
  // check ciphertext digest in all permutations of request and response messages
  // four possible permutations
  // 1. drop first message from response, changecipherspec from server
  // 2. drop last message from response, close notify from server
  // - request, response[1..]
  // - request, response[0..-1]
  // - request, response[1..-1]

  // Case: receiving message & not the last message. Drop last message, it's close notify.
  let actual_ciphertext_digest = compute_ciphertext_digest::<CIRCUIT_SIZE>(
    &request_messages,
    &response_messages[0..response_messages.len() - 1],
  );
  if actual_ciphertext_digest == expected_ciphertext_digest {
    debug!("Ciphertext found in response[0..-1] permutation");
    return response_messages[0..response_messages.len() - 1].to_vec();
  }

  for i in 0..response_messages.len() {
    // Case: remove first messages from response, changecipherspec from server
    let actual_ciphertext_digest =
      compute_ciphertext_digest::<CIRCUIT_SIZE>(&request_messages, &response_messages[i..]);
    if actual_ciphertext_digest == expected_ciphertext_digest {
      debug!("Ciphertext found in response[{i}..] permutation");
      return response_messages[i..].to_vec();
    }

    // Case: first message from server after request
    // Case: receiving message & not the last message. Drop last message, it's close notify.
    let actual_ciphertext_digest = compute_ciphertext_digest::<CIRCUIT_SIZE>(
      &request_messages,
      &response_messages[i..response_messages.len() - 1],
    );
    if actual_ciphertext_digest == expected_ciphertext_digest {
      debug!("Ciphertext found in response[{i}..-1] permutation");
      return response_messages[i..response_messages.len() - 1].to_vec();
    }
  }

  panic!("Ciphertext not found in any permutation");
}

// pub async fn verify(
//   State(state): State<Arc<SharedState>>,
//   extract::Json(payload): extract::Json<VerifyBody>,
// ) -> Result<Json<SignedVerificationReply>, NotaryServerError> {
//   let proof = FoldingProof {
//     proof:           payload.origo_proof.proof.proof.clone(),
//     verifier_digest: payload.origo_proof.proof.verifier_digest.clone(),
//   }
//   .deserialize()?;

//   debug!("verifier_digest: {:?}", proof.verifier_digest.clone());

//   // Form verifier inputs
//   let verifier_inputs =
//     state.verifier_sessions.lock().unwrap().get(&payload.session_id).cloned().unwrap();

//   // TODO: might be incorrect to check ciphertext in this manner, but for now, we play along
//   // Find the correct ciphertext from permutation of the ciphertexts
//   let expected_ciphertext_digest =
//     F::<G1>::from_bytes(&payload.origo_proof.ciphertext_digest).unwrap();
//   let response_messages = find_ciphertext_permutation::<CIRCUIT_SIZE_512>(
//     expected_ciphertext_digest,
//     verifier_inputs.request_messages.clone(),
//     verifier_inputs.response_messages.clone(),
//   );

//   // DEBUG: Use this digest to pin the proving behavior. You must also override
//   // `client/src/tls.rs#decrypt_tls_ciphertext`
//   //
//   // let ciphertext_digest = F::<G1>::from_bytes(&hex::decode(
//   //   "66ab857c95c11767913c36e9341dbe4d46915616a67a5f47379e06848411b32b"
//   // ).unwrap().try_into().unwrap()).unwrap();

//   debug!("circuits {:?}", payload.origo_proof.rom.circuit_data);
//   debug!("rom {:?}", payload.origo_proof.rom.rom);
//   let verifier = &state.verifier;

//   let InitialNIVCInputs { initial_nivc_input, ciphertext_digest, .. } =
//     payload.manifest.initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE_512>(
//       &verifier_inputs.request_messages,
//       &response_messages,
//     )?;
//   assert_eq!(ciphertext_digest, expected_ciphertext_digest);

//   let (z0_primary, _) = verifier.setup_params.extend_public_inputs(
//     &origo_verifier::flatten_rom(payload.origo_proof.rom.rom),
//     &initial_nivc_input.to_vec(),
//   )?;
//   let z0_secondary = vec![F::<G2>::from(0)];

//   let verify_output = match proof.proof.verify(
//     &verifier.setup_params.public_params,
//     &verifier.verifier_key,
//     &z0_primary,
//     &z0_secondary,
//   ) {
//     Ok((output, _)) => {
//       // TODO: We should also check that the full extended ROM was correct? Although maybe that's
//       // implicit in this.
//       if output[5] != F::<G1>::from(0) {
//         debug!("HTTP header match: {:?}", output[5]);
//         return Err(ProofError::VerifyFailed(String::from("HTTP header match failed")).into());
//       } else if output[8] != F::<G1>::from(0) {
//         debug!("JSON final state: {:?}", output[8]);
//         return Err(ProofError::VerifyFailed(String::from("JSON final state invalid")).into());
//       } else if output[10] != ciphertext_digest {
//         debug!("expected ciphertext_digest: {:?}", ciphertext_digest);
//         debug!("calculated ciphertext digest {:?}", output[10]);
//         return Err(
//           ProofError::VerifyFailed(String::from("invalid calculated ciphertext digest")).into(),
//         );
//       } else if output[0]
//         != polynomial_digest(
//           payload.origo_proof.value.clone().unwrap().as_bytes(),
//           ciphertext_digest,
//           0,
//         )
//       {
//         debug!("output[0]: {:?}", output[0]);
//         debug!("value: {:?}", payload.origo_proof.value.clone().unwrap());
//         debug!(
//           "value_polynomial_digest: {:?}",
//           polynomial_digest(
//             payload.origo_proof.value.clone().unwrap().as_bytes(),
//             ciphertext_digest,
//             0,
//           )
//         );
//         return Err(ProofError::VerifyFailed(String::from("inccorect final circuit
// value")).into());       } else {
//         // TODO: add the manifest digest?
//         debug!("output from verifier: {output:?}");
//         // This unwrap should be safe for now as the value will always be present
//         VerifyOutput {
//           value:    payload.origo_proof.value.unwrap(),
//           manifest: payload.manifest.into(),
//         }
//       }
//     },
//     Err(e) => {
//       error!("Error verifying proof: {:?}", e);
//       return Err(ProofError::SuperNova(e).into());
//     },
//   };

//   crate::verifier::sign_verification(verify_output, State(state)).map(Json)
// }

pub async fn websocket_notarize(
  socket: WebSocket,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to websocket connection");
  let mut stream = WsStream::new(socket.into_inner()).compat();
  match proxy_service(&mut stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using websocket!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using websocket: {err}");
    },
  }
}

pub async fn tcp_notarize(
  mut stream: TokioIo<Upgraded>,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to tcp connection");
  match proxy_service(&mut stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

pub async fn proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin>(
  socket: S,
  session_id: &str,
  target_host: &str,
  target_port: u16,
  state: Arc<SharedState>,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  info!("Connecting to target {}:{}", target_host, target_port);
  let mut tcp_stream = TcpStream::connect(format!("{}:{}", target_host, target_port))
    .await
    .expect("Failed to connect to TCP server");

  let (mut tcp_read, mut tcp_write) = tcp_stream.split();

  let (mut socket_read, mut socket_write) = tokio::io::split(socket);

  let messages = Arc::new(Mutex::new(Vec::new()));
  let client_to_server = async {
    let mut buf = [0u8; 8192];
    loop {
      match socket_read.read(&mut buf).await {
        Ok(0) => break,
        Ok(n) => {
          debug!("sending to server len={:?}, data={:?}", n, hex::encode(&buf[..n]));
          tcp_write.write_all(&buf[..n]).await?;
          let mut buffer = messages.lock().unwrap();
          buffer.push(UnparsedMessage { direction: Direction::Sent, payload: buf[..n].to_vec() })
        },
        Err(e) => return Err(e),
      }
    }

    // MATT: this shutsdown the target connection, but not the socket, right?
    tcp_write.shutdown().await?;
    Ok(())
  };

  let server_to_client = async {
    let mut buf = [0u8; 8192];
    loop {
      match tcp_read.read(&mut buf).await {
        Ok(0) => break,
        Ok(n) => {
          debug!("sending to client len={:?}, data={:?}", n, hex::encode(&buf[..n]));
          socket_write.write_all(&buf[..n]).await?;
          let mut buffer = messages.lock().unwrap();
          buffer
            .push(UnparsedMessage { direction: Direction::Received, payload: buf[..n].to_vec() })
        },
        Err(e) => return Err(e),
      }
    }

    // MATT: this shuts down the socket connection, can't do that here
    // socket_write.shutdown().await.unwrap();
    Ok(())
  };

  use futures::{future::select, pin_mut};
  pin_mut!(client_to_server, server_to_client);
  let _ = select(client_to_server, server_to_client).await.factor_first().0;

  state
    .origo_sessions
    .lock()
    .unwrap()
    .insert(session_id.to_string(), Transcript { payload: messages.lock().unwrap().to_vec() });

  Ok(())
}
