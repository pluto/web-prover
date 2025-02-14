use std::sync::{Arc, Mutex};

use alloy_primitives::utils::keccak256;
use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use client::origo::{SignBody, SignedVerificationReply, VerifyBody, VerifyReply};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use proofs::{
  circuits::{CIRCUIT_SIZE_512, MAX_STACK_HEIGHT},
  errors::ProofError,
  program::manifest::{compute_ciphertext_digest, InitialNIVCInputs},
  proof::FoldingProof,
  F, G1, G2,
};
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info};
use web_proof_circuits_witness_generator::polynomial_digest;
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  errors::{NotaryServerError, ProxyError},
  tls_parser::{Direction, Transcript, UnparsedMessage},
  tlsn::ProtocolUpgrade,
  verifier, SharedState,
};

#[derive(Deserialize)]
pub struct SignQuery {
  session_id: String,
}

#[derive(Serialize)]
pub struct SignReply {
  merkle_root: String,
  leaves:      Vec<String>,
  signature:   String,
  signature_r: String,
  signature_s: String,
  signature_v: u8,
  signer:      String,
}

#[derive(Serialize, Debug, Clone)]
pub struct VerifierInputs {
  request_messages:  Vec<Vec<u8>>,
  response_messages: Vec<Vec<u8>>,
}

// TODO: Don't need this method? But can use the logic to do the signature.
pub async fn sign(
  query: Query<SignQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<SignBody>,
) -> Result<Json<SignReply>, ProxyError> {
  let transcript = state.origo_sessions.lock().unwrap().get(&query.session_id).cloned().unwrap();

  let handshake_server_key = hex::decode(payload.handshake_server_key).unwrap();
  let handshake_server_iv = hex::decode(payload.handshake_server_iv).unwrap();

  let r = transcript.into_flattened()?.into_parsed(
    &handshake_server_key,
    &handshake_server_iv,
    None,
    None,
    None,
    None,
  );
  let parsed_transcript = match r {
    Ok(p) => p,
    Err(e) => {
      error!("error parsing transcript: {:?}", e);
      return Err(e);
    },
  };

  // Ensure the TLS certificate is valid and we're communicating with the correct server.
  match parsed_transcript.verify_certificate_sig() {
    Ok(_) => (),
    Err(e) => {
      error!("error verifying certificate sig: {:?}", e);
      return Err(e);
    },
  }

  // Determine possible request hash and response hash
  let (request_messages, response_messages) = parsed_transcript.get_ciphertext_hashes();

  // Log a verifier session for public inputs
  debug!("inserting with session_id={:?}", query.session_id);
  state
    .verifier_sessions
    .lock()
    .unwrap()
    .insert(query.session_id.clone(), VerifierInputs { request_messages, response_messages });

  // TODO check OSCP and CT (maybe)
  // TODO check target_name matches SNI and/or cert name (let's discuss)

  let leaves: Vec<String> = vec!["request".to_string(), "response".to_string()]; // TODO

  let leaf_hashes: Vec<[u8; 32]> =
    leaves.iter().map(|leaf| KeccakHasher::hash(leaf.as_bytes())).collect();

  let merkle_tree = MerkleTree::<KeccakHasher>::from_leaves(&leaf_hashes);
  let merkle_root = merkle_tree.root().unwrap();

  // need secp256k1 here for Solidity
  let (signature, recover_id) =
    state.origo_signing_key.clone().sign_prehash_recoverable(&merkle_root).unwrap();

  let signer_address =
    alloy_primitives::Address::from_public_key(state.origo_signing_key.verifying_key());

  let verifying_key =
    k256::ecdsa::VerifyingKey::recover_from_prehash(&merkle_root.clone(), &signature, recover_id)
      .unwrap();

  assert_eq!(state.origo_signing_key.verifying_key(), &verifying_key);

  // TODO is this right? we need lower form S for sure though
  let s = if signature.normalize_s().is_some() {
    hex::encode(signature.normalize_s().unwrap().to_bytes())
  } else {
    hex::encode(signature.s().to_bytes())
  };

  let response = SignReply {
    merkle_root: "0x".to_string() + &hex::encode(merkle_root),
    leaves,
    signature: "0x".to_string() + &hex::encode(signature.to_der().as_bytes()),
    signature_r: "0x".to_string() + &hex::encode(signature.r().to_bytes()),
    signature_s: "0x".to_string() + &s,

    // the good old +27
    // https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA-tryRecover-bytes32-bytes-
    signature_v: recover_id.to_byte() + 27,
    signer: "0x".to_string() + &hex::encode(signer_address),
  };

  Ok(Json(response))
}

pub fn sign_verification(
  query: VerifyReply,
  State(state): State<Arc<SharedState>>,
) -> Result<Json<SignedVerificationReply>, ProxyError> {
  // TODO check OSCP and CT (maybe)
  // TODO check target_name matches SNI and/or cert name (let's discuss)

  let leaf_hashes = vec![
    KeccakHasher::hash(query.value.as_bytes()),
    KeccakHasher::hash(serde_json::to_string(&query.manifest)?.as_bytes()),
  ];
  let merkle_tree = MerkleTree::<KeccakHasher>::from_leaves(&leaf_hashes);
  let merkle_root = merkle_tree.root().unwrap();

  // need secp256k1 here for Solidity
  let (signature, recover_id) =
    state.origo_signing_key.clone().sign_prehash_recoverable(&merkle_root).unwrap();

  let signer_address =
    alloy_primitives::Address::from_public_key(state.origo_signing_key.verifying_key());

  let verifying_key =
    k256::ecdsa::VerifyingKey::recover_from_prehash(&merkle_root.clone(), &signature, recover_id)
      .unwrap();

  assert_eq!(state.origo_signing_key.verifying_key(), &verifying_key);

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

  Ok(Json(response))
}

#[derive(Clone)]
struct KeccakHasher;

impl Hasher for KeccakHasher {
  type Hash = [u8; 32];

  fn hash(data: &[u8]) -> Self::Hash { keccak256(data).into() }
}

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id:  String,
  target_host: String,
  target_port: u16,
}

/// Handles protocol upgrade requests for notarization sessions.
///
/// This function serves as an entry point for both WebSocket and TCP protocol upgrades,
/// routing the connection to the appropriate notarization handler based on the upgrade type.
///
/// # Arguments
///
/// * `protocol_upgrade` - The protocol upgrade request (WebSocket or TCP)
/// * `query` - Query parameters containing notarization session details
/// * `state` - Shared application state wrapped in an Arc
///
/// # Returns
///
/// Returns an axum [`Response`] that will handle the protocol upgrade
///
/// # Notes
///
/// - For WebSocket upgrades, forwards to `websocket_notarize`
/// - For TCP upgrades, forwards to `tcp_notarize`
/// - Session ID is logged at the start of each connection
pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

  info!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(socket, session_id, query.target_host.clone(), query.target_port, state)
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, session_id, query.target_host.clone(), query.target_port, state)
    }),
  }
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

  // Case: first message from server after request
  let actual_ciphertext_digest =
    compute_ciphertext_digest::<CIRCUIT_SIZE>(&request_messages, &response_messages[1..]);
  if actual_ciphertext_digest == expected_ciphertext_digest {
    debug!("Ciphertext found in response[1..] permutation");
    return response_messages[1..].to_vec();
  }

  // Case: receiving message & not the last message. Drop last message, it's close notify.
  let actual_ciphertext_digest = compute_ciphertext_digest::<CIRCUIT_SIZE>(
    &request_messages,
    &response_messages[0..response_messages.len() - 1],
  );
  if actual_ciphertext_digest == expected_ciphertext_digest {
    debug!("Ciphertext found in response[0..-1] permutation");
    return response_messages[0..response_messages.len() - 1].to_vec();
  }

  // Case: first message from server after request
  // Case: receiving message & not the last message. Drop last message, it's close notify.
  let actual_ciphertext_digest = compute_ciphertext_digest::<CIRCUIT_SIZE>(
    &request_messages,
    &response_messages[1..response_messages.len() - 1],
  );
  if actual_ciphertext_digest == expected_ciphertext_digest {
    debug!("Ciphertext found in response[1..-1] permutation");
    return response_messages[1..response_messages.len() - 1].to_vec();
  }

  panic!("Ciphertext not found in any permutation");
}

pub async fn verify(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<VerifyBody>,
) -> Result<Json<SignedVerificationReply>, ProxyError> {
  let proof = FoldingProof {
    proof:           payload.origo_proof.proof.proof.clone(),
    verifier_digest: payload.origo_proof.proof.verifier_digest.clone(),
  }
  .deserialize();

  debug!("verifier_digest: {:?}", proof.verifier_digest.clone());

  // Form verifier inputs
  let verifier_inputs =
    state.verifier_sessions.lock().unwrap().get(&payload.session_id).cloned().unwrap();

  // TODO: might be incorrect to check ciphertext in this manner, but for now, we play along
  // Find the correct ciphertext from permutation of the ciphertexts
  let expected_ciphertext_digest =
    F::<G1>::from_bytes(&payload.origo_proof.ciphertext_digest).unwrap();
  let response_messages = find_ciphertext_permutation::<CIRCUIT_SIZE_512>(
    expected_ciphertext_digest,
    verifier_inputs.request_messages.clone(),
    verifier_inputs.response_messages.clone(),
  );

  // DEBUG: Use this digest to pin the proving behavior. You must also override
  // `client/src/tls.rs#decrypt_tls_ciphertext`
  //
  // let ciphertext_digest = F::<G1>::from_bytes(&hex::decode(
  //   "66ab857c95c11767913c36e9341dbe4d46915616a67a5f47379e06848411b32b"
  // ).unwrap().try_into().unwrap()).unwrap();

  debug!("circuits {:?}", payload.origo_proof.rom.circuit_data);
  debug!("rom {:?}", payload.origo_proof.rom.rom);
  let verifier = &state.verifier;

  let InitialNIVCInputs { initial_nivc_input, ciphertext_digest, .. } =
    payload.manifest.initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE_512>(
      &verifier_inputs.request_messages,
      &response_messages,
    )?;
  assert_eq!(ciphertext_digest, expected_ciphertext_digest);

  let (z0_primary, _) = verifier.setup_params.extend_public_inputs(
    &verifier::flatten_rom(payload.origo_proof.rom.rom),
    &initial_nivc_input.to_vec(),
  )?;
  let z0_secondary = vec![F::<G2>::from(0)];

  let verify_output = match proof.proof.verify(
    &verifier.setup_params.public_params,
    &verifier.verifier_key,
    &z0_primary,
    &z0_secondary,
  ) {
    Ok((output, _)) => {
      // TODO: I think that `output[10] == ciphertext_digest` should also check? But I'm not 100%
      // sure. Right now it doesn't and that's probably because we have the split up request and
      // response.
      // TODO: We should also check that the full extended ROM was correct? Although maybe that's
      // implicit in this.
      if output[5] == F::<G1>::from(0)
        && output[8] == F::<G1>::from(0)
        && output[0]
          == polynomial_digest(
            &payload.origo_proof.value.clone().unwrap().as_bytes(),
            ciphertext_digest,
            0,
          )
        && output[10] == ciphertext_digest
      {
        // TODO: add the manifest digest?
        debug!("output from verifier: {output:?}");
        // TODO: This unwrap should be safe for now as the value will always be present at this
        // point
        VerifyReply { value: payload.origo_proof.value.unwrap(), manifest: payload.manifest }
      } else {
        // TODO (autoparallel): May want richer error content here to say what was wrong.
        return Err(ProofError::VerifyFailed().into());
      }
    },
    Err(e) => {
      error!("Error verifying request proof: {:?}", e);
      return Err(ProofError::SuperNova(e).into());
    },
  };

  sign_verification(verify_output, State(state))
}

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
