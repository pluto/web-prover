use std::{
  sync::{Arc, Mutex},
  time::SystemTime,
};

use alloy_primitives::utils::keccak256;
use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info, trace};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  errors::{NotaryServerError, ProxyError},
  tlsn::ProtocolUpgrade,
  SharedState, tls_parser,
};

#[derive(Debug, Clone)]
pub enum Direction {
  Sent,
  Received,
}

#[derive(Debug, Clone)]
struct Message {
  direction: Direction,
  payload: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct OrigoSession {
  messages: Vec<Message>,
  _timestamp: SystemTime,
}

impl OrigoSession {
  pub fn get_transcript(&self) -> Vec<u8> {
    let mut out = Vec::new();
    for m in self.messages.clone() {
      out.extend(m.payload);
    }
    out
  }
}

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

#[derive(Deserialize, Debug, Clone)]
pub struct SignBody {
  handshake_server_iv:  String,
  handshake_server_key: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct VerifyBody {
  proof:           Vec<u8>,
  ciphertext_hash: Vec<u8>,
}

#[derive(Serialize, Debug, Clone)]
pub struct VerifyReply {
  valid: bool,
  // TODO: need a signature
}

pub async fn sign(
  query: Query<SignQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<SignBody>,
) -> Result<Json<SignReply>, ProxyError> {
  let session = state.origo_sessions.lock().unwrap().get(&query.session_id).unwrap().clone();
  let (messages, encrypted_messages) = tls_parser::extract_tls_handshake(&session.get_transcript(), payload.handshake_server_key, payload.handshake_server_iv)?;

  // Ensure the TLS certificate is valid and we're communicating with the correct server.
  let result = tls_parser::verify_certificate_sig(messages);


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
use std::collections::HashMap;

use client_side_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  program::data::{CircuitData, NotExpanded, Offline, Online, ProgramData},
  proof::Proof,
  witness::{data_hasher, ByteOrPad},
  E1, F, G1, G2, S1, S2,
};

use crate::circuits;

pub async fn verify(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<VerifyBody>,
) -> Result<Json<VerifyReply>, ProxyError> {
  let proof = Proof(payload.proof).decompress_and_serialize();

  let max_ciphertext = 1024;
  // TODO (tracy): Move this into a method on the proofs crate, probably also move the circuits.rs
  // file.
  let setup_data_large = circuits::construct_setup_data(max_ciphertext);
  let decryption_label = String::from("PLAINTEXT_AUTHENTICATION");
  let http_label = String::from("HTTP_VERIFICATION");
  let rom_data = HashMap::from([
    (decryption_label.clone(), CircuitData { opcode: 0 }),
    (http_label.clone(), CircuitData { opcode: 1 }),
  ]);

  // TODO (tracy): Need to form the real ciphertext, for now just accept a hash.
  let ciphertext = vec![];
  let padded_ciphertext = ByteOrPad::from_bytes_with_padding(
    &ciphertext,
    max_ciphertext - ciphertext.len(), // TODO: support different sizes.
  );
  use client_side_prover::traits::Engine;
  // let initial_nivc_input = vec![data_hasher(&padded_ciphertext)];
  let initial_nivc_input =
    vec![<E1 as Engine>::Scalar::from_bytes(&payload.ciphertext_hash.try_into().unwrap()).unwrap()];

  // TODO (tracy): We are re-initializing this everytime we verify a proof, which slows down this
  // API. We did it this way due to initial_nivc_input being static on the object. Add
  // getter/setter.
  let rom = vec![decryption_label, http_label];
  let local_params = ProgramData::<Offline, NotExpanded> {
    public_params: state.verifier_param_bytes.clone(),
    vk_digest_primary: F::<G1>::from(0), // TODO: This is gross.
    vk_digest_secondary: F::<G2>::from(0),
    setup_data: setup_data_large,
    rom,
    rom_data,
    initial_nivc_input,
    inputs: (vec![HashMap::new()], HashMap::new()),
    witnesses: vec![],
  }
  .into_online()
  .unwrap();

  let (_pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&local_params.public_params).unwrap();
  debug!(
    "initialized vk_primary.digest={:?}, vk_secondary.digest={:?}, ck_s={:?}",
    vk.vk_primary.digest, vk.vk_secondary.digest, vk.vk_secondary.vk_ee.ck_s
  );
  let (z0_primary, _) = local_params.extend_public_inputs().unwrap();
  let z0_secondary = vec![F::<G2>::from(0)];

  let valid = match proof.0.verify(&local_params.public_params, &vk, &z0_primary, &z0_secondary) {
    Ok(_) => true,
    Err(e) => {
      info!("Error verifying proof: {:?}", e);
      false
    },
  };

  let response = VerifyReply { valid };

  Ok(Json(response))
}

pub async fn websocket_notarize(
  socket: WebSocket,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to websocket connection");
  let stream = WsStream::new(socket.into_inner()).compat();
  match proxy_service(stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using websocket!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using websocket: {err}");
    },
  }
}

pub async fn tcp_notarize(
  stream: TokioIo<Upgraded>,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to tcp connection");
  match proxy_service(stream, &session_id, &target_host, target_port, state).await {
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
          buffer.push(Message{
            direction: Direction::Sent,
            payload: buf[..n].to_vec()
          })
        },
        Err(e) => return Err(e),
      }
    }
    tcp_write.shutdown().await.unwrap();
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
          buffer.push(Message{
            direction: Direction::Received,
            payload: buf[..n].to_vec()
          })
        },
        Err(e) => return Err(e),
      }
    }
    socket_write.shutdown().await.unwrap();
    Ok(())
  };

  use futures::{future::select, pin_mut};
  pin_mut!(client_to_server, server_to_client);
  let _ = select(client_to_server, server_to_client).await.factor_first().0;

  state.origo_sessions.lock().unwrap().insert(session_id.to_string(), OrigoSession {
    messages:    messages.lock().unwrap().to_vec(),
    _timestamp: SystemTime::now(),
  });

  Ok(())
}
