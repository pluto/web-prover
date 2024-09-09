use std::{
  io::Cursor,
  sync::{Arc, Mutex},
  time::SystemTime,
};

use alloy_primitives::{utils::keccak256, Keccak256};
use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use hex;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use p256::ecdsa::{signature::SignerMut, Signature};
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use tls_client2::{
  internal::msgs::hsjoiner::HandshakeJoiner,
  tls_core::msgs::{
    base::Payload,
    handshake::HandshakePayload,
    message::{Message, MessagePayload, OpaqueMessage},
  },
};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info, trace};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  tlsn::{NotaryServerError, ProtocolUpgrade},
  OrigoSession, SharedState,
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
  signature_v: String,
  signer:      String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignBody {
  server_aes_iv:  String,
  server_aes_key: String,
}

pub async fn sign(
  query: Query<SignQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<SignBody>,
) -> Json<SignReply> {
  let session = state.origo_sessions.lock().unwrap().get(&query.session_id).unwrap().clone();
  let messages = extract_tls_handshake(&session.request, payload);
  for msg in messages {
    match msg.payload {
      MessagePayload::Handshake(handshake) => match handshake.payload {
        HandshakePayload::Certificate(certificate_payload) => {
          // TODO vector of certificates (cert chain)
          // TODO for some reason this is not hit, but CertificateTLS13 is hit
          println!("Certificate");
        },
        HandshakePayload::CertificateTLS13(certificate_payload) => {
          // TODO vector of certificates (cert chain)
          println!("CertificateTLS13");
        },
        HandshakePayload::CertificateVerify(digitally_signed_struct) => {
          // TODO signed certificate chain, verify signature
          println!("CertificateVerify");
        },
        HandshakePayload::EncryptedExtensions(encrypted_extensions) => {
          // TODO can probably ignore
          println!("EncryptedExtensions");
        },
        // HandshakePayload::KeyUpdate(_) => todo!(),
        HandshakePayload::Finished(finished_payload) => {
          println!("Payload");
          // TODO what's the payload?
          // println!("Finished Payload:\n{}", String::from_utf8_lossy(&finished_payload.0))

          // Note from Tracy:
          // I believe this is verification data from either the server or client that it has
          // finished the handshake Essentially it’s a hash of the data up to that point
          // hmac signed by the derived handshake AES key
          // https://github.com/rustls/rustls/blob/8c04dba680d19d203a7eda1951ad596f5fc2ae59/rustls/src/client/tls13.rs#L1234
        },

        // TODO auto completed branch arms, delete if not needed
        // HandshakePayload::ServerHelloDone => todo!(),
        // HandshakePayload::EndOfEarlyData => todo!(),
        // HandshakePayload::ClientKeyExchange(_) => todo!(),
        // HandshakePayload::NewSessionTicket(_) => todo!(),
        // HandshakePayload::NewSessionTicketTLS13(_) => todo!(),
        // HandshakePayload::ServerKeyExchange(_) => todo!(),
        // HandshakePayload::CertificateRequest(_) => todo!(),
        // HandshakePayload::CertificateRequestTLS13(_) => todo!(),
        // HandshakePayload::HelloRequest => todo!(),
        // HandshakePayload::ClientHello(_) => todo!(),
        // HandshakePayload::ServerHello(_) => todo!(),
        // HandshakePayload::HelloRetryRequest(_) => todo!(),
        // HandshakePayload::CertificateStatus(_) => todo!(),
        // HandshakePayload::MessageHash(_) => todo!(),
        // HandshakePayload::Unknown(_) => todo!(),
        _ => {
          println!("unhandled {:?}", handshake.typ); // TODO probably just ignore
        },
      },
      _ => {
        // TODO just ignore? should be handshakes only
      },
    }
  }

  // TODO verify signature for handshake, don't return if verification fails
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

  // create signer address from verifying key
  let pubkey = k256::ecdsa::VerifyingKey::from(&state.origo_signing_key.clone());
  let point = pubkey.to_encoded_point(false);
  let pubkey_bytes = point.as_bytes();
  let pubkey_hash = keccak256(&pubkey_bytes[1..]); // skip the first byte (0x04 for uncompressed)
  let signer_address = &pubkey_hash[12..]; // last 20 bytes of the 32-byte Keccak256 hash

  let response = SignReply {
    merkle_root: hex::encode(merkle_root),
    leaves,
    signature: hex::encode(signature.to_der().as_bytes()),
    signature_r: hex::encode(signature.r().to_bytes()),
    signature_s: hex::encode(signature.s().to_bytes()),
    signature_v: hex::encode([recover_id.to_byte()]),
    signer: hex::encode(signer_address),
  };

  Json(response)
}

#[derive(Clone)]
struct KeccakHasher;

impl Hasher for KeccakHasher {
  type Hash = [u8; 32];

  fn hash(data: &[u8]) -> Self::Hash { keccak256(data).into() }
}

use nom::{bytes::streaming::take, Err, IResult};

/// Due to a bug in the tls_parser, we must override.
/// See: https://github.com/rusticata/tls-parser/issues/72
fn local_parse_record(i: &[u8]) -> IResult<&[u8], tls_parser::TlsRawRecord> {
  let (i, hdr) = tls_parser::parse_tls_record_header(i).unwrap();
  if hdr.len > (1 << 14) + 256 {
    panic!("oversized payload");
  }

  let (i, data) = take(hdr.len as usize)(i)?;
  Ok((i, tls_parser::TlsRawRecord { hdr, data }))
}

fn extract_tls_handshake(bytes: &[u8], payload: SignBody) -> Vec<Message> {
  let server_aes_key = BASE64_STANDARD.decode(payload.server_aes_key).unwrap();
  let server_aes_iv = BASE64_STANDARD.decode(payload.server_aes_iv).unwrap();

  let mut cursor = Cursor::new(bytes);
  let mut messages: Vec<Message> = vec![];

  let mut seq = 0;
  while cursor.position() < bytes.len() as u64 {
    match local_parse_record(&cursor.get_ref()[cursor.position() as usize..]) {
      Ok((_, record)) => {
        trace!("TLS record type: {}", record.hdr.record_type);

        // NOTE:
        // The first 3 messages are typically: handshake, handshake, changecipherspec
        //
        // These are plaintext. The first encrypted message is an extension from the server
        // which is labeled application data, like all subsequent encrypted messages in TLS1.3

        if record.hdr.record_type == tls_parser::TlsRecordType::ApplicationData {
          let d = tls_client2::Decrypter2::new(
            server_aes_key[..16].try_into().unwrap(),
            server_aes_iv[..12].try_into().unwrap(),
            tls_client2::CipherSuite::TLS13_AES_128_CCM_SHA256,
          );

          let msg = OpaqueMessage {
            typ:     tls_client2::tls_core::msgs::enums::ContentType::ApplicationData,
            version: tls_client2::ProtocolVersion::TLSv1_2,
            payload: Payload(record.data.to_vec()),
          };

          match d.decrypt_tls13_aes(&msg, seq) {
            Ok((plain_message, _meta)) => {
              let mut handshake_joiner = HandshakeJoiner::new();
              handshake_joiner.take_message(plain_message);
              while let Some(msg) = handshake_joiner.frames.pop_front() {
                messages.push(msg);
              }
            },
            Err(_) => {
              // This occurs once we pass the handshake records, we will no longer
              // have the correct keys to decrypt. We want to continue logging the ciphertext.
              trace!("Unable to decrypt record. Skipping.");
            },
          }

          seq += 1;
        }

        // 5 is the record header length
        cursor.set_position(cursor.position() + 5 + record.hdr.len as u64);
      },
      Err(e) => {
        let remaining = &cursor.get_ref().len() - (cursor.position() as usize);
        panic!(
          "Unable to parse record! position={}, remaining={}, e={}, ",
          cursor.position(),
          remaining,
          e
        );
      },
    }
  }

  assert!(messages.len() > 0); // TODO return an actual error
  messages
}

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id:  String,
  target_host: String,
  target_port: u16,
}

pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

  info!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(
        socket,
        session_id,
        query.target_host.clone(),
        query.target_port.clone(),
        state,
      )
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, session_id, query.target_host.clone(), query.target_port.clone(), state)
    }),
  }
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

  let request_buf = Arc::new(Mutex::new(vec![0u8; 0]));

  let client_to_server = async {
    let mut buf = [0u8; 8192];
    loop {
      match socket_read.read(&mut buf).await {
        Ok(0) => break,
        Ok(n) => {
          tcp_write.write_all(&buf[..n]).await?;
          let mut buffer = request_buf.lock().unwrap();
          buffer.extend_from_slice(&buf[..n]);
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
          socket_write.write_all(&buf[..n]).await?;
          let mut buffer = request_buf.lock().unwrap();
          buffer.extend_from_slice(&buf[..n]);
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
    // TODO currently request is both, request and response. will this become a problem?
    request:   request_buf.lock().unwrap().to_vec(),
    timestamp: SystemTime::now(),
  });

  Ok(())
}
