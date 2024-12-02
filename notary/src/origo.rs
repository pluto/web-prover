use std::{
  io::Cursor,
  sync::{Arc, Mutex},
  time::SystemTime,
};

use alloy_primitives::utils::keccak256;
use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use hex;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use nom::{bytes::streaming::take, IResult};
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use tls_client2::{
  hash_hs::HandshakeHashBuffer,
  internal::msgs::hsjoiner::HandshakeJoiner,
  tls_core::{
    msgs::{
      base::Payload,
      codec::{self, Codec, Reader},
      enums::Compression,
      handshake::{
        ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random,
        ServerExtension, ServerHelloPayload, SessionID,
      },
      message::{Message, MessagePayload, OpaqueMessage},
    },
    verify::{construct_tls13_server_verify_message, verify_tls13},
  },
  Certificate, CipherSuite, CipherSuiteKey,
};
use tls_parser::{
  parse_tls_message_handshake, ClientHello, TlsClientHelloContents, TlsMessage,
  TlsMessageHandshake, TlsServerHelloContents,
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
  errors::{NotaryServerError, ProxyError},
  tlsn::ProtocolUpgrade,
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
  signature_v: u8,
  signer:      String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignBody {
  handshake_server_aes_iv:  String,
  handshake_server_aes_key: String,
}

pub async fn sign(
  query: Query<SignQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<SignBody>,
) -> Result<Json<SignReply>, ProxyError> {
  let session = state.origo_sessions.lock().unwrap().get(&query.session_id).unwrap().clone();
  let messages = extract_tls_handshake(&session.request, payload)?;
  let handshake_hash_buffer = HandshakeHashBuffer::new();
  // TODO: get hash algorithm from cipher suite in a better way
  let mut transcript =
    handshake_hash_buffer.start_hash(&tls_client2::tls_core::suites::HashAlgorithm::SHA256);
  let mut server_certificate: Certificate = Certificate(vec![]);

  for msg in messages {
    match msg.payload {
      MessagePayload::Handshake(ref handshake) => match handshake.payload {
        HandshakePayload::ClientHello(_) => {
          debug!("ClientHello");
          transcript.add_message(&msg);
        },
        HandshakePayload::ServerHello(_) => {
          debug!("ServerHello");
          transcript.add_message(&msg);
        },
        HandshakePayload::Certificate(_) => {
          // TODO for some reason this is not hit, but CertificateTLS13 is hit
          debug!("Certificate");
        },
        HandshakePayload::CertificateTLS13(ref certificate_payload) => {
          debug!("CertificateTLS13: {}", certificate_payload.entries.len());
          transcript.add_message(&msg);
          server_certificate = certificate_payload.entries[0].cert.clone();
        },
        HandshakePayload::CertificateVerify(ref digitally_signed_struct) => {
          debug!("CertificateVerify");

          // send error back to client if signature verification fails
          match verify_tls13(
            &construct_tls13_server_verify_message(&transcript.get_current_hash()),
            &server_certificate,
            &digitally_signed_struct,
          ) {
            Ok(_) => (),
            Err(e) => return Err(ProxyError::Sign(Box::new(e))),
          };
        },
        HandshakePayload::EncryptedExtensions(_) => {
          debug!("EncryptedExtensions");
          transcript.add_message(&msg);
        },
        HandshakePayload::Finished(_) => {
          debug!("Payload");

          // Note from Tracy:
          // I believe this is verification data from either the server or client that it has
          // finished the handshake Essentially it’s a hash of the data up to that point
          // hmac signed by the derived handshake AES key
          // https://github.com/rustls/rustls/blob/8c04dba680d19d203a7eda1951ad596f5fc2ae59/rustls/src/client/tls13.rs#L1234
        },

        // TODO: some of these (CertificateRequest, HelloRetryRequest) are not considered in happy
        // path, handle later
        // HandshakePayload::KeyUpdate(_) => todo!(),
        // HandshakePayload::ServerHelloDone => todo!(),
        // HandshakePayload::EndOfEarlyData => todo!(),
        // HandshakePayload::ClientKeyExchange(_) => todo!(),
        // HandshakePayload::NewSessionTicket(_) => todo!(),
        // HandshakePayload::NewSessionTicketTLS13(_) => todo!(),
        // HandshakePayload::ServerKeyExchange(_) => todo!(),
        // HandshakePayload::CertificateRequest(_) => todo!(),
        // HandshakePayload::CertificateRequestTLS13(_) => todo!(),
        // HandshakePayload::HelloRequest => todo!(),
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

/// Due to a bug in the tls_parser, we must override.
/// See: https://github.com/rusticata/tls-parser/issues/72
fn local_parse_record(i: &[u8]) -> IResult<&[u8], tls_parser::TlsRawRecord> {
  let (i, hdr) = tls_parser::parse_tls_record_header(i)?;
  if hdr.len > (1 << 14) + 256 {
    panic!("oversized payload");
  }

  let (i, data) = take(hdr.len as usize)(i)?;
  Ok((i, tls_parser::TlsRawRecord { hdr, data }))
}

/// Extracts and processes TLS handshake messages from raw bytes
///
/// # Arguments
/// * `bytes` - Raw TLS message bytes to parse
/// * `payload` - Contains encryption keys and IVs for decrypting TLS1.3 messages
///
/// # Returns
/// * `Result<Vec<Message>, ProxyError>` - Vector of parsed TLS messages or error
fn extract_tls_handshake(bytes: &[u8], payload: SignBody) -> Result<Vec<Message>, ProxyError> {
  let server_hs_key = hex::decode(payload.handshake_server_key).unwrap();
  let server_hs_iv = hex::decode(payload.handshake_server_iv).unwrap();
  info!("key_as_string: {:?}, length: {}", server_hs_key, server_hs_key.len());
  info!("iv_as_string: {:?}, length: {}", server_hs_iv, server_hs_iv.len());

  let mut cursor = Cursor::new(bytes);
  let mut messages: Vec<Message> = vec![];
  let mut seq = 0u64;

  while cursor.position() < bytes.len() as u64 {
    let current_bytes = &cursor.get_ref()[cursor.position() as usize..];
    match local_parse_record(current_bytes) {
      Ok((_, record)) => {
        info!("TLS record type: {}", record.hdr.record_type);

        // NOTE:
        // The first 3 messages are typically: handshake, handshake, changecipherspec
        //
        // These are plaintext. The first encrypted message is an extension from the server
        // which is labeled application data, like all subsequent encrypted messages in TLS1.3
        let mut cipher_suite_key: Option<CipherSuiteKey> = None;
        if record.hdr.record_type == tls_parser::TlsRecordType::Handshake {
          let rec = parse_tls_message_handshake(record.data);
          match rec {
            Ok((_data, parse_tls_message)) => match parse_tls_message {
              TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                debug!("parsing ClientHello");
                handle_client_hello(ch, &mut messages)?;
              },
              TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                debug!("parsing ServerHello");
                handle_server_hello(sh.clone(), &mut messages)?;
                cipher_suite_key =
                  Some(set_key(server_hs_key.clone(), CipherSuite::from(sh.cipher.0))?);
              },
              _ => {
                info!("{:?}", parse_tls_message);
              },
            },
            Err(err) => {
              error!("can't parse tls raw record: {}", err);
            },
          }
        }
        // this is encrypted handshake data.
        if record.hdr.record_type == tls_parser::TlsRecordType::ApplicationData {
          handle_application_data(
            record.data.to_vec(),
            &mut messages,
            server_hs_iv.clone(),
            cipher_suite_key.clone(),
            seq,
          )?;
          seq += 1;
        }

        // 5 is the record header length
        cursor.set_position(cursor.position() + 5 + record.hdr.len as u64);
      },
      Err(e) => {
        let remaining = &cursor.get_ref().len() - (cursor.position() as usize);
        return Err(ProxyError::TlsParser {
          position: cursor.position(),
          remaining,
          e: e.to_string(),
        });
      },
    }
  }

  if messages.len() > 0 {
    Ok(messages)
  } else {
    Err(ProxyError::TlsHandshakeExtract(String::from("empty handshake messages")))
  }
}

/// Handles encrypted TLS 1.3 application data by decrypting it and processing any contained
/// handshake messages.
///
/// This function takes encrypted TLS 1.3 application data and attempts to decrypt it using the
/// provided cipher suite key and initialization vector. After decryption, any handshake messages
/// found in the plaintext are added to the messages vector.
///
/// # Arguments
///
/// * `record` - The encrypted application data as a vector of bytes
/// * `messages` - A mutable reference to a vector where decrypted handshake messages will be stored
/// * `server_hs_iv` - The server handshake initialization vector
/// * `cipher_suite_key` - The optional cipher suite key used for decryption
/// * `seq` - The sequence number for the TLS record
///
/// # Returns
///
/// * `Ok(())` - If the application data was successfully decrypted and processed or if key was not
///   set
///
/// # Supported Cipher Suites
///
/// * `TLS13_AES_128_GCM_SHA256` - Uses AES-128-GCM decryption
/// * `TLS13_CHACHA20_POLY1305_SHA256` - Uses ChaCha20-Poly1305 decryption
fn handle_application_data(
  record: Vec<u8>,
  messages: &mut Vec<Message>,
  server_hs_iv: Vec<u8>,
  cipher_suite_key: Option<CipherSuiteKey>,
  seq: u64,
) -> Result<(), ProxyError> {
  let msg = OpaqueMessage {
    typ:     tls_client2::tls_core::msgs::enums::ContentType::ApplicationData,
    version: tls_client2::ProtocolVersion::TLSv1_3,
    payload: Payload(record),
  };

  match cipher_suite_key {
    Some(key) => {
      match key {
        CipherSuiteKey::AES128GCM(key) => {
          let d = tls_client2::Decrypter::new(
            CipherSuiteKey::AES128GCM(key),
            server_hs_iv[..12].try_into().unwrap(),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
          );

          match d.decrypt_tls13_aes(&msg, seq) {
            Ok((plain_message, _meta)) => {
              let mut handshake_joiner = HandshakeJoiner::new();
              handshake_joiner.take_message(plain_message);
              while let Some(msg) = handshake_joiner.frames.pop_front() {
                messages.push(msg);
              }
            },
            Err(_) => {
              trace!("Unable to decrypt record. Skipping.");
            },
          };
        },
        CipherSuiteKey::CHACHA20POLY1305(key) => {
          let d = tls_client2::Decrypter::new(
            CipherSuiteKey::CHACHA20POLY1305(key),
            server_hs_iv[..12].try_into().unwrap(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
          );

          match d.decrypt_tls13_chacha20(&msg, seq) {
            Ok((plain_message, _meta)) => {
              let mut handshake_joiner = HandshakeJoiner::new();
              handshake_joiner.take_message(plain_message);
              while let Some(msg) = handshake_joiner.frames.pop_front() {
                messages.push(msg);
              }
            },
            Err(_) => {
              // This occurs once we pass the handshake records, we will no longer
              // have the correct keys to decrypt. We want to continue logging the
              // ciphertext.
              trace!("Unable to decrypt record. Skipping.");
            },
          };
        },
      }
    },
    None => {
      trace!("No cipher suite key set. Skipping record.");
      return Ok(());
    },
  };
  Ok(())
}

/// Processes a TLS ClientHello message and converts it into the internal message format.
///
/// Takes a ClientHello message contents and constructs a properly formatted internal Message
/// structure that includes all the TLS handshake components. The processed message is then
/// added to the provided messages vector.
///
/// # Arguments
///
/// * `client_hello` - The TLS ClientHello message contents to process
/// * `messages` - A mutable reference to a vector where the processed message will be pushed
///
/// # Returns
///
/// * `Ok(())` - If the ClientHello message was successfully processed and added
/// * `Err(ProxyError)` - If any processing step fails (missing extension, invalid format, etc.)
///
/// # Processing Steps
///
/// 1. Processes random bytes and session ID
/// 2. Converts cipher suites to internal format
/// 3. Converts compression methods
/// 4. Processes TLS extensions:
///    - Extracts extension bytes
///    - Prepends 2-byte length
///    - Decodes into ClientExtension types
/// 5. Constructs final Message with ClientHello payload
fn handle_client_hello(
  client_hello: TlsClientHelloContents,
  messages: &mut Vec<Message>,
) -> Result<(), ProxyError> {
  let ch_random = process_random_bytes(&client_hello.random)?;
  let session_id = process_session_id(client_hello.session_id)?;

  let cipher_suites: Vec<CipherSuite> =
    client_hello.ciphers().iter().map(|suite| CipherSuite::from(suite.0)).collect();

  let compressions_methods: Vec<Compression> =
    client_hello.comp().iter().map(|method| Compression::from(method.0)).collect();

  let extension_byte: &[u8] =
    client_hello.ext().ok_or(ProxyError::TlsHandshakeExtract("Missing extension".to_string()))?;
  let mut extension_byte = extension_byte.to_vec();
  let ch_extension_len: [u8; 2] = (extension_byte.len() as u16).to_be_bytes();
  extension_byte.splice(0..0, ch_extension_len);

  // create the reader which can decode extensions byte
  let mut r = Reader::init(&extension_byte);
  let extensions = codec::read_vec_u16::<ClientExtension>(&mut r)
    .ok_or(ProxyError::TlsHandshakeExtract("Failed to read server extension".to_string()))?;

  let client_hello_message = Message {
    version: tls_client2::ProtocolVersion::from(client_hello.version.0),
    payload: MessagePayload::Handshake(HandshakeMessagePayload {
      typ:     tls_client2::tls_core::msgs::enums::HandshakeType::ClientHello,
      payload: HandshakePayload::ClientHello(ClientHelloPayload {
        client_version: tls_client2::ProtocolVersion::from(client_hello.version.0),
        random: ch_random,
        session_id,
        cipher_suites,
        compression_methods: compressions_methods,
        extensions,
      }),
    }),
  };
  messages.push(client_hello_message);
  Ok(())
}

/// Handles the TLS ServerHello message by processing its contents and adding it to the message
/// queue.
///
/// This function processes a TLS ServerHello message, extracts its components, and constructs a
/// properly formatted Message structure that is then added to the messages vector.
///
/// # Arguments
///
/// * `server_hello` - The contents of the TLS ServerHello message to process
/// * `messages` - A mutable reference to a vector where the processed message will be pushed
///
/// # Returns
///
/// * `Ok(())` - If the ServerHello message was successfully processed and added
/// * `Err(ProxyError)` - If any processing step fails (missing extension, invalid format, etc.)
///
/// # Processing Steps
///
/// 1. Processes random bytes and session ID
/// 2. Extracts and formats extension bytes
/// 3. Reads server extensions
/// 4. Constructs a new Message with all components
fn handle_server_hello(
  server_hello: TlsServerHelloContents,
  messages: &mut Vec<Message>,
) -> Result<(), ProxyError> {
  let sh_random = process_random_bytes(&server_hello.random)?;
  let session_id = process_session_id(server_hello.session_id)?;

  let extension_byte: &[u8] =
    server_hello.ext.ok_or(ProxyError::TlsHandshakeExtract("Missing extension".to_string()))?;
  let mut extension_byte = extension_byte.to_vec();
  let sh_extension_len: [u8; 2] = (extension_byte.len() as u16).to_be_bytes();
  extension_byte.splice(0..0, sh_extension_len);

  let mut r = Reader::init(&extension_byte);
  let extensions = codec::read_vec_u16::<ServerExtension>(&mut r)
    .ok_or(ProxyError::TlsHandshakeExtract("Failed to read server extension".to_string()))?;
  debug!("cipher: {:?}", server_hello.cipher.0);

  let server_hello_message = Message {
    version: tls_client2::ProtocolVersion::from(server_hello.version.0),
    payload: MessagePayload::Handshake(HandshakeMessagePayload {
      typ:     tls_client2::tls_core::msgs::enums::HandshakeType::ServerHello,
      payload: HandshakePayload::ServerHello(ServerHelloPayload {
        legacy_version: tls_client2::ProtocolVersion::from(server_hello.version.0),
        random: sh_random,
        session_id,
        cipher_suite: CipherSuite::from(server_hello.cipher.0),
        compression_method: Compression::from(server_hello.compression.0),
        extensions,
      }),
    }),
  };
  messages.push(server_hello_message);
  Ok(())
}

/// Shared helper functions for TLS message processing
fn process_random_bytes(bytes: &[u8]) -> Result<Random, ProxyError> {
  let random_bytes: [u8; 32] = bytes.try_into()?;
  Ok(Random(random_bytes))
}

fn process_session_id(session_id: Option<&[u8]>) -> Result<SessionID, ProxyError> {
  let sh_session_id =
    session_id.ok_or_else(|| ProxyError::InvalidSessionId("Missing session ID".into()))?;
  let mut sh_session_id = sh_session_id.to_vec();
  sh_session_id.insert(0, sh_session_id.len() as u8);
  Ok(
    SessionID::read_bytes(&sh_session_id)
      .ok_or_else(|| ProxyError::InvalidSessionId("Failed to read session ID bytes".into()))?,
  )
}

/// Converts a raw key vector into a cipher suite-specific key format.
///
/// Takes a vector of bytes representing the raw key material and a cipher suite specification,
/// and returns a properly formatted key for the specified cipher suite.
///
/// # Arguments
///
/// * `key` - A vector of bytes containing the raw key material
/// * `cipher_suite` - The TLS 1.3 cipher suite for which to format the key
///
/// # Returns
///
/// * `Ok(CipherSuiteKey)` - A properly formatted key for the specified cipher suite
/// * `Err(ProxyError)` - If the key is too short or the cipher suite is unsupported
///
/// # Supported Cipher Suites
///
/// * `TLS13_AES_128_GCM_SHA256` - Requires at least 16 bytes of key material
/// * `TLS13_CHACHA20_POLY1305_SHA256` - Requires at least 32 bytes of key material
fn set_key(key: Vec<u8>, cipher_suite: CipherSuite) -> Result<CipherSuiteKey, ProxyError> {
  match cipher_suite {
    CipherSuite::TLS13_AES_128_GCM_SHA256 => {
      if key.len() < 16 {
        return Err(ProxyError::TlsHandshakeExtract("Key too short for AES-128-GCM".to_string()));
      }
      let mut key_array = [0u8; 16];
      key_array.copy_from_slice(&key[..16]);
      Ok(CipherSuiteKey::AES128GCM(key_array))
    },
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
      if key.len() < 32 {
        return Err(ProxyError::TlsHandshakeExtract(
          "Key too short for CHACHA20-POLY1305".to_string(),
        ));
      }
      let mut key_array = [0u8; 32];
      key_array.copy_from_slice(&key[..32]);
      Ok(CipherSuiteKey::CHACHA20POLY1305(key_array))
    },
    _ => {
      debug!("Unsupported cipher suite: {:?}", cipher_suite);
      Err(ProxyError::TlsHandshakeExtract(format!("Unsupported cipher suite: {:?}", cipher_suite)))
    },
  }
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
          debug!("sending to server len={:?}, data={:?}", n, hex::encode(&buf[..n]));
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
          debug!("sending to client len={:?}, data={:?}", n, hex::encode(&buf[..n]));
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
    request:    request_buf.lock().unwrap().to_vec(),
    _timestamp: SystemTime::now(),
  });

  Ok(())
}
