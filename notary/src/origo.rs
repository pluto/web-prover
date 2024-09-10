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
use base64::{prelude::BASE64_STANDARD, Engine};
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
  Certificate, CipherSuite,
};
use tls_parser::{parse_tls_message_handshake, ClientHello, TlsMessage, TlsMessageHandshake};
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
  server_aes_iv:  String,
  server_aes_key: String,
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
          // TODO what's the payload?
          // println!("Finished Payload:\n{}", String::from_utf8_lossy(&finished_payload.0))

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

fn extract_tls_handshake(bytes: &[u8], payload: SignBody) -> Result<Vec<Message>, ProxyError> {
  let server_aes_key = BASE64_STANDARD.decode(payload.server_aes_key)?;
  let server_aes_iv = BASE64_STANDARD.decode(payload.server_aes_iv)?;

  let mut cursor = Cursor::new(bytes);
  let mut messages: Vec<Message> = vec![];

  let mut seq = 0;
  while cursor.position() < bytes.len() as u64 {
    match local_parse_record(&cursor.get_ref()[cursor.position() as usize..]) {
      Ok((_, record)) => {
        info!("TLS record type: {}", record.hdr.record_type);

        // NOTE:
        // The first 3 messages are typically: handshake, handshake, changecipherspec
        //
        // These are plaintext. The first encrypted message is an extension from the server
        // which is labeled application data, like all subsequent encrypted messages in TLS1.3
        if record.hdr.record_type == tls_parser::TlsRecordType::Handshake {
          let rec = parse_tls_message_handshake(record.data);
          match rec {
            Ok((_data, parse_tls_message)) => {
              match parse_tls_message {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                  // parses `TlsParser::TlsClientHelloContents` to `Message`
                  debug!("parsing ClientHello");

                  // TODO: write this better
                  let ch_random_bytes: [u8; 32] =
                    ch.random().try_into().expect("ch random bytes not of correct size");
                  let ch_random = Random(ch_random_bytes);

                  // parse session id by adding byte length to TlsParser output
                  let ch_session_id = ch.session_id().expect("incorrect session_id");
                  let mut ch_session_id = ch_session_id.to_vec();
                  ch_session_id.insert(0, ch_session_id.len() as u8);
                  let session_id = SessionID::read_bytes(&ch_session_id)
                    .expect("can't read session id from bytes");

                  let cipher_suites: Vec<CipherSuite> =
                    ch.ciphers().iter().map(|suite| CipherSuite::from(suite.0)).collect();

                  let compressions_methods: Vec<Compression> =
                    ch.comp().iter().map(|method| Compression::from(method.0)).collect();

                  // Read ClientHelloPayload extensions from TlsParser by preprending byte length
                  // for TLS codec
                  let extension_byte: &[u8] =
                    ch.ext().expect("invalid client hello extension payload");
                  let mut extension_byte = extension_byte.to_vec();
                  let ch_extension_len: [u8; 2] = (extension_byte.len() as u16).to_be_bytes();
                  extension_byte.splice(0..0, ch_extension_len);

                  // create the reader which can decode extensions byte
                  let mut r = Reader::init(&extension_byte);
                  let extensions = codec::read_vec_u16::<ClientExtension>(&mut r)
                    .expect("unable to read client extension payload");

                  let client_hello_message = Message {
                    version: tls_client2::ProtocolVersion::from(ch.version.0),
                    payload: MessagePayload::Handshake(HandshakeMessagePayload {
                      typ:     tls_client2::tls_core::msgs::enums::HandshakeType::ClientHello,
                      payload: HandshakePayload::ClientHello(ClientHelloPayload {
                        client_version: tls_client2::ProtocolVersion::from(ch.version.0),
                        random: ch_random,
                        session_id,
                        cipher_suites,
                        compression_methods: compressions_methods,
                        extensions,
                      }),
                    }),
                  };

                  messages.push(client_hello_message);
                },
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                  // parses `TlsParser::TlsServerHelloContents` to `Message`
                  debug!("parsing ServerHello");

                  let sh_random_bytes: [u8; 32] =
                    sh.random.try_into().expect("ch random bytes not of correct size");
                  let sh_random = Random(sh_random_bytes);

                  let sh_session_id = sh.session_id.expect("incorrect session_id");
                  let mut sh_session_id = sh_session_id.to_vec();
                  sh_session_id.insert(0, sh_session_id.len() as u8);
                  let session_id = SessionID::read_bytes(&sh_session_id)
                    .expect("can't read session id from bytes");

                  let extension_byte: &[u8] =
                    sh.ext.expect("invalid server hello extension payload");
                  let mut extension_byte = extension_byte.to_vec();
                  let sh_extension_len: [u8; 2] = (extension_byte.len() as u16).to_be_bytes();
                  extension_byte.splice(0..0, sh_extension_len);

                  let mut r = Reader::init(&extension_byte);
                  let extensions = codec::read_vec_u16::<ServerExtension>(&mut r)
                    .expect("unable to read server extension payload");

                  let server_hello_message = Message {
                    version: tls_client2::ProtocolVersion::from(sh.version.0),
                    payload: MessagePayload::Handshake(HandshakeMessagePayload {
                      typ:     tls_client2::tls_core::msgs::enums::HandshakeType::ServerHello,
                      payload: HandshakePayload::ServerHello(ServerHelloPayload {
                        legacy_version: tls_client2::ProtocolVersion::from(sh.version.0),
                        random: sh_random,
                        session_id,
                        cipher_suite: CipherSuite::from(sh.cipher.0),
                        compression_method: Compression::from(sh.compression.0),
                        extensions,
                      }),
                    }),
                  };

                  messages.push(server_hello_message);
                },
                _ => {
                  println!("{:?}", parse_tls_message);
                },
              }
            },
            Err(err) => {
              error!("can't parse tls raw record: {}", err);
            },
          }
        }
        if record.hdr.record_type == tls_parser::TlsRecordType::ApplicationData {
          let d = tls_client2::Decrypter2::new(
            server_aes_key[..16].try_into().unwrap(),
            server_aes_iv[..12].try_into().unwrap(),
            tls_client2::CipherSuite::TLS13_AES_128_CCM_SHA256,
          );

          let msg = OpaqueMessage {
            typ:     tls_client2::tls_core::msgs::enums::ContentType::ApplicationData,
            version: tls_client2::ProtocolVersion::TLSv1_3,
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
