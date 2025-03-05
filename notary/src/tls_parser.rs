use std::io::Cursor;

use nom::{bytes::streaming::take, IResult};
use tls_client2::{
  hash_hs::HandshakeHashBuffer,
  internal::msgs::hsjoiner::HandshakeJoiner,
  tls_core::{
    msgs::{
      codec::{self, Codec, Reader},
      enums::{Compression, ContentType},
      handshake::{
        ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random,
        ServerExtension, ServerHelloPayload, SessionID,
      },
      message::{Message, MessagePayload, OpaqueMessage, PlainMessage},
    },
    verify::{construct_tls13_server_verify_message, verify_tls13},
  },
  Certificate, CipherSuite, CipherSuiteKey,
};
use tls_parser::{
  parse_tls_message_handshake, ClientHello, TlsClientHelloContents, TlsMessage,
  TlsMessageHandshake, TlsServerHelloContents,
};
use tracing::{debug, error, info, trace};

use crate::errors::ProxyError;

const TRIMMED_BYTES: usize = 17;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Direction {
  Sent,
  Received,
}

impl std::fmt::Display for Direction {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Direction::Sent => write!(f, "Sent"),
      Direction::Received => write!(f, "Received"),
    }
  }
}

#[derive(Debug)]
pub enum WrappedPayload {
  Encrypted(OpaqueMessage),
  Decrypted(Message),
}

#[derive(Debug)]
pub struct ParsedMessage {
  pub direction: Direction,
  pub seq:       u64,
  pub payload:   WrappedPayload,
}

#[derive(Debug, Clone)]
pub struct UnparsedMessage {
  pub direction: Direction,
  pub payload:   Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PayloadHTTP {
  pub request:  Vec<u8>,
  pub response: Vec<u8>,
}

/// State transitions for Transcripts
///
/// 1. Raw: Raw network data, only structure is direction
/// 2. Flattened: Organize the network data into parseable objects.
/// 3. Parsed: TLS Parsed into structured decryptable-objects
pub trait TranscriptState {
  type MessageFormat;
}
#[derive(Debug, Clone)]
pub struct Raw;
impl TranscriptState for Raw {
  type MessageFormat = Vec<UnparsedMessage>;
}

#[derive(Debug, Clone)]
pub struct Flattened;
impl TranscriptState for Flattened {
  type MessageFormat = Vec<UnparsedMessage>;
}
#[derive(Debug, Clone)]
pub struct ParsedTLS;
impl TranscriptState for ParsedTLS {
  type MessageFormat = Vec<ParsedMessage>;
}
#[derive(Debug, Clone)]
pub struct ParsedHTTP;
impl TranscriptState for ParsedHTTP {
  type MessageFormat = PayloadHTTP;
}

#[derive(Debug, Clone)]
pub struct Transcript<T: TranscriptState> {
  pub payload: T::MessageFormat,
}

impl Transcript<Raw> {
  /// Flatten neighboring transcript messages in the same direction
  pub fn into_flattened(self) -> Result<Transcript<Flattened>, ProxyError> {
    let (mut processed, current) = self.payload.iter().fold(
      (Vec::new(), Vec::<UnparsedMessage>::new()),
      |(mut processed, mut current), msg| {
        if current.is_empty() || current[0].direction == msg.direction {
          current.push(msg.clone());
        } else if current[0].direction != msg.direction {
          processed.push(UnparsedMessage {
            payload:   current.iter().flat_map(|m| m.payload.clone()).collect(),
            direction: current[0].direction,
          });

          current.clear();
          current.push(msg.clone());
        }
        (processed, current)
      },
    );

    // Handle last group
    if !current.is_empty() {
      processed.push(UnparsedMessage {
        payload:   current.iter().flat_map(|m| m.payload.clone()).collect(),
        direction: current[0].direction,
      });
    }

    Ok(Transcript { payload: processed })
  }
}

impl Transcript<Flattened> {
  /// Transform raw data into more structured TLS data by
  /// processing with handhsake keys.
  ///
  /// # Arguments
  /// * `handshake_server_key` - Encryption key for decrypting TLS1.3 messages
  /// * `handshake_server_iv` -  Encryption IV for decrypting TLS1.3 messages
  ///
  /// # Returns
  /// * `Result<Transcript<Parsed>, ProxyError>` - Vector of parsed TLS messages or error
  pub fn into_parsed(
    self,
    handshake_server_key: &[u8],
    handshake_server_iv: &[u8],
    app_server_key: Option<Vec<u8>>,
    app_server_iv: Option<Vec<u8>>,
    app_client_key: Option<Vec<u8>>,
    app_client_iv: Option<Vec<u8>>,
  ) -> Result<Transcript<ParsedTLS>, ProxyError> {
    info!("key_as_string: {:?}, length: {}", handshake_server_key, handshake_server_key.len());
    info!("iv_as_string: {:?}, length: {}", handshake_server_iv, handshake_server_iv.len());

    let mut parsed_messages: Vec<ParsedMessage> = vec![];
    let mut seq = 0u64;
    let mut handshake_cipher_key: Option<CipherSuiteKey> = None;
    let mut app_server_cipher_key: Option<CipherSuiteKey> = None;
    let mut app_client_cipher_key: Option<CipherSuiteKey> = None;
    let mut decrypters: Vec<DecryptWrapper> = vec![];

    for m in &self.payload {
      let mut cursor = Cursor::new(m.payload.clone());
      while cursor.position() < m.payload.len() as u64 {
        let current_bytes = &cursor.get_ref()[cursor.position() as usize..];
        match local_parse_record(current_bytes) {
          Ok((_, record)) => {
            // 5 is the record header length
            let message_bytes = cursor.position() + 5 + record.hdr.len as u64;
            info!("TLS record: type={}, len={}", record.hdr.record_type, message_bytes);

            // The first 3 messages are typically: handshake, handshake, changecipherspec.
            // These are plaintext. The first encrypted message is an extension from the server
            // which is labeled application data, like all subsequent encrypted messages in TLS1.3
            if record.hdr.record_type == tls_parser::TlsRecordType::Handshake {
              let rec = parse_tls_message_handshake(record.data);
              match rec {
                Ok((_data, parse_tls_message)) => match parse_tls_message {
                  TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    debug!("parsing ClientHello");
                    parsed_messages.push(ParsedMessage {
                      seq,
                      direction: m.direction,
                      payload: WrappedPayload::Decrypted(handle_client_hello(ch)?),
                    });
                  },
                  TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    debug!("parsing ServerHello");
                    parsed_messages.push(ParsedMessage {
                      seq,
                      direction: m.direction,
                      payload: WrappedPayload::Decrypted(handle_server_hello(sh.clone())?),
                    });

                    handshake_cipher_key =
                      Some(set_key(handshake_server_key.to_vec(), CipherSuite::from(sh.cipher.0))?);
                    app_server_cipher_key = match app_server_key {
                      Some(ref k) => Some(set_key(k.clone(), CipherSuite::from(sh.cipher.0))?),
                      None => None,
                    };
                    app_client_cipher_key = match app_client_key {
                      Some(ref k) => Some(set_key(k.clone(), CipherSuite::from(sh.cipher.0))?),
                      None => None,
                    };

                    // TODO: Move decrypters initialized out of here into top of parse
                    // and cleanup sequence number handling.
                    decrypters = vec![
                      (handshake_cipher_key, Some(handshake_server_iv), seq),
                      (app_server_cipher_key, app_server_iv.as_deref(), 0),
                      (app_client_cipher_key, app_client_iv.as_deref(), 0),
                    ]
                    .into_iter()
                    .flat_map(|(key, iv, seq)| match iv {
                      Some(inner_iv) => match make_decrypter(key, inner_iv.to_vec()) {
                        Ok((dec, suite)) =>
                          Some(Ok(DecryptWrapper { inner: dec, seq, ciphersuite: suite })),
                        Err(e) => Some(Err(e)),
                      },
                      None => None,
                    })
                    .collect::<Result<Vec<DecryptWrapper>, ProxyError>>()?;
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

            // Encrypted handshake data immediately proceeds ServerHello, but
            // for backwards compatability with TLS 1.2 is labeled as AppData.
            if record.hdr.record_type == tls_parser::TlsRecordType::ApplicationData {
              let decrypted_messages =
                handle_application_data(record.data.to_vec(), &mut decrypters)?;

              parsed_messages.extend(decrypted_messages.into_iter().map(|decrypted_message| {
                ParsedMessage { seq, direction: m.direction, payload: decrypted_message }
              }));

              seq += 1;
            }

            cursor.set_position(message_bytes);
          },
          Err(e) => {
            let remaining = cursor.get_ref().len() - (cursor.position() as usize);
            return Err(ProxyError::TlsParser {
              position: cursor.position(),
              remaining,
              e: e.to_string(),
            });
          },
        }
      }
    }

    if parsed_messages.is_empty() {
      return Err(ProxyError::TlsHandshakeExtract(String::from("empty transcript messages")));
    }

    Ok(Transcript { payload: parsed_messages })
  }
}

impl Transcript<ParsedTLS> {
  /// Convert a ParsedTLS transcript into an HTTP request/response pair by
  /// joining all the AppData sent to the server or received by the client.
  pub fn into_http(self) -> Result<Transcript<ParsedHTTP>, ProxyError> {
    let mut request = Vec::new();
    let mut response = Vec::new();

    let match_app_data = |w: &WrappedPayload| match w {
      WrappedPayload::Encrypted(_) => Vec::new(),
      WrappedPayload::Decrypted(msg) => match &msg.payload {
        MessagePayload::ApplicationData(payload) => payload.0.clone(),
        _ => Vec::new(),
      },
    };

    for m in self.payload.iter() {
      if m.direction == Direction::Sent {
        request.extend(match_app_data(&m.payload))
      } else {
        response.extend(match_app_data(&m.payload));
      }
    }

    Ok(Transcript { payload: PayloadHTTP { request, response } })
  }

  pub fn verify_certificate_sig(&self) -> Result<(), ProxyError> {
    // TODO: get hash algorithm from cipher suite in a better way
    let handshake_hash_buffer = HandshakeHashBuffer::new();
    let mut transcript_digest =
      handshake_hash_buffer.start_hash(&tls_client2::tls_core::suites::HashAlgorithm::SHA256);
    let mut server_certificate: Certificate = Certificate(vec![]);

    let decrypted_messages = self.payload.iter().flat_map(|m| match m.payload {
      WrappedPayload::Decrypted(ref m) => Some(m),
      WrappedPayload::Encrypted(_) => None,
    });

    for msg in decrypted_messages {
      match msg.payload {
        MessagePayload::Handshake(ref handshake) => match handshake.payload {
          HandshakePayload::ClientHello(_) => {
            debug!("verify_certificate_sig: ClientHello");
            transcript_digest.add_message(msg);
          },
          HandshakePayload::ServerHello(_) => {
            debug!("verify_certificate_sig: ServerHello");
            transcript_digest.add_message(msg);
          },
          HandshakePayload::Certificate(_) => {
            // TODO for some reason this is not hit, but CertificateTLS13 is hit
            debug!("verify_certificate_sig: Certificate");
          },
          HandshakePayload::CertificateTLS13(ref certificate_payload) => {
            debug!(
              "verify_certificate_sig: CertificateTLS13: {}",
              certificate_payload.entries.len()
            );
            transcript_digest.add_message(msg);
            server_certificate = certificate_payload.entries[0].cert.clone();
          },
          HandshakePayload::CertificateVerify(ref digitally_signed_struct) => {
            debug!("verify_certificate_sig: CertificateVerify");

            // send error back to client if signature verification fails
            return match verify_tls13(
              &construct_tls13_server_verify_message(&transcript_digest.get_current_hash()),
              &server_certificate,
              digitally_signed_struct,
            ) {
              Ok(_) => Ok(()),
              Err(e) => Err(ProxyError::Sign(Box::new(e))),
            };
          },
          HandshakePayload::EncryptedExtensions(_) => {
            debug!("verify_certificate_sig: EncryptedExtensions");
            transcript_digest.add_message(msg);
          },
          HandshakePayload::Finished(_) => {
            debug!("verify_certificate_sig: Payload");

            // This is verification data from either the server or client that it has
            // finished the handshake Essentially it’s a hash of the data up to that point
            // hmac signed by the derived handshake AES key
            // https://github.com/rustls/rustls/blob/8c04dba680d19d203a7eda1951ad596f5fc2ae59/rustls/src/client/tls13.rs#L1234
          },

          // TODO: some of these (CertificateRequest, HelloRetryRequest) are not considered in happy
          // path, handle later
          _ => {
            println!("verify_certificate_sig: unhandled {:?}", handshake.typ);
          },
        },
        _ => {
          // TODO just ignore? should be handshakes only
          trace!("verify_certificate_sig: unexpected non-handshake message");
        },
      }
    }

    Err(ProxyError::TlsHandshakeVerify(String::from("unable to parse verify data")))
  }

  /// Retrieve possible valid hashes of ciphertext. Unfortunately using encrypted
  /// TLS 1.3 data as input, there is not a deterministic way to extract the
  /// request and response data.  There can be a variable number of either request
  /// or response messages and they exist in an indeterminate spot in the transcript.
  ///
  /// To overcome this, we identify the potential subsequences of bytes and then hash
  /// all of them. The verifier will check all hashes to determine if one of the correct
  /// ones was observed.
  ///
  /// To skip redundant verification in the future, we could accept a possible target hash
  /// from the client and check if it is in the set of valid hashes.
  pub fn get_ciphertext_hashes(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // State machine for extracting request response
    // Transcript Structure:
    // - Encrypted 1: server sends back verify data
    // - Encrypted 2: client sends back verify data => drop first one from client
    // - Encrypted 2..i: client sends back real request
    // - Encrypted i..j: server sends back session ticket 0..m
    // - Encrypted j..k: server sends back real response
    // - Encrypted k: server sends close notify => drop message
    //
    #[derive(Debug)]
    enum State {
      SeekingRequest,
      ParsingRequest,
      ParsingResponse,
    }

    fn process_msg(
      m: &ParsedMessage,
      bytes: Vec<u8>,
      s: State,
      req: &mut Vec<Vec<u8>>,
      resp: &mut Vec<Vec<u8>>,
    ) -> State {
      let trim = bytes.len() - TRIMMED_BYTES;
      let trimmed_bytes = bytes[..trim].to_vec();
      match s {
        State::SeekingRequest => {
          if matches!(m.direction, Direction::Received) {
            State::SeekingRequest
          } else {
            // Drop the first non-received message. It's verify data from the client.
            State::ParsingRequest
          }
        },
        State::ParsingRequest => {
          if matches!(m.direction, Direction::Sent) {
            // Case: more request messages
            req.push(trimmed_bytes);
            State::ParsingRequest
          } else {
            resp.push(trimmed_bytes);
            State::ParsingResponse
          }
        },
        State::ParsingResponse =>
          if matches!(m.direction, Direction::Received) {
            resp.push(trimmed_bytes);
            State::ParsingResponse
          } else {
            panic!("expected only response data");
          },
      }
    }

    let mut request_messages: Vec<Vec<u8>> = Vec::new();
    let mut response_messages: Vec<Vec<u8>> = Vec::new();
    let mut current_state = State::SeekingRequest;
    debug!("Transcript length: {}", self.payload.len());
    for m in self.payload.iter() {
      match &m.payload {
        WrappedPayload::Encrypted(e) => {
          info!(
            "Encrypted Message: direction={:?}, seq={:?}, typ={:?}, version={:?}, payload={:?}",
            m.direction,
            m.seq,
            e.typ,
            e.version,
            hex::encode(e.payload.0.clone())
          );
          current_state = process_msg(
            m,
            e.payload.0.clone(),
            current_state,
            &mut request_messages,
            &mut response_messages,
          );
        },
        WrappedPayload::Decrypted(d) => {
          info!(
            "Decrypted Message: direction={:?}, seq={:?}, content_type={:?}, version={:?}",
            m.direction,
            m.seq,
            d.version,
            d.payload.content_type()
          );
          continue;
        },
      };
    }

    (request_messages, response_messages)
  }
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

enum SupportedSuites {
  AesGcm,
  ChachaPoly,
}
struct DecryptWrapper {
  inner:       Decrypter,
  seq:         u64,
  ciphersuite: SupportedSuites,
}

impl DecryptWrapper {
  fn decrypt(&mut self, msg: &OpaqueMessage) -> Option<PlainMessage> {
    match self.ciphersuite {
      SupportedSuites::AesGcm => match self.inner.decrypt_tls13_aes(&msg, self.seq) {
        Ok((plain_message, _)) => {
          self.seq += 1;
          Some(plain_message)
        },
        Err(_) => None,
      },
      SupportedSuites::ChachaPoly => match self.inner.decrypt_tls13_chacha20(msg, self.seq) {
        Ok((plain_message, _)) => {
          self.seq += 1;
          Some(plain_message)
        },
        Err(_) => None,
      },
    }
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
  decrypters: &mut Vec<DecryptWrapper>,
) -> Result<Vec<WrappedPayload>, ProxyError> {
  let msg = OpaqueMessage {
    typ:     ContentType::ApplicationData,
    version: tls_client2::ProtocolVersion::TLSv1_3,
    payload: tls_client2::tls_core::msgs::base::Payload(record),
  };

  trial_decrypt(msg, decrypters)
}

use tls_client2::Decrypter;
fn make_decrypter(
  key: Option<CipherSuiteKey>,
  iv: Vec<u8>,
) -> Result<(Decrypter, SupportedSuites), ProxyError> {
  match key {
    Some(key) => match key {
      CipherSuiteKey::AES128GCM(key) => {
        return Ok((
          tls_client2::Decrypter::new(
            CipherSuiteKey::AES128GCM(key),
            iv[..12].try_into()?,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
          ),
          SupportedSuites::AesGcm,
        ));
      },
      CipherSuiteKey::CHACHA20POLY1305(key) => {
        return Ok((
          tls_client2::Decrypter::new(
            CipherSuiteKey::CHACHA20POLY1305(key),
            iv[..12].try_into()?,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
          ),
          SupportedSuites::ChachaPoly,
        ));
      },
    },
    None => panic!("unexpected key type"),
  }
}

fn trial_decrypt(
  msg: OpaqueMessage,
  decrypters: &mut Vec<DecryptWrapper>,
) -> Result<Vec<WrappedPayload>, ProxyError> {
  let possible_decryption = decrypters
    .iter_mut()
    .flat_map(|decrypter| decrypter.decrypt(&msg))
    .map(|plain_message| {
      match plain_message.typ {
        ContentType::ApplicationData =>
          Some(vec![WrappedPayload::Decrypted(plain_message.try_into().unwrap())]),
        ContentType::Handshake => Some(process_handshake(plain_message)),
        ContentType::Alert => {
          // TODO: handle this.
          debug!(
            "skipping alert: type={:?}, payload={:?}",
            ContentType::Alert,
            hex::encode(plain_message.payload.0)
          );
          None
        },
        _ => {
          error!("unsupported message type: type={:?}", plain_message.typ);
          None
        },
      }
    })
    .collect::<Vec<Option<Vec<WrappedPayload>>>>()
    .pop()
    .unwrap_or(None);

  // If we fail to decrypt with all keys, log the error and hand back encrypted data.
  match possible_decryption {
    Some(p) => Ok(p),
    None => {
      debug!("reached non-decryptable message");
      Ok(vec![WrappedPayload::Encrypted(msg)])
    },
  }
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
fn handle_client_hello(client_hello: TlsClientHelloContents) -> Result<Message, ProxyError> {
  let ch_random = process_random_bytes(client_hello.random)?;
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

  Ok(Message {
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
  })
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
fn handle_server_hello(server_hello: TlsServerHelloContents) -> Result<Message, ProxyError> {
  let sh_random = process_random_bytes(server_hello.random)?;
  let session_id = process_session_id(server_hello.session_id)?;

  let extension_byte: &[u8] =
    server_hello.ext.ok_or(ProxyError::TlsHandshakeExtract("Missing extension".to_string()))?;
  let mut extension_byte = extension_byte.to_vec();
  let sh_extension_len: [u8; 2] = (extension_byte.len() as u16).to_be_bytes();
  extension_byte.splice(0..0, sh_extension_len);

  let mut r = Reader::init(&extension_byte);
  let extensions = codec::read_vec_u16::<ServerExtension>(&mut r)
    .ok_or(ProxyError::TlsHandshakeExtract("Failed to read server extension".to_string()))?;

  Ok(Message {
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
  })
}

fn process_handshake(message: PlainMessage) -> Vec<WrappedPayload> {
  let mut handshake_joiner = HandshakeJoiner::new();
  handshake_joiner.take_message(message);
  let mut handshake_messages = Vec::new();
  while let Some(msg) = handshake_joiner.frames.pop_front() {
    let hs_typ = if let MessagePayload::Handshake(m) = &msg.payload { Some(m.typ) } else { None };
    let mut buf = Vec::new();
    msg.payload.encode(&mut buf);
    debug!(
      "TLS Handshake record: type={}, len={}",
      hs_typ.unwrap().get_u8().to_string(),
      buf.len()
    );
    handshake_messages.push(WrappedPayload::Decrypted(msg));
  }

  handshake_messages
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
  SessionID::read_bytes(&sh_session_id)
    .ok_or_else(|| ProxyError::InvalidSessionId("Failed to read session ID bytes".into()))
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_transcript_flattening() {
    let raw = Transcript {
      payload: vec![
        UnparsedMessage { direction: Direction::Sent, payload: vec![1] },
        UnparsedMessage { direction: Direction::Sent, payload: vec![2] },
        UnparsedMessage { direction: Direction::Received, payload: vec![3] },
        UnparsedMessage { direction: Direction::Received, payload: vec![4] },
        UnparsedMessage { direction: Direction::Sent, payload: vec![5] },
      ],
    };

    // Flatten the transcript
    let flattened = raw.into_flattened().unwrap();
    assert_eq!(flattened.payload.len(), 3);
    assert_eq!(flattened.payload[0].direction, Direction::Sent);
    assert_eq!(flattened.payload[0].payload, vec![1, 2]);
    assert_eq!(flattened.payload[1].direction, Direction::Received);
    assert_eq!(flattened.payload[1].payload, vec![3, 4]);
    assert_eq!(flattened.payload[2].direction, Direction::Sent);
    assert_eq!(flattened.payload[2].payload, vec![5]);
  }
}
