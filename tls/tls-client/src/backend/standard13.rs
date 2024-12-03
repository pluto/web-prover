use std::{
  any::Any,
  collections::{HashMap, VecDeque},
  convert::TryInto,
};

use aes_gcm::{
  aead::{generic_array::{GenericArray, typenum::{U12, U5}}, Aead, NewAead, Payload},
  Aes128Gcm,
};

use chacha20poly1305::{
  aead::{Aead as ChachaAead , Payload as ChaChaPayload},
  ChaCha20Poly1305,
  Nonce,
  Key,
  KeyInit,
};

use async_trait::async_trait;
use base64::{prelude::BASE64_STANDARD, write, Engine};
use log::{debug, error, info, trace, warn, Record};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey as ECDHPublicKey};
use rand::{rngs::OsRng, thread_rng, Rng};
use ring::hkdf::Okm;
use sha2::{Digest, Sha256};
use tls_core::{
  cert::ServerCertDetails,
  ke::ServerKxDetails,
  key::{Certificate, PublicKey},
  msgs::{
    base::Payload as TLSPayload,
    enums::{CipherSuite, ContentType, HandshakeType, NamedGroup, ProtocolVersion},
    handshake::Random,
    message::{OpaqueMessage, PlainMessage},
  },
  prf::prf,
  suites::{self, SupportedCipherSuite},
};

use super::{
  origo::{RecordMeta, Direction, OrigoConnection, RecordKey},
  mode::BackendError, mode::Backend,
};
use crate::{backend::tls13::AeadKey, DecryptMode, EncryptMode, Error};

/// Implementation of TLS 1.3 backend using RustCrypto primitives
pub struct RustCryptoBackend13 {
  pub client_random:  Option<Random>,
  pub server_random:  Option<Random>,
  /// pre_master_secret size various by cipher suite, for now only support 32 bytes
  pre_master_secret:  Option<[u8; 32]>,
  client_hs_secret:   Option<OkmBlock>,
  server_hs_secret:   Option<OkmBlock>,
  // extended master secret seed
  ems_seed:           Option<Vec<u8>>,
  hs_hello_seed:      Option<Vec<u8>>,
  ecdh_pubkey:        Option<Vec<u8>>,
  ecdh_secret:        Option<EphemeralSecret>,
  // session_keys size can vary depending on the ciphersuite
  session_keys:       Option<Vec<u8>>,
  protocol_version:   Option<ProtocolVersion>,
  cipher_suite:       Option<SupportedCipherSuite>,
  curve:              Option<NamedGroup>,
  implemented_suites: [CipherSuite; 2],
  encrypter:          Option<Encrypter>,
  decrypter:          Option<Decrypter>,
  decrypt_mode:       DecryptMode,
  encrypt_mode:       EncryptMode,
  hkdf_provider:      &'static dyn super::tls13::Hkdf,

  logger: std::sync::Arc<std::sync::Mutex<OrigoConnection>>,

  buffer_incoming: VecDeque<OpaqueMessage>,

  /// tk: witness values to for gnark proof gen
  pub witness:    Witness,
  /// tk: Records for witness generation
  pub record_map: HashMap<String, RecordMeta>,
}

/// Cloned of values to be used in Origo witness generation for the Gnark prover
///
/// ref: https://gist.github.com/thor314/773533a515445676ea518a429de000aa
#[allow(non_snake_case)]
#[derive(Clone, Default, Debug)]
pub struct Witness {
  /// shared key aka premaster secret
  pub DHE:  String,
  /// early secret
  pub ES:   String,
  /// derived early secret
  pub dES:  String,
  /// Handshake secret
  pub HS:   String,
  /// Client handshake secret
  pub CHTS: String,
  /// transcript hash
  pub H2:   String,
  /// server handshake secret
  pub SHTS: String,
  /// derived handshake secret
  pub dHS:  String,
  /// master secret
  pub MS:   String,
  /// transcript hash h7
  pub H7:   String,
  /// client application traffic secret
  pub CATS: String,
  /// transcript hash h3
  pub H3:   String,
  /// server application traffic secret
  pub SATS: String,
}

impl std::fmt::Display for Witness {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{{
                DHE: {},
                ES: {},
                dES: {},
                HS: {},
                CHTS: {},
                H2: {},
                SHTS: {},
                dHS: {},
                MS: {},
                H7: {},
                CATS: {},
                H3: {},
                SATS: {}
            }}",
      self.DHE,
      self.ES,
      self.dES,
      self.HS,
      self.CHTS,
      self.H2,
      self.SHTS,
      self.dHS,
      self.MS,
      self.H7,
      self.CATS,
      self.H3,
      self.SATS
    )
  }
}

pub struct TlsKeys {
  client_key: AeadKey,
  client_iv:  AeadKey,
  server_key: AeadKey,
  server_iv:  AeadKey,
}

// === Helpers
// TODO: Move into different lib.
use super::tls13::{expand, HkdfExpander, OkmBlock};

pub fn hkdf_expand_label<T: From<[u8; N]>, const N: usize>(
  expander: &dyn HkdfExpander,
  label: &[u8],
  context: &[u8],
) -> T {
  hkdf_expand_label_inner(expander, label, context, N, |e, info| expand(e, info))
}

pub fn hkdf_expand_label_block(
  expander: &dyn HkdfExpander,
  label: &[u8],
  context: &[u8],
) -> OkmBlock {
  hkdf_expand_label_inner(expander, label, context, expander.hash_len(), |e, info| {
    e.expand_block(info)
  })
}

pub fn hkdf_expand_label_aead_key(
  expander: &dyn HkdfExpander,
  key_len: usize,
  label: &[u8],
  context: &[u8],
) -> AeadKey {
  hkdf_expand_label_inner(expander, label, context, key_len, |e, info| {
    let key: AeadKey = expand(e, info);
    key.with_length(key_len)
  })
}

pub fn hkdf_expand_label_inner<F, T>(
  e: &dyn HkdfExpander,
  label: &[u8],
  context: &[u8],
  key_len: usize,
  f: F,
) -> T
where
  F: FnOnce(&dyn HkdfExpander, &[&[u8]]) -> T,
{
  const LABEL_PREFIX: &[u8] = b"tls13 ";
  let info = &[
    &u16::to_be_bytes(key_len as u16)[..],
    &u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8)[..],
    LABEL_PREFIX,
    label,
    &u8::to_be_bytes(context.len() as u8)[..],
    context,
  ];
  trace!("hkdf_expand label={:?}", info);

  f(e, info)
}

impl RustCryptoBackend13 {
  /// Creates new instance of RustCrypto backend
  pub fn new(origo: std::sync::Arc<std::sync::Mutex<OrigoConnection>>) -> Self {
    Self {
      client_random:      None,
      server_random:      None,
      ecdh_pubkey:        None,
      ecdh_secret:        None,
      pre_master_secret:  None,
      client_hs_secret:   None,
      server_hs_secret:   None,
      ems_seed:           None,
      hs_hello_seed:      None,
      session_keys:       None,
      protocol_version:   None,
      cipher_suite:       None,
      curve:              Some(NamedGroup::secp256r1),
      implemented_suites: [CipherSuite::TLS13_AES_128_GCM_SHA256, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256],
      hkdf_provider:      &super::tls13::HkdfUsingHmac(&super::hmac::Sha256Hmac),
      encrypter:          None,
      decrypter:          None,
      buffer_incoming:    VecDeque::new(),
      decrypt_mode:       DecryptMode::Handshake,
      encrypt_mode:       EncryptMode::Handshake,
      logger:             origo,
      witness:            Witness::default(),
      record_map:         HashMap::default(),
    }
  }

  /// tk: add a field to the witness record map
  pub fn insert_record(
    &mut self,
    d: Direction,
    seq: u64,
    ct: ContentType,
    first_byte: u8,
    record_meta: RecordMeta,
  ) {
    self.record_map.insert(record_meta.nonce.clone(), record_meta.clone());
    self.logger.lock().unwrap().insert_record(RecordKey::new(d, ct, seq, first_byte), record_meta);
  }

  /// consume the witness data generated for writing `session_params_13.json`
  pub fn write_witness_to_file(&self) {
    // todo
    todo!();
  }

  /// Derive keys for a given mode. Depends on pre_master_secret.
  pub fn derive_keys(&mut self) -> TlsKeys {
    self.witness.DHE = BASE64_STANDARD.encode(self.pre_master_secret.unwrap());
    trace!("setting DHE to {:?}", self.witness.DHE);
    if self.pre_master_secret.is_none() {
      panic!("attempt to derive keys without pre_master_secret");
    }

    let okm_block = OkmBlock::default();
    {
      // ES = hkdf-extract(nil, nil).
      let es = self.hkdf_provider.hmac_sign(&okm_block, &[0u8; 32]);
      self.witness.ES = BASE64_STANDARD.encode(es); // warning: rather suspect!
      trace!("setting ES to {:?}", self.witness.ES);
    }

    // initialize empty hash context
    let mut hasher = Sha256::new();
    hasher.update(b"");
    let context = hasher.finalize();
    trace!("empty salt ctxt={:?}", BASE64_STANDARD.encode(context));

    let current = self.hkdf_provider.extract_from_zero_ikm(Some(okm_block.as_ref()));
    let k0_salt = hkdf_expand_label_block(current.as_ref(), b"derived", &context);
    self.witness.dES = BASE64_STANDARD.encode(k0_salt.clone()); // warning: suspect! dES not derived from ES.
    trace!("setting dES to {:?}", self.witness.dES);
    let k0_secret = self
      .hkdf_provider
      .extract_from_secret(Some(k0_salt.as_ref()), &self.pre_master_secret.unwrap());
    {
      let hs_tag = self.hkdf_provider.hmac_sign(&k0_salt, &self.pre_master_secret.unwrap().clone());
      self.witness.HS = BASE64_STANDARD.encode(hs_tag);
      trace!("setting HS to {:?}", self.witness.HS);
    }

    // Choose master secret and key labels. This is expanded into the AES keys for the connection.
    // It's dependent on the per connection randomness.
    let (master_secret, client_label, server_label) =
      if matches!(self.encrypt_mode, EncryptMode::Application) {
        // When deriving the application keys, we need to derive a k+1 salt and master secret
        let k1_salt = hkdf_expand_label_block(k0_secret.as_ref(), b"derived", &context);
        self.witness.dHS = BASE64_STANDARD.encode(k1_salt.as_ref());
        trace!("setting dHS to {:?}", self.witness.dHS);

        let k1_secret = self.hkdf_provider.extract_from_secret(Some(k1_salt.as_ref()), &[0u8; 32]);

        let ms = self.hkdf_provider.hmac_sign(&k1_salt, &[0u8; 32]);
        self.witness.MS = BASE64_STANDARD.encode(ms);
        trace!("setting MS to {:?}", self.witness.MS);

        (k1_secret, b"c ap traffic", b"s ap traffic")
      } else {
        // In the base case, derive the first master secret.
        (k0_secret, b"c hs traffic", b"s hs traffic")
      };

    // Expand the master secret into two labeled secrets
    // expect: context / handshake hash = h3 at handshake layer
    let context = self.ems_seed.clone().unwrap();
    debug!("context={:?}", hex::encode(context.clone()));
    let client_secret = hkdf_expand_label_block(master_secret.as_ref(), client_label, &context);
    let server_secret = hkdf_expand_label_block(master_secret.as_ref(), server_label, &context);

    // janky, log the secrets if handshake mode, as they're required for verification data.
    if matches!(self.encrypt_mode, EncryptMode::Handshake) {
      self.witness.H2 = BASE64_STANDARD.encode(self.ems_seed.clone().unwrap());
      self.witness.CHTS = BASE64_STANDARD.encode(client_secret.clone());
      self.witness.SHTS = BASE64_STANDARD.encode(server_secret.clone());
      trace!("setting CHTS to {:?}", self.witness.CHTS);
      trace!("setting SHTS to {:?}", self.witness.SHTS);
      trace!("setting H2 to {:?}", self.witness.H2);
      self.client_hs_secret = Some(client_secret.clone());
      self.server_hs_secret = Some(server_secret.clone());
    } else {
      self.witness.H3 = BASE64_STANDARD.encode(self.ems_seed.clone().unwrap());
      self.witness.CATS = BASE64_STANDARD.encode(client_secret.clone());
      self.witness.SATS = BASE64_STANDARD.encode(server_secret.clone());
      trace!("setting CATS to {:?}", self.witness.CATS);
      trace!("setting SATS to {:?}", self.witness.SATS);
      trace!("setting H3 to {:?}", self.witness.H3);
    }

    debug!("intermediate witness set during encrypt_mode: {:?}", self.encrypt_mode);

    // Finally, derive the actual AES key and IV for each secret.
    let client_expander = self.hkdf_provider.expander_for_okm(&client_secret);
    let server_expander = self.hkdf_provider.expander_for_okm(&server_secret);
    let client_iv = hkdf_expand_label_aead_key(client_expander.as_ref(), 12, b"iv", &[]);
    let server_iv = hkdf_expand_label_aead_key(server_expander.as_ref(), 12, b"iv", &[]);
    debug!("CipherSuite={:?}", self.cipher_suite.unwrap().suite());
    let (client_key, server_key) = match self.cipher_suite.unwrap().suite() {
      CipherSuite::TLS13_AES_128_GCM_SHA256 => {
        let client_key = hkdf_expand_label_aead_key(client_expander.as_ref(), 16, b"key", &[]);
        self.logger.lock().unwrap().set_secret(
          format!("{:?}:client_key", self.encrypt_mode).to_string(),
          client_key.buf[..16].to_vec(),
        );
        let server_key = hkdf_expand_label_aead_key(server_expander.as_ref(), 16, b"key", &[]);
        self.logger.lock().unwrap().set_secret(
          format!("{:?}:server_key", self.encrypt_mode).to_string(),
          server_key.buf[..16].to_vec(),
        );
        debug!("client_key={:?}", client_key.buf.len());
        (
          client_key,
          server_key,
        )
      },
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
        let client_key = hkdf_expand_label_aead_key(client_expander.as_ref(), 32, b"key", &[]);
        self.logger.lock().unwrap().set_secret(
          format!("{:?}:client_key", self.encrypt_mode).to_string(),
          client_key.buf.into(),
        );
        let server_key = hkdf_expand_label_aead_key(server_expander.as_ref(), 32, b"key", &[]);
        self.logger.lock().unwrap().set_secret(
          format!("{:?}:server_key", self.encrypt_mode).to_string(),
          server_key.buf.into(),
        );
        debug!("client_key={:?}", client_key.buf.len());
        (
          client_key,
          server_key,
        )

      },
      _ => panic!("unsupported ciphersuite"),
    };


    trace!(
      "client_iv={:?}, iv_len={:?}",
      hex::encode(client_iv.buf),
      client_iv.buf.len()
    );
    self.logger.lock().unwrap().set_secret(
      format!("{:?}:client_iv", self.encrypt_mode).to_string(),
      client_iv.buf.into(),
    );

    trace!(
      "client_key={:?}, iv_len={:?}",
      hex::encode(client_key.buf),
      client_iv.buf.len()
    );

    trace!(
      "server_iv={:?}, iv_len={:?}",
      hex::encode(server_iv.buf),
      server_iv.buf.len()
    );
    self.logger.lock().unwrap().set_secret(
      format!("{:?}:server_iv", self.encrypt_mode).to_string(),
      server_iv.buf.into(),
    );

    trace!(
      "server_key={:?}, iv_len={:?}",
      hex::encode(server_key.buf),
      server_key.buf.len()
    );

    TlsKeys {
      client_key,
      client_iv,
      server_key,
      server_iv,
    }
  }

  /// Derive an encrypter from the given keys
  pub fn get_encrypter(&self, keys: &TlsKeys) -> Encrypter {
    match self.cipher_suite.unwrap().suite() {
      CipherSuite::TLS13_AES_128_GCM_SHA256 => {
        let mut key = [0u8; 16];
        key.copy_from_slice(&keys.client_key.buf[..16]);
        debug!("Got Encrypter with key length: {:?}", key.len());
        Encrypter::new(
        CipherSuiteKey::AES128GCM(key),
        keys.client_iv.buf[..12].try_into().unwrap(),
        self.cipher_suite.unwrap().suite(),
      )},
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
        let mut key = [0u8; 32];
        key.copy_from_slice(&keys.client_key.buf[..32]);
        debug!("Got Encrypter with key length: {:?}", key.len());
        Encrypter::new(
        CipherSuiteKey::CHACHA20POLY1305(key),
        keys.client_iv.buf[..12].try_into().unwrap(),
        self.cipher_suite.unwrap().suite(),
      )},
      _ => panic!("unsupported ciphersuite"),
    }
  }

  /// Derive an decrypter from the given keys
  pub fn get_decrypter(&self, keys: &TlsKeys) -> Decrypter {
    match self.cipher_suite.unwrap().suite() {
      CipherSuite::TLS13_AES_128_GCM_SHA256 => {
        let mut key = [0u8; 16];
        key.copy_from_slice(&keys.server_key.buf[..16]);
        debug!("Got Decrypter with key length: {:?}", key.len());
        Decrypter::new(
        CipherSuiteKey::AES128GCM(key),
        keys.server_iv.buf[..12].try_into().unwrap(),
        self.cipher_suite.unwrap().suite(),
      )},
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
        let mut key = [0u8; 32];
        key.copy_from_slice(&keys.server_key.buf[..32]);
        debug!("Got Decrypter with key length: {:?}", key.len());
         Decrypter::new(
      CipherSuiteKey::CHACHA20POLY1305(key),
      keys.server_iv.buf[..12].try_into().unwrap(),
      self.cipher_suite.unwrap().suite(),
      )},
      _ => panic!("unsupported ciphersuite"),
    }
  }
}

#[async_trait]
impl Backend for RustCryptoBackend13 {
  fn set_pre_master_secret(&mut self, ms: [u8; 32]) -> Result<(), BackendError> {
    self.pre_master_secret = Some(ms);
    Ok(())
  }

  fn get_pre_master_secret(&mut self) -> Option<[u8; 32]> { self.pre_master_secret }

  // === Basic Session Configuration ===
  async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
    match version {
      ProtocolVersion::TLSv1_3 => {
        self.protocol_version = Some(version);
        Ok(())
      },
      version => return Err(BackendError::UnsupportedProtocolVersion(version)),
    }
  }

  async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
    let version = self.protocol_version.ok_or(BackendError::InvalidState(
      "can not set ciphersuite, protocol version not set".to_string(),
    ))?;

    if suite.version().version != version {
      return Err(BackendError::InvalidConfig(
        "Ciphersuite protocol version does not match configured version".to_string(),
      ));
    }

    if !self.implemented_suites.contains(&suite.suite()) {
      return Err(BackendError::UnsupportedCiphersuite(suite.suite()));
    }
    self.cipher_suite = Some(suite);

    Ok(())
  }

  // TODO(WJ 2024-11-21): this is unused
  // NOTE: For now only support the bare minimum. Extend to more in the future.
  async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
    Ok(suites::tls13::TLS13_AES_128_GCM_SHA256)
  }

  // === Handshake Cryptography Setup ==
  async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
    // In TLS1.3, this is sent during the start of the handshake, enabling
    // the server to encrypt more of the data. It should be identical to
    // the algorithm of TLS1.2, just a different point in time.

    let sk = EphemeralSecret::random(&mut OsRng);
    let pk_bytes = EncodedPoint::from(sk.public_key()).to_bytes().to_vec();
    self.ecdh_pubkey = Some(pk_bytes.clone());
    self.ecdh_secret = Some(sk);

    // return our ECDH pubkey
    let group =
      self.curve.ok_or(BackendError::InvalidState("ECDH key curve not set yet".to_string()))?;

    Ok(PublicKey { group, key: pk_bytes })
  }

  // NOTE: We hardcode this method to simultaneously derive the handshake keys for a connection.
  // There are features in TLS 1.3 which this does not support (early data, resumption, ech, key
  // update) in most cases this will work.
  async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
    let sk = self.ecdh_secret.as_ref().unwrap();
    let server_pk =
      ECDHPublicKey::from_sec1_bytes(&key.key).map_err(|_| BackendError::InvalidServerKey)?;

    // Start with diffie hellman dto produce the shared pre_master_secret
    let mut pms = [0u8; 32]; // NOTE: 32 bytes in both impls
    let secret = *sk.diffie_hellman(&server_pk).raw_secret_bytes();
    pms.copy_from_slice(secret.as_slice());
    self.pre_master_secret = Some(pms);
    trace!("pre_master_secret={:?}", BASE64_STANDARD.encode(pms));

    // Now, for tls 1.3, perform the "key expansion" necessary for connection enc/dec
    let keys = self.derive_keys(); // wtf
    self.encrypter = Some(self.get_encrypter(&keys));
    self.decrypter = Some(self.get_decrypter(&keys));

    Ok(())
  }

  async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
    let e = self.hkdf_provider.expander_for_okm(&self.server_hs_secret.clone().unwrap());
    let hmac_key = hkdf_expand_label_block(e.as_ref(), b"finished", &[]);
    let r = self.hkdf_provider.hmac_sign(&hmac_key, &hash);

    return Ok(r.as_ref().to_vec());
  }

  async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
    let e = self.hkdf_provider.expander_for_okm(&self.client_hs_secret.clone().unwrap());
    let hmac_key = hkdf_expand_label_block(e.as_ref(), b"finished", &[]);
    let r = self.hkdf_provider.hmac_sign(&hmac_key, &hash);

    return Ok(r.as_ref().to_vec());
  }

  async fn encrypt(&mut self, msg: PlainMessage, seq: u64) -> Result<OpaqueMessage, BackendError> {
    let enc = self
      .encrypter
      .as_mut()
      .ok_or(BackendError::EncryptionError("Encrypter not ready".to_string()))?;

    match enc.cipher_suite {
      CipherSuite::TLS13_AES_128_GCM_SHA256 => match msg.version {
        // TODO: Do we need both on the encrypt side?
        ProtocolVersion::TLSv1_3 | ProtocolVersion::TLSv1_2 => {
          let (cipher_msg, meta) = enc.encrypt_tls13_aes(&msg, seq)?;

          self.insert_record(Direction::Sent, seq, msg.typ, msg.payload.0[0], meta);
          return Ok(cipher_msg);
        },
        version => {
          return Err(BackendError::UnsupportedProtocolVersion(version));
        },
      },
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => match msg.version{
        ProtocolVersion::TLSv1_3 | ProtocolVersion::TLSv1_2  => {
          let (cipher_msg, meta) = enc.encrypt_tls13_chacha20_poly1305(&msg, seq)?;

          self.insert_record(Direction::Sent, seq, msg.typ, msg.payload.0[0], meta);
          return Ok(cipher_msg);
        },
        version => {
          return Err(BackendError::UnsupportedProtocolVersion(version));
        },
      },
      suite => {
        return Err(BackendError::UnsupportedCiphersuite(suite));
      },
    }
  }

  async fn decrypt(&mut self, msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, BackendError> {
    let dec = self
      .decrypter
      .as_mut()
      .ok_or(BackendError::DecryptionError("Decrypter not ready".to_string()))?;

    match dec.cipher_suite {
      CipherSuite::TLS13_AES_128_GCM_SHA256
       => match msg.version {
        // NOTE: Must support both because cipher messages are labeled 1.2
        ProtocolVersion::TLSv1_3 | ProtocolVersion::TLSv1_2 => {
          let (plain_message, record_meta) = dec.decrypt_tls13_aes(&msg, seq)?;
          self.insert_record(
            Direction::Received,
            seq,
            plain_message.typ,
            plain_message.payload.0[0],
            record_meta,
          );
          return Ok(plain_message);
        },
        version => {
          return Err(BackendError::UnsupportedProtocolVersion(version));
        },
      },
      CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => match msg.version {
        ProtocolVersion::TLSv1_3 | ProtocolVersion::TLSv1_2 => {
          let (plain_message, record_meta) = dec.decrypt_tls13_chacha20(&msg, seq)?;
          self.insert_record(
            Direction::Received,
            seq,
            plain_message.typ,
            plain_message.payload.0[0],
            record_meta,
          );
          return Ok(plain_message);
        },
        version => {
          return Err(BackendError::UnsupportedProtocolVersion(version));
        },
            }
      suite => {
        return Err(BackendError::UnsupportedCiphersuite(suite));
      },
    }
  }

  // Switch between handshake and application keys.
  fn set_encrypt_decrypt(&mut self, mode: EncryptMode) -> Result<(), BackendError> {
    debug!("toggling encrypt mode: {:?}", mode);
    self.encrypt_mode = mode;

    if matches!(self.encrypt_mode, EncryptMode::Application | EncryptMode::Handshake) {
      let keys = self.derive_keys();
      self.encrypter = Some(self.get_encrypter(&keys));
      self.decrypter = Some(self.get_decrypter(&keys));
    }

    if matches!(self.encrypt_mode, EncryptMode::Application) {
      //   tk_dbg_with_context(&self.witness);
    }

    Ok(())
  }

  /// generate client random and store it
  async fn get_client_random(&mut self) -> Result<Random, BackendError> {
    let r = Random(thread_rng().gen());
    self.client_random = Some(r);
    self.logger.lock().unwrap().set_secret("client_random".to_string(), r.0.to_vec());
    Ok(r)
  }

  async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
    // store server random
    self.server_random = Some(random);
    Ok(())
  }

  async fn set_server_cert_details(
    &mut self,
    _cert_details: ServerCertDetails,
  ) -> Result<(), BackendError> {
    Ok(())
  }

  async fn set_server_kx_details(
    &mut self,
    _kx_details: ServerKxDetails,
  ) -> Result<(), BackendError> {
    Ok(())
  }

  fn get_hs_hash_client_key_exchange(&self) -> Result<Option<Vec<u8>>, BackendError> {
    Ok(self.ems_seed.clone())
  }

  fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
    debug!("Setting Client KX Hash: {:x?}", BASE64_STANDARD.encode(hash.clone()));

    self.ems_seed = Some(hash.to_vec());
    Ok(())
  }

  fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
    debug!("Setting Server Hello Hash: {:?}", BASE64_STANDARD.encode(hash.clone()));
    self.hs_hello_seed = Some(hash.to_vec());
    Ok(())
  }

  async fn prepare_encryption(&mut self) -> Result<(), BackendError> { Ok(()) }

  async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
    self.buffer_incoming.push_back(msg);
    Ok(())
  }

  async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
    Ok(self.buffer_incoming.pop_front())
  }

  async fn buffer_len(&mut self) -> Result<usize, BackendError> { Ok(self.buffer_incoming.len()) }

  fn set_witness_h7(&mut self, h7: &[u8]) -> Result<(), BackendError> {
    self.witness.H7 = BASE64_STANDARD.encode(h7);
    trace!("setting H7 to {:?}", self.witness.H7);
    Ok(())
  }
}

fn tk_dbg_with_context(witness: &Witness) {
  let expected = [
    ("DHE", "vC4GIYWwM1k4WJnIuW29+OpFLGJdzIJeuWnkE93wYQM="),
    ("ES", "M60KHGB+wDsJ5s2Yk2gM4hCt8wCqHyZg4bIuEPFw+So="),
    ("dES", "byYVoQjHAsVnj1T8nbq2lxbAdhicSCUM6+rDV2w2Ebo="),
    ("HS", "u+Wcepisyp9Y19JfjX1SaOj5TZSIthgR73bQjl3CQBQ="),
    ("CHTS", "sRzF/bbqN7mbp8J/eWOWz2V0lCpM+y33qmi/1Lck7hc="),
    ("H2", "sGq3ZD04fmlO/DSPh/6LvBWSMTjpAeETrGEyJ0NvHXA="),
    ("SHTS", "0lMWahfpu5Sn3jTjxnQ/21ukze2caE36RpBUoEDH4xA="),
    ("dHS", "Ug1ENXl4efjfXDL8onS0n+zGgLdx6JVNqEZtjygXhrk="),
    ("MS", "M9Z4fWEMNTo821O5NPPhBvKZk63i4+4x3nTffujRm+4="),
    ("H7", "WSZc7DcCkCHYCGpbdprCwa1ZZFxdPSjKyU33hYWkSk4="),
    ("CATS", "a2I4MMsmeBPeUKS4H+OuMGhdPZJVLDcLSlhd63uksvM="),
    ("H3", "T2oRxmufMZ+212X4G+qyUt7tB73Xmun+BsTfPz9u9bE="),
    ("SATS", "w1KIzRTWnmPW8eyBOTsBl79Jr1HZ6KV4qwZ6oOQyKJ0="),
  ];
  let target = HashMap::from(expected);
  for (k, v) in target {
    let s = format!("{k}: {v}");
    if !witness.to_string().contains(&s) {
      debug!("witness value mismatch for key: {:?}; want: {}", k, &s);
    }
  }

  debug!("witness: {witness}");
}

pub fn make_nonce(iv: [u8; 12], seq: u64) -> [u8; 12] {
  let mut nonce = [0u8; 12];
  nonce[4..].copy_from_slice(&seq.to_be_bytes());

  nonce.iter_mut().zip(iv.iter()).for_each(|(nonce, iv)| {
    *nonce ^= *iv;
  });

  nonce
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
  loop {
    match v.pop() {
      Some(0) => {},
      Some(content_type) => return ContentType::from(content_type),
      None => return ContentType::Unknown(0),
    }
  }
}

fn make_tls13_aad(len: usize) -> [u8; 5] {
  [
    0x17, // ContentType::ApplicationData
    0x3,  // ProtocolVersion (major)
    0x3,  // ProtocolVersion (minor)
    (len >> 8) as u8,
    len as u8,
  ]
}

#[derive(Clone)]
pub enum CipherSuiteKey{
    AES128GCM([u8; 16]), // 128-bit key
    CHACHA20POLY1305([u8; 32]), // 256-bit key
}

impl AsRef<[u8]> for CipherSuiteKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            CipherSuiteKey::AES128GCM(key) => key,
            CipherSuiteKey::CHACHA20POLY1305(key) => key,
        }
    }
}

pub struct Encrypter {
    write_key: CipherSuiteKey,
    write_iv: [u8; 12],
    cipher_suite: CipherSuite,
}

impl Encrypter {
  pub fn new(write_key: CipherSuiteKey, write_iv: [u8; 12], cipher_suite: CipherSuite) -> Self {
    Self { write_key, write_iv, cipher_suite }
  }

/// Encrypts a TLS 1.3 message using ChaCha20-Poly1305 AEAD cipher.
///
/// This function performs TLS 1.3 record layer encryption using ChaCha20-Poly1305:
/// - Appends the content type to the plaintext (as required by TLS 1.3)
/// - Generates the additional authenticated data (AAD)
/// - Encrypts using ChaCha20-Poly1305 with the configured key and nonce
/// - Returns an opaque message suitable for transmission
///
/// # Security Considerations
/// 
/// - The sequence number must not repeat for a given key
/// - The write key must be exactly 32 bytes 
/// - The initialization vector must be 12 bytes
///
/// # Arguments
///
/// * `m` - The plaintext message to encrypt
/// * `seq` - The record sequence number used for nonce generation
///
/// # Returns
///
/// Returns a tuple containing:
/// - An `OpaqueMessage` with the encrypted payload
/// - A `RecordMeta` containing encryption metadata for debugging/verification
///
/// # Errors
///
/// Returns `BackendError` if:
/// - Encryption fails
/// - Wrong key type is used (must be CHACHA20POLY1305)
///
/// # Panics
///
/// Panics if the write key is not a CHACHA20POLY1305 key
///
  fn encrypt_tls13_chacha20_poly1305(
    &self,
    m: &PlainMessage,
    seq: u64,
  ) -> Result<(OpaqueMessage, RecordMeta), BackendError> {
    let total_len = m.payload.0.len() + 1 + 16;
    let aad = make_tls13_aad(total_len);
    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(&m.payload.0);
    payload.push(m.typ.get_u8()); // Very important, encrypted messages must have the type appended.

    let write_key = match self.write_key {
      CipherSuiteKey::CHACHA20POLY1305(key) => key,
      _ => unreachable!("wrong key type"),
    };
    let write_key = Key::from_slice(&write_key);
    let cipher = ChaCha20Poly1305::new(write_key);
    let init_nonce = Nonce::from(make_nonce(self.write_iv, seq));
    let payload = ChaChaPayload { msg: &payload, aad: &aad };
    let ciphertext = cipher
      .encrypt(&init_nonce, payload)
      .map_err(|e| BackendError::EncryptionError(e.to_string()))?;

    trace!("ENC: cipher={:?}", hex::encode(ciphertext.clone()));
    trace!("ENC: plain_text={:?}", hex::encode(m.payload.0.clone()));
    debug!(
      "ENC: cipher_len={:?}, plain_len={:?}, seq={:?}, iv={:?}, dec_key={:?}, nonce={:?}, aad={:?}",
      ciphertext.len(),
      m.payload.0.len(),
      seq,
      hex::encode(self.write_iv),
      hex::encode(write_key),
      hex::encode(init_nonce),
      hex::encode(aad),
    );

    Ok((
      OpaqueMessage {
        typ:     ContentType::ApplicationData, // Always send Application Data label
        version: ProtocolVersion::TLSv1_2,     // Opaque Messages lie.
        payload: TLSPayload::new(ciphertext.clone()),
      },
      RecordMeta::new(&aad, &m.payload.0, &ciphertext, &init_nonce ),
    ))
    
  }

  fn encrypt_tls13_aes(
    &self,
    m: &PlainMessage,
    seq: u64,
  ) -> Result<(OpaqueMessage, RecordMeta), BackendError> {
    let total_len = m.payload.0.len() + 1 + 16;
    let aad = make_tls13_aad(total_len);
    let init_nonce =  make_nonce(self.write_iv, seq);

    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(&m.payload.0);
    payload.push(m.typ.get_u8()); // Very important, encrypted messages must have the type appended.

    let aes_payload = Payload { msg: &payload, aad: &aad };

    let write_key = match self.write_key {
      CipherSuiteKey::AES128GCM(key) => key,
      _ => unreachable!("wrong key type"),
    };

    let cipher = Aes128Gcm::new((&write_key).into());
    let nonce = GenericArray::<u8, U12>::from_slice(&init_nonce);
    let ciphertext = cipher
      .encrypt(nonce, aes_payload)
      .map_err(|e| BackendError::EncryptionError(e.to_string()))?;

    trace!("ENC: cipher={:?}", hex::encode(ciphertext.clone()));
    trace!("ENC: plain_text={:?}", hex::encode(m.payload.0.clone()));
    debug!(
      "ENC: cipher_len={:?}, plain_len={:?}, seq={:?}, iv={:?}, dec_key={:?}, nonce={:?}, aad={:?}",
      ciphertext.len(),
      m.payload.0.len(),
      seq,
      hex::encode(self.write_iv),
      hex::encode(write_key),
      hex::encode(nonce),
      hex::encode(aad),
    );

    Ok((
      OpaqueMessage {
        typ:     ContentType::ApplicationData, // Always send Application Data label
        version: ProtocolVersion::TLSv1_2,     // Opaque Messages lie.
        payload: TLSPayload::new(ciphertext.clone()),
      },
      RecordMeta::new(&aad, &m.payload.0, &ciphertext, nonce),
    ))
  }
}

pub struct Decrypter {
  // Keys are symetric for us right now
  write_key:   CipherSuiteKey,
  write_iv:     [u8; 12],
  cipher_suite: CipherSuite,
}

impl Decrypter {
  pub fn new(write_key: CipherSuiteKey, write_iv: [u8; 12], cipher_suite: CipherSuite) -> Self {
    Self { write_key, write_iv, cipher_suite }
  }

  /// Decrypts a TLS 1.3 message using ChaCha20-Poly1305 AEAD cipher.
  ///
  /// This function performs TLS 1.3 record layer decryption using ChaCha20-Poly1305:
  /// - Generates additional authenticated data (AAD) from message length
  /// - Decrypts using ChaCha20-Poly1305 with the configured key and nonce
  /// - Removes padding and extracts the true content type
  /// - Returns the decrypted plaintext message and metadata
  ///
  /// # Security Considerations
  ///
  /// - The sequence number must not repeat for a given key
  /// - The write key must be exactly 32 bytes
  /// - The initialization vector must be 12 bytes
  /// - Message authentication tag is verified during decryption
  ///
  /// # Arguments
  ///
  /// * `m` - The encrypted opaque message to decrypt
  /// * `seq` - The record sequence number used for nonce generation
  ///
  /// # Returns
  ///
  /// Returns a tuple containing:
  /// - A `PlainMessage` with the decrypted payload and true content type
  /// - A `RecordMeta` containing decryption metadata for debugging/verification 
  ///
  /// # Errors
  ///
  /// Returns `BackendError` if:
  /// - Decryption fails (invalid tag, corrupted message)
  /// - Wrong key type is used (must be CHACHA20POLY1305)
  /// - Message contains invalid padding or content type
  ///
  /// # Panics
  ///
  /// Panics if the write key is not a CHACHA20POLY1305 key
  ///
  pub fn decrypt_tls13_chacha20(
    &self,
    m: &OpaqueMessage,
    seq: u64,
  ) -> Result<(PlainMessage, RecordMeta), BackendError> {

    let aad = make_tls13_aad(m.payload.0.len());
    // let init_nonce = make_nonce(self.write_iv, seq);


    let write_key = match self.write_key {
      CipherSuiteKey::CHACHA20POLY1305(key) => key,
      _ => unreachable!("wrong key"),};

    let write_key = Key::from_slice(&write_key);
    let cipher = ChaCha20Poly1305::new(write_key);
    let init_nonce = Nonce::from(make_nonce(self.write_iv, seq));
    let chacha_payload = ChaChaPayload { msg: &m.payload.0, aad: &aad };

    let mut plaintext = cipher
      .decrypt(&init_nonce, chacha_payload)
      .map_err(|e| BackendError::DecryptionError(e.to_string()))?;

    let typ = unpad_tls13(&mut plaintext);
    if typ == ContentType::Unknown(0) {
      return Err(BackendError::InternalError("peer sent bad TLSInnerPlaintext".to_string()));
    }
    trace!("DEC: cipher={:?}", hex::encode(m.payload.0.clone()));
    trace!("DEC: plain_text={:?}", hex::encode(plaintext.clone()));
    debug!(
      "DEC: cipher_len={:?}, plain_len={:?}, seq={:?}, iv={:?}, dec_key={:?}, nonce={:?}, aad={:?}",
      m.payload.0.len(),
      plaintext.len(),
      seq,
      hex::encode(self.write_iv),
      hex::encode(write_key),
      hex::encode(init_nonce),
      hex::encode(aad)
    );

    Ok((
      PlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_3,
        payload: TLSPayload(plaintext.clone()),
      },
      RecordMeta::new(&aad, &plaintext, &m.payload.0, &init_nonce),
    ))

  }

  pub fn decrypt_tls13_aes(
    &self,
    m: &OpaqueMessage,
    seq: u64,
  ) -> Result<(PlainMessage, RecordMeta), BackendError> {
    let aad = make_tls13_aad(m.payload.0.len());
    let init_nonce = make_nonce(self.write_iv, seq);

    let aes_payload = Payload { msg: &m.payload.0, aad: &aad };

    let write_key = match self.write_key {
      CipherSuiteKey::AES128GCM(key) => key,
      _ => unreachable!("wrong key"),};

    let cipher = Aes128Gcm::new_from_slice(&write_key).unwrap();
    let nonce = GenericArray::<u8, U12>::from_slice(&init_nonce);
    debug!("Attempting to aes decrypt with key: {:?}", write_key);
    let mut plaintext = cipher
      .decrypt(nonce, aes_payload)
      .map_err(|e| BackendError::DecryptionError(e.to_string()))?; // error in invalid here

    let typ = unpad_tls13(&mut plaintext);
    if typ == ContentType::Unknown(0) {
      return Err(BackendError::InternalError("peer sent bad TLSInnerPlaintext".to_string()));
    }

    trace!("DEC: cipher={:?}", hex::encode(m.payload.0.clone()));
    trace!("DEC: plain_text={:?}", hex::encode(plaintext.clone()));
    debug!(
      "DEC: cipher_len={:?}, plain_len={:?}, seq={:?}, iv={:?}, dec_key={:?}, nonce={:?}, aad={:?}",
      m.payload.0.len(),
      plaintext.len(),
      seq,
      hex::encode(self.write_iv),
      hex::encode(write_key),
      hex::encode(nonce),
      hex::encode(aad)
    );

    Ok((
      PlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_3,
        payload: TLSPayload(plaintext.clone()),
      },
      RecordMeta::new(&aad, &plaintext, &m.payload.0, nonce),
    ))
  }
}
