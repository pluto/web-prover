use std::{
  collections::HashMap,
  io::{BufReader, Cursor},
  path::PathBuf,
  sync::Arc,
};

use arecibo::{provider::Bn256EngineKZG, supernova::RecursiveSNARK};
use futures::{channel::oneshot, AsyncWriteExt};
use hyper::{body::Bytes, Request, StatusCode};
use proofs::{
  circom::witness::load_witness_from_bin_reader,
  program,
  program::data::{
    CircuitData, Expanded, FoldInput, InstructionConfig, NotExpanded, Online, ProgramData,
    R1CSType, SetupData, WitnessGeneratorType,
  },
};
use serde::Serialize;
use serde_json::{json, Value};
use tls_client2::{
  origo::WitnessData, CipherSuite, ClientConnection, Decrypter2, ProtocolVersion,
  RustCryptoBackend, RustCryptoBackend13, ServerName,
};
use tls_client_async2::bind_client;
use tls_core::msgs::{base::Payload, codec::Codec, enums::ContentType, message::OpaqueMessage};
use tracing::debug;
use url::Url;
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{config, config::ProvingData, errors, origo::SignBody, Proof};

pub async fn proxy_and_sign(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let (sb, witness) = proxy(config.clone(), session_id.clone()).await;

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb, &witness).await;

  let program_data = generate_program_data(&witness, config.proving).await;
  let program_output = program::run(&program_data);
  let compressed_verifier = program::compress_proof(&program_output, &program_data.public_params);
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();

  Ok(crate::Proof::Origo(serialized_compressed_verifier.0))
}

async fn generate_program_data(
  witness: &WitnessData,
  proving: ProvingData,
) -> ProgramData<Online, Expanded> {
  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: &[u8] = &witness.request.aes_key;
  let iv: &[u8] = &witness.request.aes_iv;

  let mut private_input = HashMap::new();

  let ct: &[u8] = witness.request.ciphertext.as_bytes();
  let sized_key: [u8; 16] = key[..16].try_into().unwrap();
  let sized_iv: [u8; 12] = iv[..12].try_into().unwrap();

  private_input.insert("key".to_string(), serde_json::to_value(&sized_key).unwrap());
  private_input.insert("iv".to_string(), serde_json::to_value(&sized_iv).unwrap());

  let dec = Decrypter2::new(sized_key, sized_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = dec
    .decrypt_tls13_aes(
      &OpaqueMessage {
        typ:     ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(hex::decode(ct).unwrap()),
      },
      0,
    )
    .unwrap();
  let pt = plaintext.payload.0.to_vec();
  let aad = hex::decode(meta.additional_data.to_owned()).unwrap();
  let mut padded_aad = vec![0; 16 - aad.len()];
  padded_aad.extend(aad);

  // this somehow needs to be nested in this hashmap of values to be under another key called
  // "fold_input" private_input.insert("plainText".to_string(),
  // serde_json::to_value(&pt).unwrap()); private_input.insert("aad".to_string(),
  // serde_json::to_value(&aad).unwrap());

  // TODO: Is padding the approach we want or change to support variable length?
  let janky_padding = if pt.len() % 16 != 0 { 16 - pt.len() % 16 } else { 0 };
  let mut janky_plaintext_padding = vec![0; janky_padding];
  let rom_len = (pt.len() + janky_padding) / 16;
  janky_plaintext_padding.extend(pt);

  let mut witnesses = Vec::new();
  for w in proving.witnesses {
    witnesses.push(load_witness_from_bin_reader(BufReader::new(Cursor::new(w.val))));
  }

  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(proving.r1cs), // TODO: Load more including extractors
    ],
    witness_generator_types: vec![WitnessGeneratorType::Browser],
    max_rom_length:          10,
  };

  let aes_instr = String::from("AES_GCM_1");
  let rom_data = HashMap::from([
    (aes_instr.clone(), CircuitData { opcode: 0 }),
    // TODO: Add more opcodes for extraction, determine how a web proof
    // chooses an extraction
  ]);

  let aes_rom_opcode_config = InstructionConfig {
    name:          aes_instr.clone(),
    private_input: HashMap::from([
      (String::from("key"), json!(sized_key)),
      (String::from("iv"), json!(sized_iv)),
      (String::from("aad"), json!(padded_aad)),
    ]),
  };

  let mut rom = vec![aes_rom_opcode_config; rom_len];
  let inputs = HashMap::from([(aes_instr.clone(), FoldInput {
    value: HashMap::from([(
      String::from("plainText"),
      janky_plaintext_padding.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
    )]),
  })]);

  let mut initial_input = vec![0; 23]; // default number of step_in.
  initial_input.extend(janky_plaintext_padding.iter());
  initial_input.resize(4160, 0); // TODO: This is currently the `TOTAL_BYTES` used in circuits
  let final_input: Vec<u64> = initial_input.into_iter().map(u64::from).collect();

  // TODO: Load this from a file. Run this in preprocessing step.
  let public_params = program::setup(&setup_data);

  return ProgramData::<Online, NotExpanded> {
    public_params,
    setup_data,
    rom,
    rom_data,
    initial_nivc_input: final_input.to_vec(),
    inputs,
    witnesses,
  }
  .into_expanded();
}

async fn proxy(config: config::Config, session_id: String) -> (SignBody, WitnessData) {
  // TODO build sanitized query
  let wss_url = format!(
    "wss://{}:{}/v1/origo?session_id={}&target_host={}&target_port={}",
    config.notary_host,
    config.notary_port,
    session_id.clone(),
    config.target_host(),
    config.target_port(),
  );

  let root_store = crate::tls::tls_client2_default_root_store();

  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let origo_conn = Arc::new(std::sync::Mutex::new(tls_client2::origo::OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
    tls_client2::ServerName::try_from(config.target_host().as_str()).unwrap(),
  )
  .unwrap();

  let (_, ws_stream) = WsMeta::connect(wss_url.to_string(), None).await.unwrap();

  let (mut client_tls_conn, tls_fut) = bind_client(ws_stream.into_io(), client);

  let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

  let (tls_sender, tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await;
    // Triggered when the server shuts the connection.
    let _ = tls_sender.send(result);
  };
  spawn_local(handled_tls_fut);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await.unwrap();

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  spawn_local(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()).await.unwrap();

  assert_eq!(response.status(), StatusCode::OK);

  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner();
  client_socket.close().await.unwrap();

  let server_aes_iv =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_key").unwrap().clone();

  let witness = origo_conn.lock().unwrap().to_witness_data();
  let sb = SignBody {
    hs_server_aes_iv:  hex::encode(server_aes_iv.to_vec()),
    hs_server_aes_key: hex::encode(server_aes_key.to_vec()),
  };

  (sb, witness)
}

use core::slice;
use std::{
  pin::Pin,
  task::{Context, Poll},
};

use pin_project_lite::pin_project;

pin_project! {
    #[derive(Debug)]
    pub(crate) struct FuturesIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> FuturesIo<T> {
  /// Create a new `FuturesIo` wrapping the given I/O object.
  ///
  /// # Safety
  ///
  /// This wrapper is only safe to use if the inner I/O object does not under
  /// any circumstance read from the buffer passed to `poll_read` in the
  /// `futures::AsyncRead` implementation.
  pub(crate) unsafe fn new(inner: T) -> Self { Self { inner } }

  pub(crate) fn into_inner(self) -> T { self.inner }
}

impl<T> hyper::rt::Write for FuturesIo<T>
where T: futures::AsyncWrite + Unpin
{
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_close(cx)
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write_vectored(cx, bufs)
  }
}

// Adapted from https://github.com/hyperium/hyper-util/blob/99b77a5a6f75f24bc0bcb4ca74b5f26a07b19c80/src/rt/tokio.rs
impl<T> hyper::rt::Read for FuturesIo<T>
where T: futures::AsyncRead + Unpin
{
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    mut buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    // Safety: buf_slice should only be written to, so it's safe to convert `&mut
    // [MaybeUninit<u8>]` to `&mut [u8]`.
    let buf_slice = unsafe {
      slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
    };

    let n = match futures::AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
      Poll::Ready(Ok(n)) => n,
      other => return other.map_ok(|_| ()),
    };

    unsafe {
      buf.advance(n);
    }
    Poll::Ready(Ok(()))
  }
}
