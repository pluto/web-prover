use std::{
  collections::HashMap,
  io::{BufReader, Cursor},
  path::{Path, PathBuf},
  sync::Arc,
};

use futures::{channel::oneshot, AsyncWriteExt};
use hyper::{body::Bytes, Request, StatusCode};
use num_bigint::BigInt;
use proofs::{
  circom::witness::load_witness_from_bin_reader,
  program::{
    self,
    data::{
      CircuitData, Expanded, FoldInput, InstructionConfig, NotExpanded, Offline, Online,
      ProgramData, R1CSType, SetupData, WitnessGeneratorType,
    },
  },
  witness::{compute_http_header_witness, compute_http_witness, compute_json_witness, data_hasher},
  G1,
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

use crate::{circuits::*, config, config::ProvingData, errors, origo::SignBody, Proof};

const JSON_MASK_KEY_DEPTH_1: (&str, [u8; 10]) = ("key", [100, 97, 116, 97, 0, 0, 0, 0, 0, 0]); // "data"
const JSON_MASK_KEYLEN_DEPTH_1: (&str, [u8; 1]) = ("keyLen", [4]);

pub async fn proxy_and_sign(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let (sb, witness) = proxy(config.clone(), session_id.clone()).await?;

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb, &witness).await;

  debug!("generating NIVC program data!");
  let program_data = generate_program_data(&witness, config.proving).await?;

  debug!("starting proof generation!");
  let program_output = program::run(&program_data)?;

  debug!("compressing proof!");
  let compressed_verifier = program::compress_proof(&program_output, &program_data.public_params)?;

  debug!("running compressed verifier!");
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();

  Ok(crate::Proof::Origo(serialized_compressed_verifier.0))
}

async fn generate_program_data(
  witness: &WitnessData,
  proving: ProvingData,
) -> Result<ProgramData<Online, Expanded>, errors::ClientErrors> {
  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: [u8; 16] = witness.request.aes_key[..16].try_into()?;
  let iv: [u8; 12] = witness.request.aes_iv[..12].try_into()?;

  // Get the request ciphertext, request plaintext, and AAD
  let request_ciphertext = hex::decode(witness.request.ciphertext.as_bytes())?;

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

  let mut witnesses = Vec::new();
  for w in proving.witnesses {
    witnesses.push(load_witness_from_bin_reader(BufReader::new(Cursor::new(w.val)))?);
  }

  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      // WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(HTTP_NIVC_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      // WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
      WitnessGeneratorType::Browser,
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };

  // TODO: Is padding the approach we want or change to support variable length?
  let padding = 512 - request_plaintext.len();
  let mut padded_request_plaintext = request_plaintext.clone();
  padded_request_plaintext.extend(vec![0; padding]);

  // NOTE (autoparallel): This removes the 16 + 1 extra bytes for authtag and tls inner content
  // type, then pads with 0.
  let mut padded_request_ciphertext =
    request_ciphertext[..request_plaintext.len()].to_vec().clone();
  padded_request_ciphertext.extend(vec![0; padding]);

  debug!("plaintext: {:?}", padded_request_plaintext);
  debug!("ciphertext: {:?}", padded_request_ciphertext);

  let (rom_data, rom, fold_input) = proving.manifest.unwrap().rom_from_request(
    &key,
    &iv,
    &padded_aad,
    &padded_request_plaintext,
    &padded_request_ciphertext,
  );

  debug!("generating public params");
  // let public_params = program::setup(&setup_data);

  let pd = ProgramData::<Offline, NotExpanded> {
    public_params: proving.serialized_pp,
    setup_data,
    rom,
    rom_data,
    initial_nivc_input: vec![proofs::F::<G1>::from(0)],
    inputs: fold_input,
    witnesses,
  }
  .into_online();

  // let pd = ProgramData::<Online, NotExpanded> {
  //   public_params,
  //   setup_data,
  //   rom,
  //   rom_data,
  //   initial_nivc_input: final_input.to_vec(),
  //   inputs,
  //   witnesses,
  // };

  debug!("online -> expanded");
  Ok(pd?.into_expanded()?)
}

async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<(SignBody, WitnessData), errors::ClientErrors> {
  // TODO build sanitized query
  let wss_url = format!(
    "wss://{}:{}/v1/origo?session_id={}&target_host={}&target_port={}",
    config.notary_host,
    config.notary_port,
    session_id.clone(),
    config.target_host()?,
    config.target_port()?,
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
    tls_client2::ServerName::try_from(config.target_host()?.as_str())?,
  )?;

  let (_, ws_stream) = WsMeta::connect(wss_url.to_string(), None).await?;

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
    hyper::client::conn::http1::handshake(client_tls_conn).await?;

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  spawn_local(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let mut client_socket = connection_receiver.await.unwrap()?.io.into_inner();
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

  Ok((sb, witness))
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
