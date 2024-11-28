use std::{
  io::{BufReader, Cursor},
  sync::Arc,
};

use futures::{channel::oneshot, AsyncWriteExt};
use hyper::StatusCode;
use proofs::{
  circom::witness::load_witness_from_bin_reader,
  program::{
    self,
    data::{
      Expanded, NotExpanded, Offline, Online, ProgramData, R1CSType, RawProvingParams, SetupData,
      WitnessGeneratorType,
    },
  },
  G1,
};
use serde_json::{json, Value};
use tls_client2::origo::WitnessData;
use tls_client_async2::bind_client;
use tracing::debug;
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{
  circuits::*, config, config::ProvingData, errors, origo::SignBody, tls::decrypt_tls_ciphertext,
  Proof,
};

pub async fn proxy_and_sign(
  mut config: config::Config,
  proving_params: Option<RawProvingParams>,
) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let (sb, witness) = proxy(config.clone(), session_id.clone()).await?;

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb, &witness).await;

  debug!("generating NIVC program data!");
  let program_data = generate_program_data(&witness, config.proving, proving_params).await?;

  debug!("starting proof generation!");
  let program_output = program::run(&program_data)?;

  debug!("compressing proof!");
  let compressed_verifier = program::compress_proof(&program_output, &program_data.public_params)?;

  debug!("running compressed verifier!");
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();

  Ok(crate::Proof::Origo((serialized_compressed_verifier.0, vec![])))
}
/// takes TLS transcripts and [`ProvingData`] and generates NIVC [`ProgramData`] for request and
/// response separately
/// - decrypts TLS ciphertext in [`WitnessData`]
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
async fn generate_program_data(
  witness: &WitnessData,
  proving: ProvingData,
  proving_params: Option<RawProvingParams>,
) -> Result<ProgramData<Online, Expanded>, errors::ClientErrors> {
  let (request_inputs, _response_inputs) = decrypt_tls_ciphertext(witness)?;

  let setup_data = construct_setup_data_512();
  let (request_rom_data, request_rom, request_fold_inputs) =
    proving.manifest.as_ref().unwrap().rom_from_request(request_inputs);

  // // pad AES response ciphertext
  // let (response_rom_data, response_rom, response_fold_inputs) =
  // proving.manifest.as_ref().unwrap().rom_from_response(response_inputs);

  // TODO: Unravel this insanity further.
  debug!("serializing witness objects");
  let mut witnesses = Vec::new();
  for w in proving.witnesses.unwrap() {
    witnesses.push(load_witness_from_bin_reader(BufReader::new(Cursor::new(w)))?);
  }

  debug!("initializing public params");
  let pd = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params.unwrap(),
    setup_data,
    rom: request_rom,
    rom_data: request_rom_data,
    initial_nivc_input: vec![proofs::F::<G1>::from(0)],
    inputs: request_fold_inputs,
    witnesses,
  }
  .into_online();

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
