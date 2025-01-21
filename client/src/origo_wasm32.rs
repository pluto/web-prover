use core::slice;
use std::{
  collections::HashMap,
  io::{BufReader, Cursor},
  ops::Deref,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
};

use caratls::client::TeeTlsConnector;
use futures::{channel::oneshot, AsyncWriteExt};
use hyper::StatusCode;
use js_sys::Promise;
use proofs::{
  circom::witness::load_witness_from_bin_reader,
  program::{
    self,
    data::{Expanded, NotExpanded, Offline, Online, ProgramData},
    manifest::{
      EncryptionInput, JsonKey, NIVCRom, NivcCircuitInputs, Request as ManifestRequest,
      Response as ManifestResponse, TLSEncryption,
    },
  },
  F, G1, G2,
};
use serde::{Deserialize, Serialize};
use tls_client2::{origo::WitnessData, CipherSuiteKey};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{
  circuits::*,
  config,
  config::{NotaryMode, ProvingData},
  errors,
  origo::SignBody,
  tls::decrypt_tls_ciphertext,
  tls_client_async2::bind_client,
  OrigoProof,
};

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct WitnessOutput {
  pub data: Vec<js_sys::Uint8Array>,
}

#[wasm_bindgen]
impl WitnessOutput {
  #[wasm_bindgen(constructor)]
  pub fn new(wit: Vec<js_sys::Uint8Array>) -> WitnessOutput { Self { data: wit } }
}
// TODO(WJ 2024-12-12): move to wasm client lib?
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = witness, js_name = createWitness)]
  async fn create_witness_js(input: &JsValue, rom: &JsValue) -> JsValue;
}

// #[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_witness(input: JsValue, rom: JsValue) -> Result<WitnessOutput, JsValue> {
  // Convert the Rust WitnessInput to a JsValue
  let js_witnesses_output = create_witness_js(&input, &rom).await;

  // Call JavaScript function and await the Promise
  info!("result: {:?}", js_witnesses_output);
  let js_obj = js_sys::Object::from(js_witnesses_output);
  let data_value = js_sys::Reflect::get(&js_obj, &JsValue::from_str("data"))?;
  let array = js_sys::Array::from(&data_value);
  let mut data = Vec::with_capacity(array.length() as usize);

  for i in 0..array.length() {
    let item = array.get(i);
    if let Ok(uint8_array) = item.dyn_into::<js_sys::Uint8Array>() {
      data.push(uint8_array);
    }
  }
  debug!("data: {:?}", data);
  Ok(WitnessOutput { data })
}

pub async fn proxy_and_sign_and_generate_proof(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<OrigoProof, errors::ClientErrors> {
  let session_id = config.session_id.clone();
  let mut origo_conn = proxy(config.clone(), session_id.clone()).await?;

  let sb = SignBody {
    handshake_server_iv:  hex::encode(
      origo_conn.secret_map.get("Handshake:server_iv").unwrap().clone().to_vec(),
    ),
    handshake_server_key: hex::encode(
      origo_conn.secret_map.get("Handshake:server_key").unwrap().clone().to_vec(),
    ),
  };

  let _sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb).await;

  debug!("generating program data!");
  let witness = origo_conn.to_witness_data();

  // decrypt TLS ciphertext for request and response and create NIVC inputs
  let TLSEncryption { request: request_inputs, response: response_inputs } =
    decrypt_tls_ciphertext(&witness)?;

  // generate NIVC proofs for request and response
  let manifest = config.proving.manifest.unwrap();
  let request_proof = construct_request_program_data_and_proof(
    &manifest.request,
    request_inputs,
    proving_params.clone(),
  )
  .await?;

  let response_proof =
    construct_response_program_data_and_proof(&manifest.response, response_inputs, proving_params)
      .await?;

  // TODO(Sambhav): handle request and response into one proof
  Ok(OrigoProof { request: request_proof?, response: response_proof? })
}

/// creates NIVC proof from TLS transcript and [`Manifest`] config
///
/// # Arguments
/// - `manifest` - [`Manifest`] config containing proof and circuit information
/// - `inputs` - TLS transcript inputs
///
/// # Returns
/// - `CompressedSNARKProof` - NIVC proof
///
/// # Details
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
async fn construct_request_program_data_and_proof(
  manifest_request: &ManifestRequest,
  inputs: EncryptionInput,
  proving_params: Option<Vec<u8>>,
) -> Result<CompressedSNARKProof<Vec<u8>>, ClientErrors> {
  let setup_data = construct_setup_data();

  let NivcCircuitInputs { fold_inputs, private_inputs, initial_nivc_input } =
    manifest_request.build_inputs(&inputs);
  let NIVCRom { circuit_data, rom } = manifest_request.build_rom();
  let rom_opcodes = rom.iter().map(|c| circuit_data.get(c).unwrap().opcode).collect::<Vec<_>>();

  let mut wasm_private_inputs = private_inputs.clone();
  let initial_nivc_inputs =
    initial_nivc_input.iter().map(|&x| field_element_to_base10_string(x)).collect::<Vec<String>>();

  for (input, initial_input) in wasm_private_inputs.iter_mut().zip(initial_nivc_inputs.iter()) {
    input.insert("step_in".to_string(), json!(initial_input));
  }

  debug!("generating witness in wasm");
  // now we call the js FFI to generate the witness in wasm with snarkjs
  let witnesses = build_witness_data_from_wasm(wasm_private_inputs.clone(), rom_opcodes).await?;

  debug!("Generating request's `ProgramData`...");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params.unwrap(),
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: vec![initial_nivc_input[0]],
    inputs: (private_inputs, fold_inputs),
    witnesses,
  }
  .into_online()?;

  debug!("expanding program data");
  let program_data = program_data.into_expanded()?;

  debug!("starting request recursive proving");
  let proof = generate_proof(program_data)?;
  Ok(proof)
}

/// takes TLS transcripts and [`ProvingData`] and generates NIVC [`ProgramData`] for request and
/// response separately
/// - decrypts TLS ciphertext in [`WitnessData`]
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
async fn construct_response_program_data_and_proof(
  manifest_response: &ManifestResponse,
  inputs: EncryptionInput,
  proving_params: Option<Vec<u8>>,
) -> Result<CompressedSNARKProof<Vec<u8>>, ClientErrors> {
  let setup_data = construct_setup_data();

  // - construct private inputs and program layout for circuits for TLS request -
  let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
    manifest_response.build_inputs(&inputs)?;
  let NIVCRom { circuit_data, rom } = manifest_response.build_rom(inputs.plaintext.len());
  let rom_opcodes = rom.iter().map(|c| circuit_data.get(c).unwrap().opcode).collect::<Vec<_>>();

  // TODO (tracy): Today we are carrying witness data on the proving object,
  // it's not obviously the right place for it. This code path needs a larger
  // refactor.
  let mut wasm_private_inputs = private_inputs.clone();
  let initial_nivc_inputs =
    initial_nivc_input.iter().map(|&x| field_element_to_base10_string(x)).collect::<Vec<String>>();

  for (input, initial_input) in wasm_private_inputs.iter_mut().zip(initial_nivc_inputs.iter()) {
    input.insert("step_in".to_string(), json!(initial_input));
  }

  // now we call the js FFI to generate the witness in wasm with snarkjs
  debug!("generating witness in wasm");

  // now we pass witness input type to generate program data
  let witnesses = build_witness_data_from_wasm(wasm_private_inputs, rom_opcodes).await?;

  debug!("initializing public params");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params.unwrap(),
    vk_digest_primary: proofs::F::<G1>::from(0),
    vk_digest_secondary: proofs::F::<G2>::from(0),
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: vec![initial_nivc_input[0]],
    inputs: (private_inputs, fold_inputs),
    witnesses,
  }
  .into_online()?;

  debug!("expanding program data");
  let program_data = program_data.into_expanded()?;

  debug!("starting response recursive proving");
  let proof = generate_proof(program_data)?;

  Ok(proof)
}

/// generates NIVC proof from [`ProgramData`]
/// - run NIVC recursive proving
/// - run CompressedSNARK to compress proof
/// - serialize proof
fn generate_proof(
  program_data: ProgramData<Online, Expanded>,
) -> Result<CompressedSNARKProof<Vec<u8>>, ClientErrors> {
  let program_output = program::run(&program_data)?;
  debug!("compressing proof!");
  let compressed_snark_proof = program::compress_proof_no_setup(
    &program_output,
    &program_data.public_params,
    program_data.vk_digest_primary,
    program_data.vk_digest_secondary,
  )?;
  debug!("serialize");
  Ok(compressed_snark_proof.serialize())
}

pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<tls_client2::origo::OrigoConnection, errors::ClientErrors> {
  // TODO build sanitized query
  let wss_url = format!(
    "wss://{}:{}/v1/{}?session_id={}&target_host={}&target_port={}",
    config.notary_host,
    config.notary_port,
    if config.mode == NotaryMode::TEE { "tee" } else { "origo" },
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

  // Either bind client to TEE TLS connection or plain websocket connection
  let (mut client_tls_conn, tls_fut) = if config.mode == NotaryMode::TEE {
    let tee_tls_connector = TeeTlsConnector::new("example.com"); // TODO example.com
    let tee_tls_stream = tee_tls_connector.connect(ws_stream.into_io()).await?;
    bind_client(tee_tls_stream.compat(), client)
  } else {
    bind_client(ws_stream.into_io(), client)
  };

  let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

  let (tls_sender, _tls_receiver) = oneshot::channel();
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

  let origo_conn = origo_conn.lock().unwrap().deref().clone();
  Ok(origo_conn)
}

async fn build_witness_data_from_wasm(
  private_inputs: Vec<HashMap<String, Value>>,
  rom_opcodes: Vec<u64>,
) -> Result<Vec<Vec<F<G1>>>, errors::ClientErrors> {
  let js_witness_input = serde_wasm_bindgen::to_value(&private_inputs).unwrap();
  let js_witness_rom = serde_wasm_bindgen::to_value(&rom_opcodes).unwrap();

  // debug!("js_witness_input: {:?}, rom: {:?}", js_witness_input, js_witness_rom);
  let js_witnesses_output = create_witness(js_witness_input, js_witness_rom).await.unwrap();
  // debug!("js_witnesses_output: {:?}", js_witnesses_output);
  let js_computed_witnesses: Vec<Vec<u8>> =
    js_witnesses_output.data.iter().map(|w| w.to_vec()).collect();
  let mut witnesses = Vec::new();
  for w in js_computed_witnesses {
    witnesses.push(load_witness_from_bin_reader(BufReader::new(Cursor::new(w)))?);
  }

  Ok(witnesses)
}

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
