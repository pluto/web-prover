use std::{
  clone,
  collections::HashMap,
  io::{BufReader, Cursor},
  ops::Deref,
  sync::Arc,
};

use futures::{channel::oneshot, AsyncWriteExt};
use hyper::StatusCode;
use proofs::{
  circom::witness::load_witness_from_bin_reader,
  program::{
    self,
    data::{Expanded, NotExpanded, Offline, Online, ProgramData},
    manifest::{EncryptionInput, NIVCRom, NivcCircuitInputs, TLSEncryption},
  },
  F, G1, G2,
};
use serde::{Deserialize, Serialize};
use tls_client2::{origo::WitnessData, CipherSuiteKey};
use tracing::{debug, info};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{
  circuits::*, config, config::ProvingData, errors, origo::SignBody, tls::decrypt_tls_ciphertext,
  tls_client_async2::bind_client, Proof,
};

// #[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Clone, Deserialize)]
pub struct WitnessInput {
  pub key:        Vec<u8>,
  pub iv:         Vec<u8>,
  pub aad:        Vec<u8>,
  pub plaintext:  Vec<u8>,
  pub ciphertext: Vec<u8>,
  pub headers:    HashMap<String, String>,
}

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
// #[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = witness, js_name = createWitness)]
  async fn create_witness_js(input: &JsValue) -> JsValue;
}

// #[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn create_witness(input: JsValue) -> Result<WitnessOutput, JsValue> {
  // Convert the Rust WitnessInput to a JsValue
  // let js_input = serde_wasm_bindgen::to_value(&input).unwrap();

  let js_witnesses_output = create_witness_js(&input).await;
  // Call JavaScript function and await the Promise
  info!("result: {:?}", js_witnesses_output);
  let js_obj = js_sys::Object::from(js_witnesses_output);
  info!("js_obj: {:?}", js_obj);
  let data_value = js_sys::Reflect::get(&js_obj, &JsValue::from_str("data"))?;
  info!("data_value: {:?}", data_value);
  let array = js_sys::Array::from(&data_value);
  info!("array: {:?}", array);
  let mut data = Vec::with_capacity(array.length() as usize);

  for i in 0..array.length() {
    let item = array.get(i);
    if let Ok(uint8_array) = item.dyn_into::<js_sys::Uint8Array>() {
      data.push(uint8_array);
    }
  }
  info!("data: {:?}", data);
  Ok(WitnessOutput { data })
}

pub async fn proxy_and_sign_and_generate_proof(
  mut config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<Proof, errors::ClientErrors> {
  let sesion_id = config.session_id;
  let mut origo_conn = proxy(config.clone(), session_id.clone()).await?;

  let sb = SignBody {
    handshake_server_iv:  hex::encode(
      origo_conn.secret_map.get("Handshake:server_iv").unwrap().clone().to_vec(),
    ),
    handshake_server_key: hex::encode(
      origo_conn.secret_map.get("Handshake:server_key").unwrap().clone().to_vec(),
    ),
  };

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb).await;

  debug!("generating program data!");
  let witness = origo_conn.to_witness_data();
  let program_data = generate_program_data(&witness, config.proving, proving_params).await?;

  debug!("starting proof generation!");
  let program_output = program::run(&program_data)?;

  debug!("compressing proof!");
  let compressed_snark_proof = program::compress_proof_no_setup(
    &program_output,
    &program_data.public_params,
    program_data.vk_digest_primary,
    program_data.vk_digest_secondary,
  )?;
  let proof = compressed_snark_proof.serialize();

  // TODO(sambhav): Add real response proving
  Ok(crate::Proof::Origo(OrigoProof { request_proof: Some(proof), response_proof: None }))
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
  proving_params: Option<Vec<u8>>,
) -> Result<ProgramData<Online, Expanded>, errors::ClientErrors> {
  let TLSEncryption { request: request_inputs, response: response_inputs } =
    decrypt_tls_ciphertext(witness)?;

  let request_setup_data = construct_setup_data();

  // - construct private inputs and program layout for circuits for TLS request -
  let NivcCircuitInputs {
    fold_inputs: request_fold_inputs,
    private_inputs: request_private_inputs,
    initial_nivc_input: request_initial_nivc_input,
  } = proving.manifest.as_ref().unwrap().request.build_inputs(&request_inputs);
  let NIVCRom { circuit_data: request_rom_data, rom: request_rom } =
    proving.manifest.as_ref().unwrap().request.build_rom();

  // // pad AES response ciphertext
  // let (response_rom_data, response_rom, response_fold_inputs) =
  // proving.manifest.as_ref().unwrap().rom_from_response(response_inputs);

  // TODO (tracy): Today we are carrying witness data on the proving object,
  // it's not obviously the right place for it. This code path needs a larger
  // refactor.

  // now we call the js FFI to generate the witness in wasm with snarkjs
  debug!("generating witness in wasm");
  // now we pass witness input type to generate program data
  let witnesses = build_witness_data_from_wasm(
    &request_inputs,
    proving.manifest.unwrap().request.headers.clone(),
  )
  .await?;

  debug!("initializing public params");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params.unwrap(),
    vk_digest_primary: proofs::F::<G1>::from(0),
    vk_digest_secondary: proofs::F::<G2>::from(0),
    setup_data: request_setup_data,
    rom: request_rom,
    rom_data: request_rom_data,
    initial_nivc_input: request_initial_nivc_input,
    inputs: (request_private_inputs, request_fold_inputs),
    witnesses,
  }
  .into_online();

  debug!("online -> expanded");
  Ok(program_data?.into_expanded()?)
}

async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<tls_client2::origo::OrigoConnection, errors::ClientErrors> {
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

  let origo_conn = origo_conn.lock().unwrap().deref().clone();
  Ok(origo_conn)
}

async fn build_witness_data_from_wasm(
  witness_data: &EncryptionInput,
  headers: HashMap<String, String>,
) -> Result<Vec<Vec<F<G1>>>, errors::ClientErrors> {
  let js_witness_input = to_js_witness_input(witness_data, headers);
  let js_witnesses_output = create_witness(js_witness_input).await.unwrap();
  debug!("js_witnesses_output: {:?}", js_witnesses_output);
  let js_computed_witnesses: Vec<Vec<u8>> =
    js_witnesses_output.data.iter().map(|w| w.to_vec()).collect();
  let mut witnesses = Vec::new();
  info!("js_computed_witnesses: {:?}", js_computed_witnesses);
  for w in js_computed_witnesses {
    witnesses.push(load_witness_from_bin_reader(BufReader::new(Cursor::new(w)))?);
  }
  // for wit in js_computed_witnesses {
  //   info!("loading witness from bytes {:?}",wit);
  //   witnesses.push(load_witness_from_bytes(wit)?);
  // }
  Ok(witnesses)
}

fn to_js_witness_input(witness: &EncryptionInput, headers: HashMap<String, String>) -> JsValue {
  let key_vec = match witness.key {
    CipherSuiteKey::CHACHA20POLY1305(key) => key.to_vec(),
    CipherSuiteKey::AES128GCM(key) => key.to_vec(),
  };
  let input = WitnessInput {
    key: key_vec,
    iv: witness.iv.to_vec(),
    aad: witness.aad.to_vec(),
    plaintext: witness.plaintext.clone(),
    ciphertext: witness.ciphertext.clone(),
    headers,
  };
  serde_wasm_bindgen::to_value(&input).unwrap()
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
