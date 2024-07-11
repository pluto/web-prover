// This is where we will merge in the client code

#[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
use std::{
  ffi::{CStr, CString},
  os::raw::c_char,
};

use base64::prelude::*;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use notary;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use url::Url;
#[cfg(target_arch = "wasm32")]
use {
  crate::wasm_utils::WasmAsyncIo as AsyncIo, futures::channel::oneshot, wasm_bindgen::prelude::*,
  wasm_bindgen_futures::spawn_local, ws_stream_wasm::*,
  std::panic,
};
#[cfg(not(target_arch = "wasm32"))]
use {
  hyper_util::rt::TokioIo as AsyncIo, // TokioIo is used for TLS connection in the iOS version

  tokio::{net::TcpStream, spawn},
  tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
};

use super::*;

#[cfg(test)] mod tests;

#[derive(Serialize, Clone)]
#[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
struct Output {
  proof: Option<String>,
  error: Option<String>,
}

#[cfg(all(not(target_arch = "wasm32"), not(target_os = "ios")))]
pub fn prover(config: Config) -> Result<TlsProof, ClientErrors> {
  #[cfg(feature = "tracing")]
  {
    let collector = tracing_subscriber::fmt().with_max_level(Level::TRACE).finish();
    subscriber::set_global_default(collector).unwrap();
  }
  let rt = tokio::runtime::Runtime::new().unwrap();
  rt.block_on(prover_inner(config))
}

#[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
#[no_mangle]
// TODO: We should probably clarify this safety doc
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn prover(config_json: *const c_char) -> *const c_char {
  #[cfg(feature = "tracing")]
  {
    let collector = tracing_subscriber::fmt().with_max_level(Level::TRACE).finish();
    subscriber::set_global_default(collector).map_err(|e| panic!("{e:?}")).unwrap();
  }

  let result: Result<TlsProof, ClientErrors> =
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let config_str = unsafe {
        assert!(!config_json.is_null());
        CStr::from_ptr(config_json).to_str().map_err(ClientErrors::from)
      };
      let config: Config = serde_json::from_str(config_str?)?;
      let rt = tokio::runtime::Runtime::new()?;
      rt.block_on(prover_inner(config))
    }))
    .map_err(|e| panic!("{e:?}"))
    .unwrap();
  let proof = result
    .map_err(|e| {
      let backtrace = std::backtrace::Backtrace::capture();
      panic!(
        "Error:{e:?}/n
  Stack:{backtrace:?}"
      )
    })
    .unwrap();
  CString::new(
    serde_json::to_string_pretty(&Output {
      proof: Some(serde_json::to_string_pretty(&proof).unwrap()),
      error: None,
    })
    .map_err(|e| panic!("{e:?}"))
    .unwrap(),
  )
  .map_err(|e| panic!("{e:?}"))
  .unwrap()
  .into_raw()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn prover(config: *mut Config) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));
  #[cfg(feature = "tracing")]
  panic::set_hook(Box::new(|info| {
    // error!("panic occurred: {:?}", info);
    console_error_panic_hook::hook(info);
  }));
  let config: Config = unsafe { (*config).clone() };
  let proof = prover_inner(config)
    .await
    .map_err(|e| JsValue::from_str(&format!("Could not produce proof: {:?}", e)))?;
  serde_json::to_string_pretty(&proof)
    .map_err(|e| JsValue::from_str(&format!("Could not serialize proof: {:?}", e)))
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip(config)))]
async fn prover_inner(config: Config) -> Result<TlsProof, ClientErrors> {
  #[cfg(feature = "tracing")]
  info!("client entered `prover_inner` to construct webproof");
  #[cfg(feature = "tracing")]
  trace!("{config:#?}");
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Parse the target url -> Check that it is HTTPS -> Extract the port being used
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "parse_target_url").entered();
  let target_url = Url::parse(&config.target_url)?;
  #[cfg(feature = "tracing")]
  trace!("parsed `target_url`: {target_url:?}");
  // TODO: These three lines with target_url should probably throw a well-defined error instead of
  // causing panic.
  let target_host = target_url.host_str().expect("Invalid `target_url` host!");
  assert!(target_url.scheme() == "https");
  #[cfg(feature = "tracing")]
  debug!("parsed `target_host`: {target_host:?}; IS HTTPS!");
  // Only returns none if no port or known protocol used
  #[cfg(any(not(feature = "websocket"), not(target_arch = "wasm32")))]
  let target_port = target_url.port_or_known_default().expect("Target has an unknown port!");
  #[cfg(feature = "tracing")]
  // debug!("parsed `target_port`: {target_port:?}");
  #[cfg(feature = "tracing")]
  info!("target connection data built");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // TODO: The following should be made modular in that we don't want to enforce we are going to
  // notary approach
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Create a notary session and get back a `NetworkStream` and the session ID
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "connect_to_notary").entered();
  let (notary_tls_socket, session_id) = notary::request_notarization(
    &config.notary_host,
    config.notary_port,
    &config.notarization_session_request,
    &config.notary_ca_cert_path,
  )
  .await?;
  #[cfg(feature = "tracing")]
  info!("connected to notary with session id: {session_id:?}");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Set up the prover which lies on the client and can access the notary for MPC
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "create_prover").entered();
  let prover_config = ProverConfig::builder().id(session_id).server_dns(target_host).build()?;

  // Create a new prover and with MPC backend.
  #[cfg(not(target_arch = "wasm32"))]
  let prover = Prover::new(prover_config).setup(notary_tls_socket.compat()).await?;
  #[cfg(target_arch = "wasm32")]
  let prover = Prover::new(prover_config).setup(notary_tls_socket.into_io()).await?;
  #[cfg(feature = "tracing")]
  trace!("{prover:?}");
  #[cfg(feature = "tracing")]
  info!("prover created");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // TODO: This is where we have to consider using another mode of connection like ws
  // connect to target
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Connect the client to the target via TLS and maintain it concurrently
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // TODO: This will likely not compile without websocket feature  on wasm since this is a tokio
  // tcpstream. ALSO, this does noit actually provide a websocket feature for non-wasm.
  //
  // Bind the Prover to server connection
  #[cfg(any(not(feature = "websocket"), not(target_arch = "wasm32")))]
  let (client_target_tls, prover_fut) = {
    let client_target_socket = TcpStream::connect((target_host, target_port)).await?;
    prover.connect(client_target_socket.compat()).await?
  };
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let ws_query = url::form_urlencoded::Serializer::new(String::new())
    .extend_pairs([("target", target_host)])
    .finish();
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let (client_target_tls, prover_fut) = {
    let (_ws_meta, ws_stream) =
      WsMeta::connect(format!("{}?{}", config.websocket_proxy_url, ws_query), None).await?;
    let client_target_socket = ws_stream.into_io();
    prover.connect(client_target_socket).await?
  };

  #[cfg(any(not(feature = "websocket"), not(target_arch = "wasm32")))]
  let client_target_tls = AsyncIo::new(client_target_tls.compat());
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let client_target_tls = AsyncIo::new(client_target_tls);

  // Grab a control handle to the Prover
  let prover_ctrl = prover_fut.control();

  // Spawn the Prover to be run concurrently
  #[cfg(not(target_arch = "wasm32"))]
  let prover_task = spawn(prover_fut);

  #[cfg(target_arch = "wasm32")]
  let prover_task = {
    let (tx, rx) = oneshot::channel();
    let prover_fut = async {
      let result = prover_fut.await;
      tx.send(result).expect("Failed to send result out of prover task channel!");
    };
    spawn_local(prover_fut);
    rx
  };

  // Attach the hyper HTTP client to the TLS connection
  let (mut request_sender, client_target_tls_connection) =
    hyper::client::conn::http1::handshake(client_target_tls).await?;

  // Spawn the HTTP task to be run concurrently
  #[cfg(not(target_arch = "wasm32"))]
  let _client_target_tls_connection_task = spawn(client_target_tls_connection);
  #[cfg(target_arch = "wasm32")]
  let _client_target_tls_connection_task = {
    let client_target_tls_connection = async {
      client_target_tls_connection.await.unwrap();
    };
    spawn_local(client_target_tls_connection);
  };
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Build the HTTP request asking the target for some data
  //---------------------------------------------------------------------------------------------------------------------------------------//
  let mut request = Request::builder().method(config.target_method.as_str()).uri(config.target_url);

  // The following `unwrap()` should be safe since we just created the `Request` above
  let headers = request.headers_mut().unwrap();
  // TODO: This could be a source of error as the mapping now just holds a single string, so I will
  // leave commented out code here.
  for (key, value) in config.target_headers {
    //   for (key, values) in config.target_headers {
    // for value in values {
    //   headers.append(
    //     hyper::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
    //     value.parse().unwrap(),
    //   );
    // }
    headers.append(hyper::header::HeaderName::from_bytes(key.as_bytes())?, value.parse()?);
  }

  headers.insert("Host", target_host.parse()?);
  // Using "identity" instructs the Server not to use compression for its HTTP response.
  // TLSNotary tooling does not support compression.
  headers.insert("Accept-Encoding", "identity".parse()?);
  headers.insert("Connection", "close".parse()?);

  if headers.get("Accept").is_none() {
    headers.insert("Accept", "*/*".parse()?);
  }

  let body = if config.target_body.is_empty() {
    Full::new(Bytes::from(vec![])) // TODO Empty::<Bytes>::new()
  } else {
    Full::new(Bytes::from(BASE64_STANDARD.decode(config.target_body)?))
  };

  let request = request.body(body)?;
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Send the HTTP request from the client to the target
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  debug!("Sending request");

  // Because we don't need to decrypt the response right away, we can defer decryption
  // until after the connection is closed. This will speed up the proving process!
  prover_ctrl.defer_decryption().await?;

  // TODO: Clean up this logging and error handling
  match request_sender.send_request(request).await {
    Ok(response) => {
      let is_success = response.status().is_success();
      let _payload = response.into_body();
      #[cfg(feature = "tracing")]
      debug!("Response:\n{:?}", _payload);

      assert!(is_success); // status is 200-299
      #[cfg(feature = "tracing")]
      debug!("Request OK");
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO */
    Err(e) => panic!("{:?}", e),
  };

  #[cfg(feature = "tracing")]
  debug!("Sent request");
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Complete the prover and notarization
  //---------------------------------------------------------------------------------------------------------------------------------------//
  let prover = prover_task.await??;

  // Upgrade the prover to an HTTP prover, and start notarization.
  let mut prover = prover.to_http()?.start_notarize();

  // TODO: unwrap for now as we need to bring in `tlsn_formats`
  // Commit to the transcript with the default committer, which will commit using BLAKE3.
  prover.commit().unwrap();

  // Finalize, returning the notarized HTTP session
  let notarized_session = prover.finalize().await?;

  #[cfg(feature = "tracing")]
  debug!("Notarization complete!");
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // TODO: This is where selective disclosure happens, we should modularize this and verify its
  // correctness
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Restructure the proof and return it
  //---------------------------------------------------------------------------------------------------------------------------------------//
  let session_proof = notarized_session.session_proof();

  let mut proof_builder = notarized_session.session().data().build_substrings_proof();

  // Prove the request, while redacting the secrets from it.
  let request = &notarized_session.transcript().requests[0];

  proof_builder.reveal_sent(&request.without_data(), CommitmentKind::Blake3)?;

  proof_builder.reveal_sent(&request.request.target, CommitmentKind::Blake3)?;

  for header in &request.headers {
    // Only reveal the host header
    if header.name.as_str().eq_ignore_ascii_case("Host") {
      proof_builder.reveal_sent(header, CommitmentKind::Blake3)?;
    } else {
      proof_builder.reveal_sent(&header.without_value(), CommitmentKind::Blake3)?;
    }
  }

  // Prove the entire response, as we don't need to redact anything
  let response = &notarized_session.transcript().responses[0];

  proof_builder.reveal_recv(response, CommitmentKind::Blake3)?;

  // Build the proof
  let substrings_proof = proof_builder.build()?;

  Ok(TlsProof { session: session_proof, substrings: substrings_proof })
  //---------------------------------------------------------------------------------------------------------------------------------------//
}
