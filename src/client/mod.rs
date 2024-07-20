use std::panic;
#[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
use std::{
  ffi::{CStr, CString},
  os::raw::c_char,
};

use base64::prelude::*;
#[cfg(target_arch = "wasm32")]
use gloo_utils::format::JsValueSerdeExt;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
#[cfg(feature = "tracing")] use tracing::error;
use url::Url;
#[cfg(target_arch = "wasm32")]
use {
  crate::wasm_utils::WasmAsyncIo as AsyncIo, futures::channel::oneshot, wasm_bindgen::prelude::*,
  wasm_bindgen_futures::spawn_local, ws_stream_wasm::*,
};
#[cfg(not(target_arch = "wasm32"))]
use {
  hyper_util::rt::TokioIo as AsyncIo, // TokioIo is used for TLS connection in the iOS version

  tokio::{net::TcpStream, spawn},
  tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
};

use super::*;

#[cfg(test)] mod tests;

const NOTARY_CA_CERT: &[u8] = include_bytes!("../../tests/fixture/certs/ca-cert.cer"); // TODO make build config

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
pub async fn prover(config: JsValue) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));
  #[cfg(feature = "tracing")]
  panic::set_hook(Box::new(|info| {
    error!("panic occurred: {:?}", info);
    console_error_panic_hook::hook(info);
  }));
  let config: Config = config.into_serde().unwrap(); // TODO replace unwrap
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
  let target_port = target_url.port_or_known_default().expect("Target has an unknown port!");
  // #[cfg(feature = "tracing")]
  // debug!("parsed `target_port`: {target_port:?}"); // TODO target_port does not exist, fix
  // feature flags
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

  let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
  let mut root_store = tls_client::RootCertStore::empty();
  let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
  assert_eq!(added, 1); // TODO there is probably a better way

  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "create_prover").entered();
  let mut prover_config = ProverConfig::builder();
  prover_config.id(session_id).server_dns(target_host).root_cert_store(root_store);

  if let Some(max_sent_data) = config.notarization_session_request.max_sent_data {
    prover_config.max_sent_data(max_sent_data);
  }
  if let Some(max_recv_data) = config.notarization_session_request.max_recv_data {
    prover_config.max_recv_data(max_recv_data);
  }

  let prover_config = prover_config.build().unwrap();

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
  let (mpc_tls_connection, prover_fut) = {
    let client_target_socket = TcpStream::connect((target_host, target_port)).await?;
    prover.connect(client_target_socket.compat()).await?
  };
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let ws_query = url::form_urlencoded::Serializer::new(String::new())
    .extend_pairs([("target", format!("{}:{}", target_host, target_port))])
    .finish();
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let (mpc_tls_connection, prover_fut) = {
    let (_, ws_stream) =
      WsMeta::connect(format!("{}?{}", config.websocket_proxy_url, ws_query), None).await?;
    let client_target_socket = ws_stream.into_io();
    prover.connect(client_target_socket).await?
  };

  // mpc_tls_connection is mpc_tls_connection (in working code)

  #[cfg(any(not(feature = "websocket"), not(target_arch = "wasm32")))]
  let mpc_tls_connection = AsyncIo::new(mpc_tls_connection.compat());
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let mpc_tls_connection = AsyncIo::new(mpc_tls_connection);

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
  let (mut request_sender, mpc_tls_connection) =
    hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

  // Spawn the HTTP task to be run concurrently
  #[cfg(not(target_arch = "wasm32"))]
  let _mpc_tls_connection_task = spawn(mpc_tls_connection);

  // let (connection_sender, connection_receiver) = oneshot::channel();
  // let connection_fut = mpc_tls_connection.without_shutdown();
  // let handled_connection_fut = async {
  //   let result = connection_fut.await;
  //   let _ = connection_sender.send(result);
  // };
  // spawn_local(handled_connection_fut);
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
  // use futures::AsyncWriteExt;
  // let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner();
  // client_socket.close().await.unwrap();

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Complete the prover and notarization
  //---------------------------------------------------------------------------------------------------------------------------------------//
  let prover = prover_task.await.unwrap().unwrap(); // TODO fix unwrap

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

// use std::io::{BufReader, Cursor};

use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::{body::Bytes, Request, StatusCode};
// use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
#[cfg(target_arch = "wasm32")]
use {
  wasm_bindgen_futures::spawn_local, wasm_utils::WasmAsyncIo as AsyncIo, ws_stream_wasm::WsMeta,
};
#[cfg(target_arch = "wasm32")]
type NetworkStream = ws_stream_wasm::WsStream;
#[cfg(not(target_arch = "wasm32"))]
use {
  hyper::client::conn::http1::Parts,
  hyper_util::rt::TokioIo as AsyncIo,
  std::sync::Arc,
  tokio::net::TcpStream,
  tokio::spawn,
  tokio_rustls::{client::TlsStream, TlsConnector},
};
#[cfg(not(target_arch = "wasm32"))]
type NetworkStream = TlsStream<TcpStream>;

use super::*;

// TODO: The `ClientType` and  `NotarizationSessionRequest` and `NotarizationSessionResponse` is
// redundant with what we had in `request` for the wasm version which was deprecated. May have to be
// careful with the camelCase used here.

/// Requests notarization from the Notary server.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip_all))]
pub async fn request_notarization(
  notary_host: &str,
  notary_port: u16,
  config_notarization_session_request: &ConfigNotarizationSessionRequest,
) -> Result<(NetworkStream, String), ClientErrors> {
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Configure TLS Notary session and get session id
  //---------------------------------------------------------------------------------------------------------------------------------------//
  todo!("todo");
  // TODO the following applies to WASM only, make it work with non wasm as well

  // #[cfg(feature = "tracing")]
  // let _span = tracing::span!(tracing::Level::TRACE, "configure_tls_notary_session").entered();
  // let mut opts = web_sys::RequestInit::new();
  // opts.method("POST");
  // opts.mode(web_sys::RequestMode::Cors);

  // let headers = web_sys::Headers::new().unwrap(); // TODO fix unwrap
  // headers.append("Host", notary_host).unwrap(); // TODO fix unwrap
  // headers.append("Content-Type", "application/json").unwrap(); // TODO fix unwrap
  // opts.headers(&headers);

  // let notarization_session_request = NotarizationSessionRequest {
  //   client_type:   config_notarization_session_request.client_type,
  //   max_sent_data: config_notarization_session_request.max_sent_data,
  //   max_recv_data: config_notarization_session_request.max_recv_data,
  // };

  // let payload = serde_json::to_string(&notarization_session_request).unwrap(); // TODO fix unwrap
  // opts.body(Some(&wasm_bindgen::JsValue::from_str(&payload)));

  // let url = format!("https://{}:{}/session", notary_host, notary_port);

  // let raw_notarization_session_response =
  //   wasm_utils::fetch_as_json_string(&url, &opts).await.unwrap(); // TODO fix unwrap
  // let notarization_response =
  //   serde_json::from_str::<NotarizationSessionResponse>(&raw_notarization_session_response)
  //     .unwrap(); // TODO fix unwrap
  // #[cfg(feature = "tracing")]
  // info!("Session configured, session_id: {}", notarization_response.session_id);
  // #[cfg(feature = "tracing")]
  // drop(_span);

  // // TODO: Be careful to put this in with the right target arch
  // #[cfg(feature = "tracing")]
  // debug!("TLS socket created with TCP connection");
  // let (_, notary_tls_socket) = WsMeta::connect(
  //   format!(
  //     "wss://{}:{}/notarize?sessionId={}",
  //     notary_host, notary_port, notarization_response.session_id
  //   ),
  //   None,
  // )
  // .await?;
  // //---------------------------------------------------------------------------------------------------------------------------------------//

  // // Claim back the TLS socket after HTTP exchange is done
  // // #[cfg(not(target_arch = "wasm32"))]
  // // let Parts { io: notary_tls_socket, .. } = connection_task.await??;
  // #[cfg(not(target_arch = "wasm32"))]
  // return Ok((notary_tls_socket.into_inner(), notarization_response.session_id.to_string()));
  // #[cfg(target_arch = "wasm32")]
  // return Ok((notary_tls_socket, notarization_response.session_id.to_string()));
}


// TODO proxy client:
// use std::panic;

// use url::Url;
// use wasm_bindgen::prelude::*;
// use ws_stream_wasm::WsMeta;
// pub(crate) mod hyper_io;
// macro_rules! console_log {
//     ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
// }

// #[wasm_bindgen]
// pub async fn connect(
//     proxy_url: String,
//     target_host: String,
//     target_port: u16,
// ) -> Result<JsValue, JsValue> {
//     // https://github.com/rustwasm/console_error_panic_hook
//     panic::set_hook(Box::new(console_error_panic_hook::hook));

//     console_log!(
//         "Connecting to {}:{} via proxy {}",
//         target_host,
//         target_port,
//         proxy_url
//     );

//     let mut url = Url::parse(&proxy_url)
//         .map_err(|e| JsValue::from_str(&format!("Could not parse proxy_url: {:?}", e)))?;

//     // TODO check url.scheme() == wss or ws

//     url.query_pairs_mut()
//         .append_pair("target_host", &target_host);
//     url.query_pairs_mut()
//         .append_pair("target_port", &target_port.to_string());

//     // // TODO simple ping/pong example
//     // console_log!("ping sent");
//     // stream.write_all(b"ping").await.unwrap();

//     // let mut buf = [0; 4]; // store pong
//     // stream.read_exact(&mut buf).await.unwrap();
//     // console_log!("Received: {}", String::from_utf8_lossy(&buf));

//     use std::sync::Arc;

//     use futures::{channel::oneshot, AsyncWriteExt};
//     use http_body_util::{BodyExt, Full};
//     use hyper::{body::Bytes, Request, StatusCode};
//     use pki_types::CertificateDer;
//     use tls_client::{ClientConnection, RustCryptoBackend, ServerName};
//     use tls_client_async::bind_client;
//     use wasm_bindgen_futures::spawn_local;

//     use crate::hyper_io::FuturesIo;

//     // === 1. Setup a websocket
//     let (_, ws_stream) = WsMeta::connect(url.to_string(), None)
//         .await
//         .map_err(|e| JsValue::from_str(&format!("Could not connect to proxy: {:?}", e)))?;

//     // === 2.  Setup a TLS Connection
//     let target = format!("https://{}:{}", target_host, target_port);
//     let target_url = Url::parse(&target)
//         .map_err(|e| JsValue::from_str(&format!("Could not parse target_url: {:?}", e)))?;

//     console_log!("target_url: {:?}", target_url);
//     console_log!("target_url: {:?}", target_url.host_str());

//     let target_host = target_url
//         .host_str()
//         .ok_or(JsValue::from_str("Could not get target host"))?;

//     let mut root_store = tls_client::RootCertStore::empty();
//     root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
//         tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
//             ta.subject.as_ref(),
//             ta.subject_public_key_info.as_ref(),
//             ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
//         )
//     }));

//     const LOCALHOST_DEBUG_CA_CERT: &[u8] = include_bytes!("../../src/fixture/mock_server/ca-cert.cer");
//     let cert = CertificateDer::from(LOCALHOST_DEBUG_CA_CERT.to_vec());
//     let (added, _) = root_store.add_parsable_certificates(&[cert.to_vec()]);
//     assert_eq!(added, 1);

//     let config = tls_client::ClientConfig::builder()
//         .with_safe_defaults()
//         .with_root_certificates(root_store)
//         .with_no_client_auth();

//     let client = ClientConnection::new(
//         Arc::new(config),
//         Box::new(RustCryptoBackend::new()),
//         ServerName::try_from(target_host).unwrap(),
//     )
//     .unwrap();
//     let (client_tls_conn, tls_fut) = bind_client(ws_stream.into_io(), client);

//     // TODO: Is this really needed?
//     let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

//     // TODO: What do with tls_fut? what do with tls_receiver?
//     let (tls_sender, _tls_receiver) = oneshot::channel();
//     let handled_tls_fut = async {
//         let result = tls_fut.await;
//         // Triggered when the server shuts the connection.
//         console_log!("tls_sender.send({:?})", result);
//         let _ = tls_sender.send(result);
//     };
//     spawn_local(handled_tls_fut);

//     // === 3. Do HTTP over the TLS Connection
//     let (mut request_sender, connection) = hyper::client::conn::http1::handshake(client_tls_conn)
//         .await
//         .map_err(|e| JsValue::from_str(&format!("Could not handshake: {:?}", e)))?;

//     let (connection_sender, connection_receiver) = oneshot::channel();
//     let connection_fut = connection.without_shutdown();
//     let handled_connection_fut = async {
//         let result = connection_fut.await;
//         console_log!("connection_sender.send({:?})", result);
//         let _ = connection_sender.send(result);
//     };
//     spawn_local(handled_connection_fut);

//     let req_with_header = Request::builder()
//         .uri(target_url.to_string())
//         .method("POST"); // TODO: test

//     console_log!("empty body");
//     let unwrapped_request = req_with_header
//         .body(Full::new(Bytes::default()))
//         .map_err(|e| JsValue::from_str(&format!("Could not build request: {:?}", e)))?;

//     // Send the request to the Server and get a response via the TLS connection
//     let response = request_sender
//         .send_request(unwrapped_request)
//         .await
//         .map_err(|e| JsValue::from_str(&format!("Could not send request: {:?}", e)))?;

//     if response.status() != StatusCode::OK {
//         return Err(JsValue::from_str(&format!(
//             "Response status is not OK: {:?}",
//             response.status()
//         )));
//     }

//     let payload = response
//         .into_body()
//         .collect()
//         .await
//         .map_err(|e| JsValue::from_str(&format!("Could not get response body: {:?}", e)))?
//         .to_bytes();

//     console_log!("Response: {:?}", payload);

//     // Close the connection to the server
//     let mut client_socket = connection_receiver
//         .await
//         .map_err(|e| {
//             JsValue::from_str(&format!(
//                 "Could not receive from connection_receiver: {:?}",
//                 e
//             ))
//         })?
//         .map_err(|e| JsValue::from_str(&format!("Could not get TlsConnection: {:?}", e)))?
//         .io
//         .into_inner();

//     client_socket
//         .close()
//         .await
//         .map_err(|e| JsValue::from_str(&format!("Could not close socket: {:?}", e)))?;
//     console_log!("closed client_socket");

//     Ok("".into()) // TODO
// }

// #[wasm_bindgen]
// extern "C" {
//     #[wasm_bindgen(js_namespace = console)]
//     fn log(s: &str);

//     #[wasm_bindgen(js_namespace = console)]
//     fn warn(s: &str);
// }

// // == NOTES on Origo Approach
// //
// // Handshake Setup
// // - Need to verify the cert chain
// // - Reveal the Server Handshake Traffic Secret to the proxy
// // - Using this, proxy derives the SHTK to decrypt the handshake
// // - Now that handshake is decrypted, verify certificate chain (out of circuit)

// // Client Side Proof
// // - Prove that the client derived the handshake key in a predictable manner
// // - i.e. the symmetric key is "proven" to be the mix of predictable local
// //   randomness
// // - compute "h7" => H(ClientHello||...||ServerCertVerify)
// // - compute "h2" => H(ClientHello||ServerHello)

// // In-circuit Verification (key derivation)
// // Goal: Prove that keys are derived legitimately
// //
// // Witness (HS, H2, H3, SHTS)
// // SHTS <= HKDF.expand (HS,“s hs traffic” || H2)
// // dhs <= HKDF.expand (HS,“derived”, H(“ ”))
// // MS ← HKDF.extract (dHS, 0)
// // CATS ← HKDF.expand (MS, “c ap traffic” || H3)
// // SATS ← HKDF.expand (MS, “s ap traffic” || H3)
// // CATK ← DeriveTK(CATS)
// // SATK ← DeriveTK(SATS)

// // Notes:
// // h7, h2, h3, h0 => all computed by the proxy
// // only private key must be hashed in circuit  (because proxy can check the
// // rest)
// //

// // Out-of-circuit Verification
// //
// // Witness SHTS, H7, SF
// // Fk <= HKDF expand (shts, finished) => TODO: What is this algorithm
// // SF' <= HMAC (Fk, H7)
// // SF1 == SF
// // ok =? verifyCertificate()