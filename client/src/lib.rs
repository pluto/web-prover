pub mod errors;

#[cfg(target_arch = "wasm32")] mod wasm_utils;

use std::collections::HashMap;

use base64::prelude::*;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use serde::{Deserialize, Serialize};
use tlsn_core::commitment::CommitmentKind;
pub use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::ProverState, Prover, ProverConfig};
use tracing::{debug, info, trace};
use url::Url;
#[cfg(target_arch = "wasm32")]
use {futures::channel::oneshot, wasm_bindgen_futures::spawn_local, ws_stream_wasm::WsMeta};
#[cfg(not(target_arch = "wasm32"))]
use {
  tokio::net::TcpStream, tokio_util::compat::FuturesAsyncReadCompatExt,
  tokio_util::compat::TokioAsyncReadCompatExt,
};

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub notary_host:                  String,
  pub notary_port:                  u16,
  pub target_method:                String,
  pub target_url:                   String,
  pub target_headers:               HashMap<String, String>,
  pub target_body:                  String,
  #[cfg(feature = "websocket")]
  pub websocket_proxy_url:          String,
  pub notarization_session_request: NotarizationSessionRequest, // TODO rename to something better
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizationSessionRequest {
  pub client_type:   ClientType, // TODO depends on feature = websocket
  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
  /// Client that has access to the transport layer
  Tcp,
  /// Client that cannot directly access transport layer, e.g. browser extension
  Websocket,
}

pub async fn prover_inner(config: Config) -> Result<TlsProof, errors::ClientErrors> {
  info!("client entered `prover_inner` to construct webproof");

  trace!("{config:#?}");
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Parse the target url -> Check that it is HTTPS -> Extract the port being used
  //---------------------------------------------------------------------------------------------------------------------------------------//

  let _span = tracing::span!(tracing::Level::TRACE, "parse_target_url").entered();
  let target_url = Url::parse(&config.target_url)?;

  trace!("parsed `target_url`: {target_url:?}");
  // TODO: These three lines with target_url should probably throw a well-defined error instead of
  // causing panic.
  let target_host = target_url.host_str().expect("Invalid `target_url` host!");
  assert!(target_url.scheme() == "https");

  debug!("parsed `target_host`: {target_host:?}; IS HTTPS!");
  // Only returns none if no port or known protocol used
  let target_port = target_url.port_or_known_default().expect("Target has an unknown port!");
  // debug!("parsed `target_port`: {target_port:?}"); // TODO target_port does not exist, fix
  // feature flags

  info!("target connection data built");

  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // TODO: The following should be made modular in that we don't want to enforce we are going to
  // notary approach
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Create a notary session and get back a `NetworkStream` and the session ID
  //---------------------------------------------------------------------------------------------------------------------------------------//

  let _span = tracing::span!(tracing::Level::TRACE, "connect_to_notary").entered();

  // TODO: (OLD COMMENT?)
  // Claim back the TLS socket after HTTP exchange is done
  // #[cfg(not(target_arch = "wasm32"))]
  // let Parts { io: notary_tls_socket, .. } = connection_task.await??;

  debug!("TLS socket created with TCP connection");

  let session_id = uuid::Uuid::new_v4().to_string();

  let wss_url = format!(
    "wss://{}:{}/v1/tlsnotary?session_id={}",
    config.notary_host, config.notary_port, session_id
  );

  #[cfg(target_arch = "wasm32")]
  let (_, notary_tls_socket) = WsMeta::connect(wss_url, None).await.unwrap();

  #[cfg(not(target_arch = "wasm32"))]
  let ws_connection = {
    use ws_stream_tungstenite::WsStream;
    let (notary_tls_socket, _) =
      async_tungstenite::async_std::connect_async(wss_url).await.unwrap();
    WsStream::new(notary_tls_socket)
  };

  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Set up the prover which lies on the client and can access the notary for MPC
  //---------------------------------------------------------------------------------------------------------------------------------------//

  let root_store = default_root_store(); // TODO lot of memory allocation happening here.
                                         // maybe add this to shared state?

  let _span = tracing::span!(tracing::Level::TRACE, "create_prover").entered();
  let mut prover_config = ProverConfig::builder();
  prover_config.id(session_id).server_dns(target_host).root_cert_store(root_store);
  prover_config.max_transcript_size(
    config.notarization_session_request.max_sent_data.unwrap()
      + config.notarization_session_request.max_recv_data.unwrap(),
  ); // TODO unwrap
  let prover_config = prover_config.build()?;

  // Create a new prover and with MPC backend. use tokio::io::{AsyncReadExt, AsyncWriteExt};
  #[cfg(not(target_arch = "wasm32"))]
  let prover =
    Prover::new(prover_config).setup(TokioAsyncReadCompatExt::compat(ws_connection)).await?;
  #[cfg(target_arch = "wasm32")]
  let prover = Prover::new(prover_config).setup(notary_tls_socket.into_io()).await?;

  debug!("{prover:?}");

  debug!("prover created");

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
    .extend_pairs([("target_host", target_host), ("target_port", &target_port.to_string())])
    .finish();
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let (mpc_tls_connection, prover_fut) = {
    let (_, ws_stream) =
      WsMeta::connect(format!("{}?{}", config.websocket_proxy_url, ws_query), None).await?;
    let client_target_socket = ws_stream.into_io();
    prover.connect(client_target_socket).await?
  };

  #[cfg(any(not(feature = "websocket"), not(target_arch = "wasm32")))]
  let mpc_tls_connection = hyper_util::rt::TokioIo::new(mpc_tls_connection.compat());
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let mpc_tls_connection = wasm_utils::WasmAsyncIo::new(mpc_tls_connection);

  // Grab a control handle to the Prover
  let prover_ctrl = prover_fut.control();

  debug!("prover created");
  // Spawn the Prover to be run concurrently
  #[cfg(not(target_arch = "wasm32"))]
  let prover_task = tokio::spawn(prover_fut);

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
  let _mpc_tls_connection_task = tokio::spawn(mpc_tls_connection);

  #[cfg(target_arch = "wasm32")]
  let connection_receiver = {
    let (connection_sender, connection_receiver) = oneshot::channel();
    let connection_fut = mpc_tls_connection.without_shutdown();
    let handled_connection_fut = async {
      let result = connection_fut.await;
      let _ = connection_sender.send(result);
    };
    spawn_local(handled_connection_fut);
    connection_receiver
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
  // Send the HTTP request from the client to the target
  //---------------------------------------------------------------------------------------------------------------------------------------//

  debug!("Sending request");

  // Because we don't need to decrypt the response right away, we can defer decryption
  // until after the connection is closed. This will speed up the proving process!
  prover_ctrl.defer_decryption().await?;

  // TODO: Clean up this logging and error handling
  match request_sender.send_request(request).await {
    Ok(response) => {
      let status = response.status();
      let _payload = response.into_body();

      debug!("Response:\n{:?}", _payload);
      debug!("Response Status:\n{:?}", status);

      assert!(status.is_success()); // status is 200-299

      debug!("Request OK");
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO */
    Err(e) => panic!("{:?}", e),
  };

  debug!("Sent request");
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(target_arch = "wasm32")]
  {
    use futures::AsyncWriteExt;
    let mut client_socket = connection_receiver.await.unwrap()?.io.into_inner(); // TODO fix unwrap
    client_socket.close().await?;
  }

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Complete the prover and notarization
  //---------------------------------------------------------------------------------------------------------------------------------------//
  let prover = prover_task.await.unwrap()?; // TODO fix unwrap

  // Upgrade the prover to an HTTP prover, and start notarization.
  let mut prover = prover.to_http()?.start_notarize();

  // TODO: unwrap for now as we need to bring in `tlsn_formats`
  // Commit to the transcript with the default committer, which will commit using BLAKE3.
  prover.commit().unwrap();

  // Finalize, returning the notarized HTTP session
  let notarized_session = prover.finalize().await?;

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

pub async fn tlsnotary_notarize(
  prover: Prover<tlsn_prover::tls::state::Closed>,
) -> Result<TlsProof, errors::ClientErrors> {
  let mut prover = prover.to_http()?.start_notarize();

  prover.commit().unwrap();

  let notarized_session = prover.finalize().await?;

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
}

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

/// Default root store using mozilla certs.
pub fn default_root_store() -> tls_client::RootCertStore {
  let mut root_store = tls_client::RootCertStore::empty();
  root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
      ta.subject.as_ref(),
      ta.subject_public_key_info.as_ref(),
      ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
    )
  }));

  #[cfg(feature = "notary_ca_cert")]
  {
    debug!("notary_ca_cert feature enabled");
    let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
    let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
    assert_eq!(added, 1); // TODO there is probably a better way
  }

  root_store
}
