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

const NOTARY_CA_CERT: &[u8] = include_bytes!("../fixture/mock_server/ca-cert.cer");

// TODO: The `ClientType` and  `NotarizationSessionRequest` and `NotarizationSessionResponse` is
// redundant with what we had in `request` for the wasm version which was deprecated. May have to be
// careful with the camelCase used here.

/// Requests notarization from the Notary server.
#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip_all))]
pub async fn request_notarization(
  notary_host: &str,
  notary_port: u16,
  config_notarization_session_request: &ConfigNotarizationSessionRequest,
  target_host: &str,
  target_port: u16,
) -> Result<(NetworkStream, String), ClientErrors> {
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Get the certs and add them to the root store
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "add_certs_to_root_store").entered();
  let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
  let mut root_store = tls_client::RootCertStore::empty();
  let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
  assert_eq!(added, 1); // TODO there is probably a better way
  #[cfg(feature = "tracing")]
  info!("certs added to root store");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Configure TLS Notary session and get session id
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // TODO the following applies to WASM only, make it work with non wasm as well

  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "configure_tls_notary_session").entered();
  let mut opts = web_sys::RequestInit::new();
  opts.method("POST");
  opts.mode(web_sys::RequestMode::Cors);

  let headers = web_sys::Headers::new().unwrap(); // TODO fix unwrap
  headers.append("Host", notary_host).unwrap(); // TODO fix unwrap
  headers.append("Content-Type", "application/json").unwrap(); // TODO fix unwrap
  opts.headers(&headers);

  let notarization_session_request = NotarizationSessionRequest {
    client_type:   config_notarization_session_request.client_type,
    max_sent_data: config_notarization_session_request.max_sent_data,
    max_recv_data: config_notarization_session_request.max_recv_data,
  };

  let payload = serde_json::to_string(&notarization_session_request).unwrap(); // TODO fix unwrap
  opts.body(Some(&wasm_bindgen::JsValue::from_str(&payload)));

  let url = format!("https://{}:{}/session", notary_host, notary_port);

  let raw_notarization_session_response =
    wasm_utils::fetch_as_json_string(&url, &opts).await.unwrap(); // TODO fix unwrap
  let notarization_response =
    serde_json::from_str::<NotarizationSessionResponse>(&raw_notarization_session_response)
      .unwrap(); // TODO fix unwrap
  #[cfg(feature = "tracing")]
  info!("Session configured, session_id: {}", notarization_response.session_id);
  #[cfg(feature = "tracing")]
  drop(_span);

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Create and maintain a TLS session between the client and the notary
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "create_client_notary_tls_session").entered();
  #[cfg(not(target_arch = "wasm32"))]
  let client_notary_config =
    ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
  // #[cfg(feature = "tracing")]
  // trace!("{client_notary_config:#?}"); // TODO: not found in this scope
  #[cfg(not(target_arch = "wasm32"))]
  let notary_tls_socket = {
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));
    let notary_socket = TcpStream::connect((host, port)).await?;
    notary_connector
    // Require the domain name of notary server to be the same as that in the server cert
    .connect(ServerName::try_from(host.to_owned()).unwrap(), notary_socket)
    .await
    ?
  };

  // TODO: Be careful to put this in with the right target arch
  #[cfg(feature = "tracing")]
  debug!("TLS socket created with TCP connection");
  // #[cfg(feature = "tracing")]
  // trace!("{notary_tls_socket:#?}"); // TODO not found in this scope
  // TODO connect to Notary requires notarization_response.session_id
  //      /notarize?sessionId={}
  // TODO Second WS connection is to websocket proxy (pass in config into function)
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let (notary_tls_socket_io, notary_tls_socket) = {
    let (_ws_meta, ws_stream) =
      WsMeta::connect(format!("wss://{}:{}", notary_host, notary_port), None).await?;
    let (_ws_meta, ws_stream_io) =
      WsMeta::connect(format!("wss://{}:{}", notary_host, notary_port), None).await?;
    (ws_stream_io.into_io(), ws_stream)
  };
  // Attach the hyper HTTP client to the notary TLS connection to send request to the /session
  // endpoint to configure notarization and obtain session id
  // #[cfg(target_arch = "wasm32")]
  // let (mut request_sender, connection) =
  //   hyper::client::conn::http1::handshake(AsyncIo::new(notary_tls_socket_io)).await?;
  // #[cfg(not(target_arch = "wasm32"))]
  // let (mut request_sender, connection) =
  //   hyper::client::conn::http1::handshake(AsyncIo::new(notary_tls_socket)).await?;

  // Spawn the HTTP task to be run concurrently
  // #[cfg(not(target_arch = "wasm32"))]
  // let connection_task = spawn(connection.without_shutdown());
  // #[cfg(target_arch = "wasm32")]
  // {
  //   let connection = async {
  //     // TODO: This error handling here should work, but it is messy. The unwrap is acceptable in
  //     // this case.
  //     connection
  //       .await
  //       .map_err(|e| panic!("Connection failed in `request_notarization` due to {:?}", e))
  //       .unwrap();
  //   };
  //   spawn_local(connection);
  // }
  // TODO: For some reason this span isn't really working properly
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Send the HTTP request to configure notarization
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // #[cfg(feature = "tracing")]
  // let _span =
  //   tracing::span!(tracing::Level::TRACE, "send_notarization_configuration_request").entered();
  // let payload = serde_json::to_string(notarization_session_request)?;

  // let request = Request::builder()
  //       .uri(format!("https://{notary_host}:{notary_port}/session"))
  //       .method("POST")
  //       .header("Host", notary_host)
  //       // Need to specify application/json for axum to parse it as json
  //       .header("Content-Type", "application/json")
  //       .body(Either::Left(Full::new(Bytes::from(payload))))?;
  // #[cfg(feature = "tracing")]
  // trace!("configuration request: {request:#?}");

  // let configuration_response = request_sender.send_request(request).await?;
  // #[cfg(feature = "tracing")]
  // debug!("sent the HTTP request for notarization configuration");

  // #[cfg(feature = "tracing")]
  // // TODO: This should be an error most likely
  // assert!(configuration_response.status() == StatusCode::OK);

  // #[cfg(feature = "tracing")]
  // info!("successfully set notarization configuration!");
  // #[cfg(feature = "tracing")]
  // drop(_span);

  // #[cfg(feature = "tracing")]
  // let _span = tracing::span!(tracing::Level::TRACE,
  // "send_notarization_protocol_request").entered();

  // let payload = configuration_response.into_body().collect().await?.to_bytes();
  // #[derive(Debug, Clone, Serialize, Deserialize)]
  // #[serde(rename_all = "camelCase")]
  // pub struct NotarizationSessionResponse {
  //   /// Unique session id that is generated by notary and shared to prover
  //   pub session_id: String,
  // }
  // let notarization_response =
  //   serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
  //     .unwrap();
  // #[cfg(feature = "tracing")]
  // trace!("{notarization_response:?}");
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Send the HTTP request to begin notarization (I think?)
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
  // let request = Request::builder()
  //       // Need to specify the session_id so that notary server knows the right configuration to
  // use       // as the configuration is set in the previous HTTP call
  //       .uri(format!(
  //           "https://{notary_host}:{notary_port}/notarize?sessionId={}", // TODO(matt) this is wss
  //           notarization_response.session_id
  //       ))
  //       .method("GET")
  //       .header("Host", notary_host)
  //       .header("Connection", "Upgrade")
  //       // Need to specify this upgrade header for server to extract tcp connection later
  //       .header("Upgrade", "TCP")
  //       .body(Either::Right(Empty::<Bytes>::new()))?;
  // #[cfg(feature = "tracing")]
  // trace!("notarization request: {request:#?}");

  // let response = request_sender.send_request(request).await?;

  #[cfg(feature = "tracing")]
  debug!("sent notarization request");

  // TODO: This should also likely be an error
  // assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

  #[cfg(feature = "tracing")]
  info!("successfully switched to notarization protocol!");
  // #[cfg(feature = "tracing")]
  // drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // Claim back the TLS socket after HTTP exchange is done
  #[cfg(not(target_arch = "wasm32"))]
  let Parts { io: notary_tls_socket, .. } = connection_task.await??;
  #[cfg(not(target_arch = "wasm32"))]
  return Ok((notary_tls_socket.into_inner(), notarization_response.session_id.to_string()));
  #[cfg(target_arch = "wasm32")]
  return Ok((notary_tls_socket, notarization_response.session_id.to_string()));
}
