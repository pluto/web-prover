use std::io::{BufReader, Cursor};

use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::{body::Bytes, Request, StatusCode};
use rustls::{
  pki_types::{CertificateDer, ServerName},
  ClientConfig, RootCertStore,
};
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
  host: &str,
  port: u16,
  notarization_session_request: &NotarizationSessionRequest,
) -> Result<(NetworkStream, String), ClientErrors> {
  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Get the certs and add them to the root store
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "add_certs_to_root_store").entered();
  let mut reader = read_pem_from_string();
  let mut certificates: Vec<CertificateDer> =
    rustls_pemfile::certs(&mut reader).flat_map(Result::ok).collect();
  let certificate = certificates.remove(0);
  let mut root_store = RootCertStore::empty();
  root_store.add(certificate)?;
  #[cfg(feature = "tracing")]
  info!("certs added to root store");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Create and maintain a TLS session between the client and the notary
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "create_client_notary_tls_session").entered();
  let client_notary_config =
    ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
  #[cfg(feature = "tracing")]
  trace!("{client_notary_config:#?}");
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
  #[cfg(feature = "tracing")]
  trace!("{notary_tls_socket:#?}");
  #[cfg(all(feature = "websocket", target_arch = "wasm32"))]
  let (notary_tls_socket_io, notary_tls_socket) = {
    let (_ws_meta, ws_stream) = WsMeta::connect(host, None).await?;
    let (_ws_meta, ws_stream_io) = WsMeta::connect(host, None).await?;
    (ws_stream_io.into_io(), ws_stream)
  };

  // Attach the hyper HTTP client to the notary TLS connection to send request to the /session
  // endpoint to configure notarization and obtain session id
  #[cfg(target_arch = "wasm32")]
  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(AsyncIo::new(notary_tls_socket_io)).await?;
  #[cfg(not(target_arch = "wasm32"))]
  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(AsyncIo::new(notary_tls_socket)).await?;

  // Spawn the HTTP task to be run concurrently
  #[cfg(not(target_arch = "wasm32"))]
  let connection_task = spawn(connection.without_shutdown());
  #[cfg(target_arch = "wasm32")]
  {
    let connection = async {
      // TODO: This error handling here should work, but it is messy. The unwrap is acceptable in
      // this case.
      connection
        .await
        .map_err(|e| panic!("Connection failed in `request_notarization` due to {:?}", e))
        .unwrap();
    };
    spawn_local(connection);
  }
  // TODO: For some reason this span isn't really working properly
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Send the HTTP request to configure notarization
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span =
    tracing::span!(tracing::Level::TRACE, "send_notarization_configuration_request").entered();
  let payload = serde_json::to_string(notarization_session_request)?;

  let request = Request::builder()
        .uri(format!("https://{host}:{port}/session"))
        .method("POST")
        .header("Host", host)
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Either::Left(Full::new(Bytes::from(payload))))?;
  #[cfg(feature = "tracing")]
  trace!("configuration request: {request:#?}");

  let configuration_response = request_sender.send_request(request).await?;
  #[cfg(feature = "tracing")]
  debug!("sent the HTTP request for notarization configuration");

  #[cfg(feature = "tracing")]
  // TODO: This should be an error most likely
  assert!(configuration_response.status() == StatusCode::OK);

  #[cfg(feature = "tracing")]
  info!("successfully set notarization configuration!");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  //---------------------------------------------------------------------------------------------------------------------------------------//
  // Send the HTTP request to begin notarization (I think?)
  //---------------------------------------------------------------------------------------------------------------------------------------//
  #[cfg(feature = "tracing")]
  let _span = tracing::span!(tracing::Level::TRACE, "send_notarization_protocol_request").entered();

  let payload = configuration_response.into_body().collect().await?.to_bytes();
  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct NotarizationSessionResponse {
    /// Unique session id that is generated by notary and shared to prover
    pub session_id: String,
  }
  let notarization_response =
    serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
      .unwrap();
  #[cfg(feature = "tracing")]
  trace!("{notarization_response:?}");

  // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
  let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "https://{host}:{port}/notarize?sessionId={}",
            notarization_response.session_id
        ))
        .method("GET")
        .header("Host", host)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Either::Right(Empty::<Bytes>::new()))?;
  #[cfg(feature = "tracing")]
  trace!("notarization request: {request:#?}");

  let response = request_sender.send_request(request).await?;

  #[cfg(feature = "tracing")]
  debug!("sent notarization request");

  // TODO: This should also likely be an error
  assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

  #[cfg(feature = "tracing")]
  info!("successfully switched to notarization protocol!");
  #[cfg(feature = "tracing")]
  drop(_span);
  //---------------------------------------------------------------------------------------------------------------------------------------//

  // Claim back the TLS socket after HTTP exchange is done
  #[cfg(not(target_arch = "wasm32"))]
  let Parts { io: notary_tls_socket, .. } = connection_task.await??;
  #[cfg(not(target_arch = "wasm32"))]
  return Ok((notary_tls_socket.into_inner(), notarization_response.session_id.to_string()));
  #[cfg(target_arch = "wasm32")]
  return Ok((notary_tls_socket, session_id.to_string()));
}

// Let's encrypt RootCA
const PEM: &str = "
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----";

fn read_pem_from_string() -> BufReader<Cursor<Vec<u8>>> {
  let cursor = Cursor::new(PEM.as_bytes().to_vec());
  BufReader::new(cursor)
}
