use std::panic;

use url::Url;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsMeta;
pub(crate) mod hyper_io;
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub async fn connect(
    proxy_url: String,
    target_host: String,
    target_port: u16,
) -> Result<JsValue, JsValue> {
    // https://github.com/rustwasm/console_error_panic_hook
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    console_log!(
        "Connecting to {}:{} via proxy {}",
        target_host,
        target_port,
        proxy_url
    );

    let mut url = Url::parse(&proxy_url)
        .map_err(|e| JsValue::from_str(&format!("Could not parse proxy_url: {:?}", e)))?;

    // TODO check url.scheme() == wss or ws

    url.query_pairs_mut()
        .append_pair("target_host", &target_host);
    url.query_pairs_mut()
        .append_pair("target_port", &target_port.to_string());

    // // TODO simple ping/pong example
    // console_log!("ping sent");
    // stream.write_all(b"ping").await.unwrap();

    // let mut buf = [0; 4]; // store pong
    // stream.read_exact(&mut buf).await.unwrap();
    // console_log!("Received: {}", String::from_utf8_lossy(&buf));

    use std::sync::Arc;

    use futures::{channel::oneshot, AsyncWriteExt};
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, Request, StatusCode};
    use pki_types::CertificateDer;
    use tls_client::{ClientConnection, RustCryptoBackend, ServerName};
    use tls_client_async::bind_client;
    use wasm_bindgen_futures::spawn_local;

    use crate::hyper_io::FuturesIo;

    // === 1. Setup a websocket
    let (_, ws_stream) = WsMeta::connect(url.to_string(), None)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not connect to proxy: {:?}", e)))?;

    // === 2.  Setup a TLS Connection
    let target = format!("https://{}:{}", target_host, target_port);
    let target_url = Url::parse(&target)
        .map_err(|e| JsValue::from_str(&format!("Could not parse target_url: {:?}", e)))?;

    console_log!("target_url: {:?}", target_url);
    console_log!("target_url: {:?}", target_url.host_str());

    let target_host = target_url
        .host_str()
        .ok_or(JsValue::from_str("Could not get target host"))?;

    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    const LOCALHOST_DEBUG_CA_CERT: &[u8] = include_bytes!("../../fixture/mock_server/ca-cert.cer");
    let cert = CertificateDer::from(LOCALHOST_DEBUG_CA_CERT.to_vec());
    let (added, _) = root_store.add_parsable_certificates(&[cert.to_vec()]);
    assert_eq!(added, 1);

    let config = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client = ClientConnection::new(
        Arc::new(config),
        Box::new(RustCryptoBackend::new()),
        ServerName::try_from(target_host).unwrap(),
    )
    .unwrap();
    let (client_tls_conn, tls_fut) = bind_client(ws_stream.into_io(), client);

    // TODO: Is this really needed?
    let client_tls_conn = unsafe { FuturesIo::new(client_tls_conn) };

    // TODO: What do with tls_fut? what do with tls_receiver?
    let (tls_sender, _tls_receiver) = oneshot::channel();
    let handled_tls_fut = async {
        let result = tls_fut.await;
        // Triggered when the server shuts the connection.
        console_log!("tls_sender.send({:?})", result);
        let _ = tls_sender.send(result);
    };
    spawn_local(handled_tls_fut);

    // === 3. Do HTTP over the TLS Connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(client_tls_conn)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not handshake: {:?}", e)))?;

    let (connection_sender, connection_receiver) = oneshot::channel();
    let connection_fut = connection.without_shutdown();
    let handled_connection_fut = async {
        let result = connection_fut.await;
        console_log!("connection_sender.send({:?})", result);
        let _ = connection_sender.send(result);
    };
    spawn_local(handled_connection_fut);

    let req_with_header = Request::builder()
        .uri(target_url.to_string())
        .method("POST"); // TODO: test

    console_log!("empty body");
    let unwrapped_request = req_with_header
        .body(Full::new(Bytes::default()))
        .map_err(|e| JsValue::from_str(&format!("Could not build request: {:?}", e)))?;

    // Send the request to the Server and get a response via the TLS connection
    let response = request_sender
        .send_request(unwrapped_request)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not send request: {:?}", e)))?;

    if response.status() != StatusCode::OK {
        return Err(JsValue::from_str(&format!(
            "Response status is not OK: {:?}",
            response.status()
        )));
    }

    let payload = response
        .into_body()
        .collect()
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not get response body: {:?}", e)))?
        .to_bytes();

    console_log!("Response: {:?}", payload);

    // Close the connection to the server
    let mut client_socket = connection_receiver
        .await
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Could not receive from connection_receiver: {:?}",
                e
            ))
        })?
        .map_err(|e| JsValue::from_str(&format!("Could not get TlsConnection: {:?}", e)))?
        .io
        .into_inner();

    client_socket
        .close()
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not close socket: {:?}", e)))?;
    console_log!("closed client_socket");

    Ok("".into()) // TODO
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn warn(s: &str);
}

// == NOTES on Origo Approach
//
// Handshake Setup
// - Need to verify the cert chain
// - Reveal the Server Handshake Traffic Secret to the proxy
// - Using this, proxy derives the SHTK to decrypt the handshake
// - Now that handshake is decrypted, verify certificate chain (out of circuit)

// Client Side Proof
// - Prove that the client derived the handshake key in a predictable manner
// - i.e. the symmetric key is "proven" to be the mix of predictable local
//   randomness
// - compute "h7" => H(ClientHello||...||ServerCertVerify)
// - compute "h2" => H(ClientHello||ServerHello)

// In-circuit Verification (key derivation)
// Goal: Prove that keys are derived legitimately
//
// Witness (HS, H2, H3, SHTS)
// SHTS <= HKDF.expand (HS,“s hs traffic” || H2)
// dhs <= HKDF.expand (HS,“derived”, H(“ ”))
// MS ← HKDF.extract (dHS, 0)
// CATS ← HKDF.expand (MS, “c ap traffic” || H3)
// SATS ← HKDF.expand (MS, “s ap traffic” || H3)
// CATK ← DeriveTK(CATS)
// SATK ← DeriveTK(SATS)

// Notes:
// h7, h2, h3, h0 => all computed by the proxy
// only private key must be hashed in circuit  (because proxy can check the
// rest)
//

// Out-of-circuit Verification
//
// Witness SHTS, H7, SF
// Fk <= HKDF expand (shts, finished) => TODO: What is this algorithm
// SF' <= HMAC (Fk, H7)
// SF1 == SF
// ok =? verifyCertificate()
