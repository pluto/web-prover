use base64::prelude::*;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::backtrace::Backtrace;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{self, AssertUnwindSafe};
use tlsn_core::commitment::CommitmentKind;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;
use url::Url;

mod notary;

#[derive(Deserialize, Clone)]
struct Config {
    notary_host: String,
    notary_port: u16,
    target_method: String,
    target_url: String,
    target_headers: HashMap<String, Vec<String>>,
    target_body: String,
    max_sent_data: Option<usize>,
    max_recv_data: Option<usize>,
}

#[derive(Serialize, Clone)]
struct Output {
    proof: Option<String>,
    error: Option<String>,
}

#[no_mangle]
pub extern "C" fn prover(config_json: *const c_char) -> *const c_char {
    let collector = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(collector).unwrap();

    println!("GIT_HASH: {:?}", env!("GIT_HASH"));

    // catch panics and return them as string with backtrace
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let config_str = unsafe {
            assert!(!config_json.is_null());
            CStr::from_ptr(config_json)
                .to_str()
                .unwrap_or_else(|_| "Invalid UTF-8")
        };

        let config: Config = serde_json::from_str(config_str).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async_prover(config))
    }));

    match result {
        Ok(proof) => {
            let out = Output {
                proof: Some(proof),
                error: None,
            };
            let out_json = serde_json::to_string_pretty(&out).unwrap();
            CString::new(out_json).expect("JSON").into_raw()
        }
        Err(err) => {
            // TODO it looks like backtraces are currently disabled by the release build profile?
            let backtrace = Backtrace::capture();
            let out = Output {
                proof: None,
                error: if let Some(s) = err.downcast_ref::<&str>() {
                    Some(format!("Error: {}\n\nStack:\n{}", s, backtrace))
                } else {
                    Some(format!("{:#?}\n\nStack:\n{}", err, backtrace))
                },
            };
            let out_json = serde_json::to_string_pretty(&out).unwrap();
            CString::new(out_json).expect("JSON").into_raw()
        }
    }
}

async fn async_prover(config: Config) -> String {
    let parsed_url = Url::parse(&config.target_url).expect("Failed to parse target_url");
    let server_domain = parsed_url.host_str().unwrap();
    assert!(parsed_url.scheme() == "https");

    let (notary_tls_socket, session_id) = notary::request_notarization(
        &config.notary_host,
        config.notary_port,
        config.max_sent_data,
        config.max_recv_data,
    )
    .await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let pconfig = ProverConfig::builder()
        .id(session_id)
        .server_dns(server_domain)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(pconfig)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((server_domain, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request
    let mut request = Request::builder()
        .method(config.target_method.as_str())
        .uri(config.target_url);

    let headers = request.headers_mut().unwrap();
    for (key, values) in config.target_headers {
        for value in values {
            headers.append(
                hyper::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
    }

    // Using "identity" instructs the Server not to use compression for its HTTP response.
    // TLSNotary tooling does not support compression.
    headers.insert("Host", server_domain.parse().unwrap());
    headers.insert("Accept-Encoding", "identity".parse().unwrap());
    headers.insert("Connection", "close".parse().unwrap());

    if headers.get("Accept").is_none() {
        headers.insert("Accept", "*/*".parse().unwrap());
    }

    let body = if config.target_body.is_empty() {
        Full::new(Bytes::from(vec![])) // TODO Empty::<Bytes>::new()
    } else {
        Full::new(Bytes::from(
            BASE64_STANDARD.decode(config.target_body).unwrap(),
        ))
    };

    let request = request.body(body).unwrap();

    debug!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    match request_sender.send_request(request).await {
        Ok(response) => {
            let is_success = response.status().is_success();
            let payload = response.into_body().collect().await.unwrap().to_bytes();
            debug!("Response:\n{}", String::from_utf8_lossy(&payload));

            assert!(is_success); // status is 200-299
            debug!("Request OK");
        }
        Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), // TODO
        Err(e) => panic!("{:?}", e),
    };

    debug!("Sent request");

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http().unwrap().start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit().unwrap();

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();

    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    serde_json::to_string_pretty(&proof).unwrap()
}

#[tokio::test]
async fn test_prover_examplecom() {
    let config = Config {
        notary_host: "tlsnotary.pluto.xyz".into(),
        notary_port: 443,
        target_method: "GET".into(),
        target_url: "https://example.com".into(),
        target_headers: Default::default(),
        target_body: "".into(),
        max_sent_data: Some(4096),
        max_recv_data: Some(16384),
    };
    let proof_str = async_prover(config).await;
    assert!(proof_str.len() > 0);
    assert!(proof_str.contains("handshake_summary"));
}

// #[tokio::test]
// async fn test_prover_jsonplaceholder() {
//     let config = Config {
//         notary_host: "tlsnotary.pluto.xyz".into(),
//         notary_port: 443,
//         target_method: "GET".into(),
//         target_url: "https://jsonplaceholder.typicode.com/todos/1".into(),
//         target_headers: HashMap::from([
//             (
//                 "Authorization".to_string(),
//                 vec![
//                     "Bearer 6e539700b0b648946905d70a834877c65a4e5885f5f7d679a8a21b51899ecbe5"
//                         .to_string(),
//                 ],
//             ),
//             (
//                 "Content-Type".to_string(),
//                 vec!["application/json".to_string()],
//             ),
//         ]),
//         target_body: "".into(),
//         max_sent_data: Some(4096),
//         max_recv_data: Some(16384),
//     };
//     let proof_str = async_prover(config).await;
//     assert!(proof_str.len() > 0);
//     assert!(proof_str.contains("handshake_summary"));
// }