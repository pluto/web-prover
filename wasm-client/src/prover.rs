use std::ops::Range;

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use js_sys::Array;
use pki_types::CertificateDer;
use strum::EnumMessage;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{Prover, ProverConfig};
use tracing::{debug, info};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
pub use wasm_bindgen_rayon::init_thread_pool;
use web_sys::{Headers, RequestInit, RequestMode};
use web_time::Instant;
use ws_stream_wasm::*;

pub use crate::request_opt::VerifyResult;
use crate::{
    fetch_as_json_string,
    hyper_io::FuturesIo,
    request_opt::RequestOptions,
    requests::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse},
};

#[derive(strum_macros::EnumMessage, Debug, Clone, Copy)]
#[allow(dead_code)]
enum ProverPhases {
    #[strum(message = "Connect application server with websocket proxy")]
    ConnectWsProxy,
    #[strum(message = "Build prover config")]
    BuildProverConfig,
    #[strum(message = "Set up prover")]
    SetUpProver,
    #[strum(message = "Bind the prover to the server connection")]
    BindProverToConnection,
    #[strum(message = "Spawn the prover thread")]
    SpawnProverThread,
    #[strum(message = "Attach the hyper HTTP client to the TLS connection")]
    AttachHttpClient,
    #[strum(message = "Spawn the HTTP task to be run concurrently")]
    SpawnHttpTask,
    #[strum(message = "Build request")]
    BuildRequest,
    #[strum(message = "Start MPC-TLS connection with the server")]
    StartMpcConnection,
    #[strum(message = "Received response from the server")]
    ReceivedResponse,
    #[strum(message = "Parsing response from the server")]
    ParseResponse,
    #[strum(message = "Close the connection to the server")]
    CloseConnection,
    #[strum(message = "Start notarization")]
    StartNotarization,
    #[strum(message = "Commit to data")]
    Commit,
    #[strum(message = "Finalize")]
    Finalize,
    #[strum(message = "Notarization complete")]
    NotarizationComplete,
    #[strum(message = "Create Proof")]
    CreateProof,
}

fn log_phase(phase: ProverPhases) {
    info!("tlsn-js {}: {}", phase as u8, phase.get_message().unwrap());
}

const LOCALHOST_DEBUG_CA_CERT: &[u8] = include_bytes!("../../vanilla-go-app/certs/ca-cert.cer");

#[wasm_bindgen]
pub async fn prover(
    target_url_str: &str,
    val: JsValue,
    secret_headers: JsValue,
    secret_body: JsValue,
) -> Result<String, JsValue> {
    debug!("target_url: {}", target_url_str);
    let target_url = Url::parse(target_url_str)
        .map_err(|e| JsValue::from_str(&format!("Could not parse target_url: {:?}", e)))?;

    debug!(
        "target_url.host: {}",
        target_url
            .host()
            .ok_or(JsValue::from_str("Could not get target host"))?
    );
    let options: RequestOptions = serde_wasm_bindgen::from_value(val)
        .map_err(|e| JsValue::from_str(&format!("Could not deserialize options: {:?}", e)))?;
    debug!("options.notary_url: {}", options.notary_url.as_str());

    let start_time = Instant::now();

    // Connect Notary with websocket

    let mut opts = RequestInit::new();
    opts.method("POST");
    // opts.method("GET");
    opts.mode(RequestMode::Cors);

    // set headers
    let headers = Headers::new()
        .map_err(|e| JsValue::from_str(&format!("Could not create headers: {:?}", e)))?;
    let notary_url = Url::parse(options.notary_url.as_str())
        .map_err(|e| JsValue::from_str(&format!("Could not parse notary_url: {:?}", e)))?;
    let notary_ssl = notary_url.scheme() == "https" || notary_url.scheme() == "wss";
    let notary_host = notary_url.authority();
    let notary_path = notary_url.path();
    let notary_path_str = if notary_path == "/" { "" } else { notary_path };

    headers
        .append("Host", notary_host)
        .map_err(|e| JsValue::from_str(&format!("Could not append Host header: {:?}", e)))?;
    headers
        .append("Content-Type", "application/json")
        .map_err(|e| {
            JsValue::from_str(&format!("Could not append Content-Type header: {:?}", e))
        })?;
    opts.headers(&headers);

    info!("notary_host: {}", notary_host);
    // set body
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Websocket,
        max_sent_data: options.max_sent_data,
        max_recv_data: options.max_recv_data,
    })
    .map_err(|e| JsValue::from_str(&format!("Could not serialize request: {:?}", e)))?;
    opts.body(Some(&JsValue::from_str(&payload)));

    // url
    let url = format!(
        "{}://{}{}/session",
        if notary_ssl { "https" } else { "http" },
        notary_host,
        notary_path_str
    );
    debug!("Request: {}", url);
    let rust_string = fetch_as_json_string(&url, &opts)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not fetch session: {:?}", e)))?;
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&rust_string)
            .map_err(|e| JsValue::from_str(&format!("Could not deserialize response: {:?}", e)))?;
    debug!("Response: {}", rust_string);

    debug!("Notarization response: {:?}", notarization_response,);
    let notary_wss_url = format!(
        "{}://{}{}/notarize?sessionId={}",
        if notary_ssl { "wss" } else { "ws" },
        notary_host,
        notary_path_str,
        notarization_response.session_id
    );
    let (_, notary_ws_stream) = WsMeta::connect(notary_wss_url, None)
        .await
        .expect_throw("assume the notary ws connection succeeds");
    let notary_ws_stream_into = notary_ws_stream.into_io();

    log_phase(ProverPhases::BuildProverConfig);

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

    let cert = CertificateDer::from(LOCALHOST_DEBUG_CA_CERT.to_vec());
    let (added, _) = root_store.add_parsable_certificates(&[cert.to_vec()]);
    assert_eq!(added, 1);

    // Basic default prover config
    let mut builder = ProverConfig::builder();

    if let Some(max_sent_data) = options.max_sent_data {
        builder.max_sent_data(max_sent_data);
    }
    if let Some(max_recv_data) = options.max_recv_data {
        builder.max_recv_data(max_recv_data);
    }
    let config = builder
        .id(notarization_response.session_id)
        .server_dns(target_host)
        .root_cert_store(root_store)
        .build()
        .map_err(|e| JsValue::from_str(&format!("Could not build prover config: {:?}", e)))?;

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    log_phase(ProverPhases::SetUpProver);
    let prover = Prover::new(config)
        .setup(notary_ws_stream_into)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not set up prover: {:?}", e)))?;

    // Connect Application Server with websocket proxy
    log_phase(ProverPhases::ConnectWsProxy);

    let (_, client_ws_stream) = WsMeta::connect(options.websocket_proxy_url, None)
        .await
        .expect_throw("assume the client ws connection succeeds");

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the Notary.
    log_phase(ProverPhases::BindProverToConnection);
    let (mpc_tls_connection, prover_fut) =
        prover.connect(client_ws_stream.into_io()).await.unwrap();
    let mpc_tls_connection = unsafe { FuturesIo::new(mpc_tls_connection) };

    let prover_ctrl = prover_fut.control();

    log_phase(ProverPhases::SpawnProverThread);
    let (prover_sender, prover_receiver) = oneshot::channel();
    let handled_prover_fut = async {
        let result = prover_fut.await;
        let _ = prover_sender.send(result);
    };
    spawn_local(handled_prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    log_phase(ProverPhases::AttachHttpClient);
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .map_err(|e| JsValue::from_str(&format!("Could not handshake: {:?}", e)))?;

    // Spawn the HTTP task to be run concurrently
    log_phase(ProverPhases::SpawnHttpTask);
    let (connection_sender, connection_receiver) = oneshot::channel();
    let connection_fut = connection.without_shutdown();
    let handled_connection_fut = async {
        let result = connection_fut.await;
        let _ = connection_sender.send(result);
    };
    spawn_local(handled_connection_fut);

    log_phase(ProverPhases::BuildRequest);
    let mut req_with_header = Request::builder()
        .uri(target_url_str)
        .method(options.method.as_str());

    for (key, value) in options.headers {
        info!("adding header: {} - {}", key.as_str(), value.as_str());
        req_with_header = req_with_header.header(key.as_str(), value.as_str());
    }

    let req_with_body = if options.body.is_empty() {
        info!("empty body");
        req_with_header.body(Full::new(Bytes::default()))
    } else {
        info!("added body - {}", options.body.as_str());
        req_with_header.body(Full::from(options.body))
    };

    let unwrapped_request = req_with_body
        .map_err(|e| JsValue::from_str(&format!("Could not build request: {:?}", e)))?;

    log_phase(ProverPhases::StartMpcConnection);

    // Defer decryption of the response.
    prover_ctrl
        .defer_decryption()
        .await
        .map_err(|e| JsValue::from_str(&format!("failed to enable deferred decryption: {}", e)))?;

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender
        .send_request(unwrapped_request)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not send request: {:?}", e)))?;

    log_phase(ProverPhases::ReceivedResponse);
    if response.status() != StatusCode::OK {
        return Err(JsValue::from_str(&format!(
            "Response status is not OK: {:?}",
            response.status()
        )));
    }

    log_phase(ProverPhases::ParseResponse);
    // Pretty printing :)
    let payload = response
        .into_body()
        .collect()
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not get response body: {:?}", e)))?
        .to_bytes();
    let parsed = serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload))
        .map_err(|e| JsValue::from_str(&format!("Could not parse response: {:?}", e)))?;
    let response_pretty = serde_json::to_string_pretty(&parsed)
        .map_err(|e| JsValue::from_str(&format!("Could not serialize response: {:?}", e)))?;
    info!("Response: {}", response_pretty);

    // Close the connection to the server
    log_phase(ProverPhases::CloseConnection);
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

    // The Prover task should be done now, so we can grab it.
    log_phase(ProverPhases::StartNotarization);
    let prover = prover_receiver
        .await
        .map_err(|e| {
            JsValue::from_str(&format!("Could not receive from prover_receiver: {:?}", e))
        })?
        .map_err(|e| JsValue::from_str(&format!("Could not get Prover: {:?}", e)))?;
    let mut prover = prover.start_notarize();

    let secret_headers_vecs = string_list_to_bytes_vec(&secret_headers)?;
    let secret_headers_slices: Vec<&[u8]> = secret_headers_vecs
        .iter()
        .map(|vec| vec.as_slice())
        .collect();

    // Identify the ranges in the transcript that contain revealed_headers
    let (sent_public_ranges, sent_private_ranges) = find_ranges(
        prover.sent_transcript().data(),
        secret_headers_slices.as_slice(),
    );

    let secret_body_vecs = string_list_to_bytes_vec(&secret_body)?;
    let secret_body_slices: Vec<&[u8]> =
        secret_body_vecs.iter().map(|vec| vec.as_slice()).collect();

    // Identify the ranges in the transcript that contain the only data we want to
    // reveal later
    let (recv_public_ranges, recv_private_ranges) = find_ranges(
        prover.recv_transcript().data(),
        secret_body_slices.as_slice(),
    );

    log_phase(ProverPhases::Commit);

    let _recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Commit to the outbound and inbound transcript, isolating the data that
    // contain secrets
    let sent_pub_commitment_ids = sent_public_ranges
        .iter()
        .map(|range| {
            builder.commit_sent(range).map_err(|e| {
                JsValue::from_str(&format!("Error committing sent pub range: {:?}", e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    sent_private_ranges.iter().try_for_each(|range| {
        builder
            .commit_sent(range)
            .map_err(|e| {
                JsValue::from_str(&format!("Error committing sent private range: {:?}", e))
            })
            .map(|_| ())
    })?;

    let recv_pub_commitment_ids = recv_public_ranges
        .iter()
        .map(|range| {
            builder.commit_recv(range).map_err(|e| {
                JsValue::from_str(&format!("Error committing recv public ranges: {:?}", e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    recv_private_ranges.iter().try_for_each(|range| {
        builder
            .commit_recv(range)
            .map_err(|e| {
                JsValue::from_str(&format!("Error committing recv private range: {:?}", e))
            })
            .map(|_| ())
    })?;

    // Finalize, returning the notarized session
    log_phase(ProverPhases::Finalize);
    let notarized_session = prover
        .finalize()
        .await
        .map_err(|e| JsValue::from_str(&format!("Error finalizing prover: {:?}", e)))?;

    log_phase(ProverPhases::NotarizationComplete);

    // Create a proof for all committed data in this session
    log_phase(ProverPhases::CreateProof);
    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal everything except the redacted stuff (which for the response it's
    // everything except the screen_name)
    sent_pub_commitment_ids
        .iter()
        .chain(recv_pub_commitment_ids.iter())
        .try_for_each(|id| {
            proof_builder
                .reveal_by_id(*id)
                .map_err(|e| JsValue::from_str(&format!("Could not reveal commitment: {:?}", e)))
                .map(|_| ())
        })?;

    let substrings_proof = proof_builder
        .build()
        .map_err(|e| JsValue::from_str(&format!("Could not build proof: {:?}", e)))?;

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    let res = serde_json::to_string_pretty(&proof)
        .map_err(|e| JsValue::from_str(&format!("Could not serialize proof: {:?}", e)))?;

    let duration = start_time.elapsed();
    info!("!@# request took {} seconds", duration.as_secs());

    Ok(res)
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

fn string_list_to_bytes_vec(secrets: &JsValue) -> Result<Vec<Vec<u8>>, JsValue> {
    let array: Array = Array::from(secrets);
    let length = array.length();
    let mut byte_slices: Vec<Vec<u8>> = Vec::new();

    for i in 0..length {
        let secret_js: JsValue = array.get(i);
        let secret_str: String = secret_js
            .as_string()
            .ok_or(JsValue::from_str("Could not convert secret to string"))?;
        let secret_bytes = secret_str.into_bytes();
        byte_slices.push(secret_bytes);
    }
    Ok(byte_slices)
}
