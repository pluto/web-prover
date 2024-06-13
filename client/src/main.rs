use base64::prelude::*;
use http_body_util::Full;
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use pki_types::CertificateDer;
use serde::Deserialize;
use std::collections::HashMap;
use tlsn_core::commitment::CommitmentKind;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;
use url::Url;
use anyhow::Result;

mod notary;

const LOCALHOST_DEBUG_CA_CERT: &[u8] = include_bytes!("../../vanilla-go-app/certs/ca-cert.cer");

#[derive(Deserialize, Clone)]
struct Config {
    target_method: String,
    target_url: String,
    target_headers: HashMap<String, Vec<String>>,
    target_body: String,

    max_sent_data: Option<usize>,
    max_recv_data: Option<usize>,

    notary_host: String,
    notary_port: u16,
    notary_ca_cert_path: String,
    notary_ca_cert_server_name: String,
}


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init(); // RUST_LOG=TRACE outputs to stdout

    let config = Config {
        target_method: "GET".into(),
        target_url: "https://localhost:8065".into(),
        target_headers: Default::default(),
        target_body: "".to_string(),

        max_sent_data: Some(4096),
        max_recv_data: Some(16384),

        notary_host: "localhost".into(), // prod: tlsnotary.pluto.xyz
        notary_port: 7047,               // prod: 443
        notary_ca_cert_path: "tlsn/notary-server/fixture/tls/rootCA.crt".to_string(), // prod: ./tlsnotary.pluto.xyz-rootca.crt
        notary_ca_cert_server_name: "tlsnotaryserver.io".to_string(), // prod: tlsnotary.pluto.xyz
    };

    let proof = prover(config).await?;
    let proof_json = serde_json::to_string_pretty(&proof)?;
    std::fs::write("webproof.json", proof_json)?;
    println!("Done");
    Ok(())
}

async fn prover(config: Config) -> Result<TlsProof> {
    let parsed_url = Url::parse(&config.target_url).expect("Failed to parse target_url");
    let server_domain = parsed_url.host_str().unwrap();
    assert!(parsed_url.scheme() == "https");

    let (notary_tls_socket, session_id) = notary::request_notarization(
        &config.notary_host,
        config.notary_port,
        config.max_sent_data,
        config.max_recv_data,
        &config.notary_ca_cert_path,
        &config.notary_ca_cert_server_name,
    )
    .await?;

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

    // Basic default prover config using the session_id returned from /session endpoint just now
    let pconfig = ProverConfig::builder()
        .id(session_id)
        .server_dns(server_domain)
        .root_cert_store(root_store)
        .build()?;

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(pconfig)
        .setup(notary_tls_socket.compat())
        .await?;

    let client_socket = tokio::net::TcpStream::connect((
        server_domain,
        match parsed_url.port() {
            Some(port) => port,
            _ => 443,
        },
    ))
    .await?;

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
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
                hyper::header::HeaderName::from_bytes(key.as_bytes())?,
                value.parse()?,
            );
        }
    }

    // Using "identity" instructs the Server not to use compression for its HTTP response.
    // TLSNotary tooling does not support compression.
    headers.insert("Host", server_domain.parse()?);
    headers.insert("Accept-Encoding", "identity".parse()?);
    headers.insert("Connection", "close".parse()?);

    if headers.get("Accept").is_none() {
        headers.insert("Accept", "*/*".parse()?);
    }

    let body = if config.target_body.is_empty() {
        Full::new(Bytes::from(vec![])) // TODO Empty::<Bytes>::new()
    } else {
        Full::new(Bytes::from(
            BASE64_STANDARD.decode(config.target_body)?,
        ))
    };

    let request = request.body(body)?;

    debug!("Sending request");

    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await?;

    match request_sender.send_request(request).await {
        Ok(response) => {
            assert!(response.status().is_success()); // status is 200-299
            debug!("Request OK");
        }
        Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), // TODO
        Err(e) => panic!("{:?}", e),
    };

    debug!("Sent request");

    // TODO: print payload for debugging purposes
    // let payload = response.into_body().collect().await.unwrap().to_bytes();
    // let parsed = serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    // debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await??;

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http()?.start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit()?;

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await?;

    debug!("Notarization complete!");

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        ?;

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        ?;

    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                ?;
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                ?;
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        ?;

    // Build the proof
    let substrings_proof = proof_builder.build()?;

    Ok(TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    })
}
