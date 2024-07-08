//! This is a mock client for local testing that should have some degree of
//! logic parity with the mobile target

use std::collections::HashMap;

use anyhow::Result;
use base64::prelude::*;
use clap::Parser;
use http_body_util::Full;
use hyper::{body::Bytes, Request, Version};
use hyper_util::rt::TokioIo;
use pki_types::CertificateDer;
use serde::Deserialize;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
#[cfg(feature = "tracing")]
use tracing::{debug, error, info, instrument, trace, trace_span, Level};
#[cfg(feature = "tracing")]
use tracing_subscriber::EnvFilter;
use url::Url;
use web_prover::{notary, ClientType, NotarizationSessionRequest};

const LOCALHOST_DEBUG_CA_CERT: &[u8] = include_bytes!("../fixture/mock_server/ca-cert.cer");

#[derive(Deserialize, Clone, Debug)]
struct Config {
  target_method:  String,
  target_url:     String,
  target_headers: HashMap<String, Vec<String>>,
  target_body:    String,
  notarization_session_request: NotarizationSessionRequest,
  notary_host:                String,
  notary_port:                u16,
  notary_ca_cert_path:        String,
}

#[derive(Parser)]
#[clap(name = "TLSN Client")]
#[clap(about = "A dummy client for Pluto TLSN WebProofs.", long_about = None)]
struct Args {
  #[clap(short, long, global = true, required = false, default_value = "TRACE")]
  log_level: String,

  #[clap(short, long, global = true, required = false, default_value = "health")]
  endpoint: String,
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info", ))]
#[tokio::main]
async fn main() -> Result<()> {
  let args = Args::parse();

  #[cfg(feature = "tracing")]
  let log_level = match args.log_level.to_lowercase().as_str() {
    "error" => Level::ERROR,
    "warn" => Level::WARN,
    "info" => Level::INFO,
    "debug" => Level::DEBUG,
    _ => Level::TRACE,
  };
  let crate_name = env!("CARGO_PKG_NAME");

  #[cfg(feature = "tracing")]
  let env_filter = EnvFilter::builder().parse_lossy(&format!("{}={},info", crate_name, log_level));

  #[cfg(feature = "tracing")]
  tracing_subscriber::fmt().with_env_filter(env_filter).init();

  let config = Config {
    target_method:  "GET".into(),
    target_url:     format!("https://localhost:8080/{}", args.endpoint),
    target_headers: Default::default(),
    target_body:    "".to_string(),

    notarization_session_request: NotarizationSessionRequest {
      client_type:   ClientType::Tcp,
      max_sent_data: Some(4096),
      max_recv_data: Some(16384),
    },

    notary_host:                "localhost".into(), // prod: tlsnotary.pluto.xyz
    notary_port:                7047,               // prod: 443
    notary_ca_cert_path:        "fixture/tls/rootCA.crt".to_string(), /* prod: ./tlsnotary.pluto.
                                                     * xyz-rootca.crt */
  };
  #[cfg(feature = "tracing")]
  info!("Client config: {:?}", config);

  let proof = prover(config).await?;
  let proof_json = serde_json::to_string_pretty(&proof)?;
  std::fs::write("webproof.json", proof_json)?;
  #[cfg(feature = "tracing")]
  info!("Proof complete. Proof written to `webproof.json`");
  Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip(config)))]
async fn prover(config: Config) -> Result<TlsProof> {
  // Verify the server at the target URL is using HTTPS
  let parsed_url = Url::parse(&config.target_url).expect("Failed to parse target_url");
  let server_domain = parsed_url.host_str().unwrap();
  assert!(parsed_url.scheme() == "https");

  // Request a notarization session from the notary server
  let (notary_tls_socket, session_id) = notary::request_notarization(
    &config.notary_host,
    config.notary_port,
    &config.notarization_session_request,
    &config.notary_ca_cert_path,
  )
  .await?;
#[cfg(feature = "tracing")]
  info!("Created a notarization session with session_id: {}", session_id);

  // Load the CA certificate for the notary server
  let root_store = {
    #[cfg(feature = "tracing")]
    let span = trace_span!("load_ca_cert");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();
    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
      tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
        ta.subject.as_ref(),
        ta.subject_public_key_info.as_ref(),
        ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
      )
    }));
    let cert = CertificateDer::from(LOCALHOST_DEBUG_CA_CERT.to_vec());
    #[cfg(feature = "tracing")]
    trace!("Adding X509 certificate to root store: {:?}", cert);
    let (added, _) = root_store.add_parsable_certificates(&[cert.to_vec()]);
    assert_eq!(added, 1);
    root_store
  };

  // Create a basic default prover config using the session_id returned from
  // session endpoint
  let prover = {
    #[cfg(feature = "tracing")]
    let span = trace_span!("prover_configuration");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();

    let pconfig = ProverConfig::builder()
      .id(session_id)
      .server_dns(server_domain)
      .root_cert_store(root_store)
      .build()?;
    #[cfg(feature = "tracing")]
    trace!("Creating prover with config: {:?}", pconfig);

    // Create a new prover and set up the MPC backend.
    Prover::new(pconfig).setup(notary_tls_socket.compat()).await?
  };

  // Connect the Prover to the server with TLS via the client socket
  let client_socket = tokio::net::TcpStream::connect((server_domain, match parsed_url.port() {
    Some(port) => port,
    _ => 443,
  }))
  .await?;
  #[cfg(feature = "tracing")]
  trace!("Connected to server via TCP socket: {:?}", client_socket);

  // Bind the Prover to server connection
  let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
  let tls_connection = TokioIo::new(tls_connection.compat());
  #[cfg(feature = "tracing")]
  debug!("Prover connected to server via TLS: {:?}", tls_connection);

  // Grab a control handle to the Prover
  let prover_ctrl = prover_fut.control();

  // Spawn the Prover to be run concurrently
  let prover_task = tokio::spawn(prover_fut);
  #[cfg(feature = "tracing")]
  debug!("Prover task spawned");

  // Attach the hyper HTTP client to the TLS connection
  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(tls_connection).await.unwrap();

  // Spawn the HTTP task to be run concurrently
  tokio::spawn(connection);
  #[cfg(feature = "tracing")]
  debug!("HTTP task spawned");

  // Send the HTTP request to the server
  // TODO: To do what exactly?
  {
    #[cfg(feature = "tracing")]
    let span = trace_span!("http_request");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();
    let mut request = Request::builder()
      .method(config.target_method.as_str())
      .uri(config.target_url)
      .version(Version::HTTP_10);

    let headers = request.headers_mut().unwrap();
    for (key, values) in config.target_headers {
      for value in values {
        headers.append(hyper::header::HeaderName::from_bytes(key.as_bytes())?, value.parse()?);
      }
    }

    // Using "identity" instructs the Server not to use compression for its HTTP
    // response. TLSNotary tooling does not support compression.
    headers.insert("Host", server_domain.parse()?);
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
    #[cfg(feature = "tracing")]
    debug!("Sending request: {:?}", request);

    // Because we don't need to decrypt the response right away, we can defer
    // decryption until after the connection is closed. This will speed up the
    // proving process!
    prover_ctrl.defer_decryption().await?;
    #[cfg(feature = "tracing")]
    trace!("Decryption deferred");

    match request_sender.send_request(request).await {
      Ok(response) => {
        #[cfg(feature = "tracing")]
        debug!("Response: {:?}", response.status());
        assert!(response.status().is_success()); // status is 200-299
        #[cfg(feature = "tracing")]
        debug!("Respose: OK");
      },
      Err(e) if e.is_incomplete_message() => {
        println!("Response: IncompleteMessage (ignored)")
      }, // TODO
      Err(e) => panic!("{:?}", e),
    };
    #[cfg(feature = "tracing")]
    info!("HTTP request sent!");
  }

  // The Prover task should be done now, so we can grab it.
  let prover = prover_task.await??;
  #[cfg(feature = "tracing")]
  debug!("Prover task complete");

  // Notarize the transcript
  let notarized_session = {
    #[cfg(feature = "tracing")]
    let span = trace_span!("notarize_transcript");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();
    let prover_result = prover.to_http();
    let mut prover = match prover_result {
      Ok(prover) => prover.start_notarize(),
      Err(e) => {
        #[cfg(feature = "tracing")]
        error!("Notarization failed: {:?}", e);
        return Err(e.into());
      },
    };

    // Commit to the transcript with the default committer, which will commit using
    // BLAKE3.
    prover.commit()?;
    #[cfg(feature = "tracing")]
    trace!("Committed to transcript");

    // Finalize, returning the notarized HTTP session
    prover.finalize().await?
  };
  #[cfg(feature = "tracing")]
  info!("Transcript notarized!");

  // Build the proofs
  let tls_proof = {
    #[cfg(feature = "tracing")]
    let span = trace_span!("build_tls_proof");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();

    let session_proof = notarized_session.session_proof();
    #[cfg(feature = "tracing")]
    debug!("Session proof created!");

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
    #[cfg(feature = "tracing")]
    debug!("Substrings proof created!");

    TlsProof { session: session_proof, substrings: substrings_proof }
  };

  Ok(tls_proof)
}
