use std::{ops::Deref, sync::Arc};

use caratls_ekm_client::TeeTlsConnector;
use caratls_ekm_google_confidential_space_client::GoogleConfidentialSpaceTokenVerifier;
use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use proofs::{
  program::{
    self,
    data::{Expanded, NotExpanded, Offline, Online, ProgramData},
    manifest::{
      EncryptionInput, NIVCRom, NivcCircuitInputs, Request as ManifestRequest,
      Response as ManifestResponse, TLSEncryption,
    },
  },
  proof::FoldingProof,
  F, G1, G2,
};
use tls_client2::origo::OrigoConnection;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{
  circuits::*,
  config::{self, NotaryMode},
  errors::ClientErrors,
  origo::SignBody,
  tls::decrypt_tls_ciphertext,
  OrigoProof,
};

/// Runs TLS proxy and generates NIVC proof
/// - runs TLS proxy to get TLS transcripts
/// - calls proxy to sign witness data
/// - decrypts TLS ciphertext in [`tls_client2::backend::origo::WitnessData`]
/// - takes TLS transcripts along with client [`Manifest`] and generates NIVC [`Proof`]
pub async fn proxy_and_sign_and_generate_proof(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
) -> Result<OrigoProof, ClientErrors> {
  let mut origo_conn = proxy(config.clone(), config.session_id.clone()).await?;

  let sb = SignBody {
    handshake_server_iv:  hex::encode(
      origo_conn.secret_map.get("Handshake:server_iv").unwrap().clone(),
    ),
    handshake_server_key: hex::encode(
      origo_conn.secret_map.get("Handshake:server_key").unwrap().clone(),
    ),
  };

  let _sign_data = crate::origo::sign(config.clone(), config.session_id.clone(), sb).await;

  let witness = origo_conn.to_witness_data();

  // decrypt TLS ciphertext for request and response and create NIVC inputs
  let TLSEncryption { request: request_inputs, response: response_inputs } =
    decrypt_tls_ciphertext(&witness)?;

  // generate NIVC proofs for request and response
  // TODO (tracy): cloning proving params here is likely quite expensive.
  let manifest = config.proving.manifest.unwrap();
  let (request_proof, response_proof) = rayon::join(
    || {
      construct_request_program_data_and_proof(
        &manifest.request,
        request_inputs,
        proving_params.clone().unwrap(),
      )
    },
    || {
      construct_response_program_data_and_proof(
        &manifest.response,
        response_inputs,
        proving_params.clone().unwrap(),
      )
    },
  );

  // TODO(Sambhav): handle request and response into one proof
  Ok(OrigoProof { request: request_proof?, response: Some(response_proof?) })
}

/// generates NIVC proof from [`ProgramData`]
/// - run NIVC recursive proving
/// - run CompressedSNARK to compress proof
/// - serialize proof
fn generate_proof(
  program_data: ProgramData<Online, Expanded>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  debug!("starting recursive proving");
  let program_output = program::run(&program_data)?;

  debug!("starting proof compression");
  let compressed_snark_proof = program::compress_proof_no_setup(
    &program_output,
    &program_data.public_params,
    program_data.vk_digest_primary,
    program_data.vk_digest_secondary,
  )?;
  Ok(compressed_snark_proof.serialize())
}

/// creates NIVC proof from TLS transcript and [`Manifest`] config
///
/// # Arguments
/// - `manifest` - [`Manifest`] config containing proof and circuit information
/// - `inputs` - TLS transcript inputs
///
/// # Returns
/// - `CompressedSNARKProof` - NIVC proof
///
/// # Details
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
fn construct_request_program_data_and_proof(
  manifest_request: &ManifestRequest,
  inputs: EncryptionInput,
  proving_params: Vec<u8>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  debug!("Setting up request's `PublicParams`... (this may take a moment)");
  let setup_data = construct_setup_data();

  let NivcCircuitInputs { fold_inputs, private_inputs, initial_nivc_input } =
    manifest_request.build_inputs(&inputs);
  let NIVCRom { circuit_data, rom } = manifest_request.build_rom();

  debug!("Generating request's `ProgramData`...");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params,
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input: initial_nivc_input.clone(),
    inputs: (private_inputs, fold_inputs),
    witnesses: vec![vec![F::<G1>::from(0)]],
  }
  .into_online()?
  .into_expanded()?;

  debug!("starting request recursive proving");
  let proof = generate_proof(program_data)?;

  Ok(proof)
}

/// takes TLS transcripts and [`ProvingData`] and generates NIVC [`ProgramData`] for request and
/// response separately
/// - decrypts TLS ciphertext in [`WitnessData`]
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
fn construct_response_program_data_and_proof(
  manifest_response: &ManifestResponse,
  inputs: EncryptionInput,
  proving_params: Vec<u8>,
) -> Result<FoldingProof<Vec<u8>, String>, ClientErrors> {
  debug!("Setting up response's `PublicParams`... (this may take a moment)");
  let setup_data = construct_setup_data();

  let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
    manifest_response.build_inputs(inputs)?;
  let NIVCRom { circuit_data, rom } = manifest_response.build_rom();

  debug!("Generating response's `ProgramData`...");
  let program_data = ProgramData::<Offline, NotExpanded> {
    public_params: proving_params,
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom,
    rom_data: circuit_data,
    initial_nivc_input,
    inputs: (private_inputs, fold_inputs),
    witnesses: vec![vec![F::<G1>::from(0)]],
  }
  .into_online()?
  .into_expanded()?;

  debug!("starting response recursive proving");
  let proof = generate_proof(program_data)?;

  Ok(proof)
}

/// we want to be able to specify somewhere in here what cipher suite to use.
/// Perhapse the config object should have this information.
pub(crate) async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<tls_client2::origo::OrigoConnection, ClientErrors> {
  let root_store = crate::tls::tls_client2_default_root_store();

  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let origo_conn = Arc::new(std::sync::Mutex::new(OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
    tls_client2::ServerName::try_from(config.target_host()?.as_str()).unwrap(),
  )?;

  let client_notary_config = rustls::ClientConfig::builder()
    .with_root_certificates(crate::tls::rustls_default_root_store())
    .with_no_client_auth();

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port)).await?;

  let notary_tls_socket = notary_connector
    .connect(rustls::pki_types::ServerName::try_from(config.notary_host.clone())?, notary_socket)
    .await?;

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);
  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await?;
  let connection_task = tokio::spawn(connection.without_shutdown());

  // TODO build sanitized query
  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/{}?session_id={}&target_host={}&target_port={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      if config.mode == NotaryMode::TEE { "tee" } else { "origo" },
      session_id.clone(),
      config.target_host()?,
      config.target_port()?,
    ))
    .method("GET")
    .header("Host", config.notary_host.clone())
    .header("Connection", "Upgrade")
    .header("Upgrade", "TCP")
    .body(http_body_util::Full::default())
    .unwrap();

  let response = request_sender.send_request(request).await?;
  assert!(response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS);

  // Claim back the TLS socket after the HTTP to TCP upgrade is done
  let hyper::client::conn::http1::Parts { io: notary_tls_socket, .. } = connection_task.await??;

  // TODO notary_tls_socket needs to implement futures::AsyncRead/Write, find a better wrapper here
  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  // Either bind client to TEE TLS connection or plain TLS connection
  let (client_tls_conn, tls_fut) = if config.mode == NotaryMode::TEE {
    let token_verifier = GoogleConfidentialSpaceTokenVerifier::new("audience").await; // TODO pass in as function input
    let tee_tls_connector = TeeTlsConnector::new(token_verifier, "example.com"); // TODO example.com
    let tee_tls_stream = tee_tls_connector.connect(notary_tls_socket).await?;
    crate::tls_client_async2::bind_client(tee_tls_stream.compat(), client)
  } else {
    crate::tls_client_async2::bind_client(notary_tls_socket.compat(), client)
  };

  // TODO: What do with tls_fut? what do with tls_receiver?
  let (tls_sender, _tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await.unwrap();
    let _ = tls_sender.send(result);
  };
  tokio::spawn(handled_tls_fut);

  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await?;

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  tokio::spawn(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()?).await?;

  assert_eq!(response.status(), StatusCode::OK);

  let payload = response.into_body().collect().await?.to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server
  // TODO this closes the TLS Connection, do we want to maybe close the TCP stream instead?
  let mut client_socket = connection_receiver.await??.io.into_inner().into_inner();
  client_socket.close().await?;

  let origo_conn = origo_conn.lock().unwrap().deref().clone();
  Ok(origo_conn)
}
