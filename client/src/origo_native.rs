use std::{ops::Deref, sync::Arc};

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use proofs::{
  program::{
    self,
    data::{Expanded, NotExpanded, Online, ProgramData},
  },
  F, G1,
};
use tls_client2::origo::{OrigoConnection, WitnessData};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{
  circuits::*, config, config::ProvingData, errors, errors::ClientErrors, origo::SignBody,
  tls::decrypt_tls_ciphertext, Proof,
};

pub async fn proxy_and_sign(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let mut origo_conn = proxy(config.clone(), session_id.clone()).await?;

  let sb = SignBody {
    handshake_server_iv:  hex::encode(
      origo_conn.secret_map.get("Handshake:server_iv").unwrap().clone().to_vec(),
    ),
    handshake_server_key: hex::encode(
      origo_conn.secret_map.get("Handshake:server_key").unwrap().clone().to_vec(),
    ),
  };

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb).await;

  debug!("generating program data!");
  let witness = origo_conn.to_witness_data();
  let (request_program_data, response_program_data) =
    generate_program_data(&witness, config.proving).await?;

  debug!("starting request recursive proving");
  let request_program_output = program::run(&request_program_data)?;

  debug!("starting response recursive proving");
  let response_program_output = program::run(&response_program_data)?;

  debug!("starting request proof compression");
  let request_compressed_verifier =
    program::compress_proof(&request_program_output, &request_program_data.public_params)?;
  let response_compressed_verifier =
    program::compress_proof(&response_program_output, &response_program_data.public_params)?;

  debug!("verification");
  let request_serialized_compressed_verifier = request_compressed_verifier.serialize_and_compress();
  let response_serialized_compressed_verifier =
    response_compressed_verifier.serialize_and_compress();

  // TODO(Sambhav): handle request and response into one proof
  Ok(crate::Proof::Origo((
    request_serialized_compressed_verifier.0,
    response_serialized_compressed_verifier.0,
  )))
}

/// takes TLS transcripts and [`ProvingData`] and generates NIVC [`ProgramData`] for request and
/// response separately
/// - decrypts TLS ciphertext in [`WitnessData`]
/// - generates NIVC ROM from [`Manifest`] config for request and response
/// - get circuit [`SetupData`] containing circuit R1CS and witness generator files according to
///   input sizes
/// - create consolidate [`ProgramData`]
/// - expand private inputs into fold inputs as per circuits
async fn generate_program_data(
  witness: &WitnessData,
  proving: ProvingData,
) -> Result<(ProgramData<Online, Expanded>, ProgramData<Online, Expanded>), ClientErrors> {
  let (request_inputs, response_inputs) = decrypt_tls_ciphertext(witness)?;

  debug!("Setting up `PublicParams`... (this may take a moment)");
  // TODO (Sambhav): this will result in duplicate program setups. eliminate this.
  // TODO (Sambhav): request and response proving can be easily parallelised. evaluate this using
  // rayon.
  let request_setup_data =
    construct_setup_data(&request_inputs.key, request_inputs.plaintext.len());
  let request_public_params = program::setup(&request_setup_data);

  let response_setup_data =
    construct_setup_data(&response_inputs.key, response_inputs.plaintext.len());
  let response_public_params = program::setup(&response_setup_data);

  debug!("Created `PublicParams`!");

  // - construct private inputs and program layout for circuits for TLS request -
  let (request_rom_data, request_rom, request_fold_inputs) =
    proving.manifest.as_ref().unwrap().rom_from_request(request_inputs);
  // - construct private inputs and program layout for circuits for TLS response -
  let (response_rom_data, response_rom, response_fold_inputs) =
    proving.manifest.as_ref().unwrap().rom_from_response(response_inputs);

  // TODO (sambhav): handle response input in a better manner, what if response is 512B
  let request_program_data = ProgramData::<Online, NotExpanded> {
    public_params:      request_public_params,
    setup_data:         request_setup_data,
    rom:                request_rom,
    rom_data:           request_rom_data,
    initial_nivc_input: vec![proofs::F::<G1>::from(0)],
    inputs:             request_fold_inputs,
    witnesses:          vec![vec![F::<G1>::from(0)]],
  }
  .into_expanded();

  let response_program_data = ProgramData::<Online, NotExpanded> {
    public_params:      response_public_params,
    setup_data:         response_setup_data,
    rom:                response_rom,
    rom_data:           response_rom_data,
    initial_nivc_input: vec![proofs::F::<G1>::from(0)],
    inputs:             response_fold_inputs,
    witnesses:          vec![vec![F::<G1>::from(0)]],
  }
  .into_expanded();

  Ok((request_program_data?, response_program_data?))
}

/// we want to be able to specify somewhere in here what cipher suite to use.
/// Perhapse the config object should have this information.
async fn proxy(
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
    .with_safe_defaults()
    .with_root_certificates(crate::tls::rustls_default_root_store())
    .with_no_client_auth();

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
      .await?;

  let notary_tls_socket = notary_connector
    .connect(rustls::ServerName::try_from(config.notary_host.as_str())?, notary_socket)
    .await?;

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await?;
  let connection_task = tokio::spawn(connection.without_shutdown());

  // TODO build sanitized query
  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/origo?session_id={}&target_host={}&target_port={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
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

  let (client_tls_conn, tls_fut) =
    crate::tls_client_async2::bind_client(notary_tls_socket.compat(), client);

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
