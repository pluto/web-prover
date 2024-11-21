use std::{collections::HashMap, sync::Arc};

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use proofs::{
  program::{
    self,
    data::{
      CircuitData, Expanded, FoldInput, InstructionConfig, NotExpanded, Online, ProgramData,
      R1CSType, SetupData, WitnessGeneratorType,
    },
    manifest,
  },
  F, G1,
};
use reqwest::Client;
use serde_json::{json, Value};
use tls_client2::{
  origo::{OrigoConnection, WitnessData},
  CipherSuite, Decrypter, EncryptionKey, ProtocolVersion,
};
use tls_core::msgs::{base::Payload, codec::Codec, enums::ContentType, message::OpaqueMessage};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, trace};

use crate::{
  circuits::*, config, config::ProvingData, errors, errors::ClientErrors, origo::SignBody, Proof,
};

pub async fn proxy_and_sign(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let (sb, witness) = proxy(config.clone(), session_id.clone()).await?;

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb, &witness).await;

  let program_data = generate_program_data(&witness, config.proving).await?;
  let program_output = program::run(&program_data)?;
  let compressed_verifier = program::compress_proof(&program_output, &program_data.public_params)?;
  let serialized_compressed_verifier = compressed_verifier.serialize_and_compress();

  Ok(crate::Proof::Origo(serialized_compressed_verifier.0))
}

// TODO: Dedup origo_native and origo_wasm. The difference is the witness/r1cs preparation.
async fn generate_program_data(
  witness: &WitnessData,
  proving: ProvingData,
) -> Result<ProgramData<Online, Expanded>, ClientErrors> {
  // ----------------------------------------------------------------------------------------------------------------------- //
  // - get AES key, IV -
  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: [u8; 16] = witness.request.aes_key[..16].try_into()?;
  let iv: [u8; 12] = witness.request.aes_iv[..12].try_into()?;
  // ----------------------------------------------------------------------------------------------------------------------- //
  // Get the request ciphertext, request plaintext, and AAD
  debug!("Decoding ciphertext hex...");
  let request_ciphertext = hex::decode(witness.request.ciphertext.as_bytes())?;


  // TODO(WJ 2024-11-21): Currently this will fail since we are getting chacha ciphertext but decrypting with AES
  // need a way to know which one we are using.
  let request_decrypter =
    Decrypter::new(EncryptionKey::AES128GCM(key), iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = request_decrypter.decrypt_tls13_aes(
    &OpaqueMessage {
      typ:     ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_3,
      payload: Payload::new(request_ciphertext.clone()), /* TODO (autoparallel): old way didn't
                                                          * introduce a clone */
    },
    0,
  )?;
  debug!("Finished decrypting ciphertext!");

  let aad = hex::decode(meta.additional_data.to_owned())?;
  let mut padded_aad = vec![0; 16 - aad.len()];
  padded_aad.extend(aad);

  let request_plaintext = plaintext.payload.0.to_vec();
  trace!("Raw request plaintext: {:?}", request_plaintext);
  // -- NOTE: Above is the following:
  // GET https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json HTTP/1.1
  // host: gist.githubusercontent.com
  // accept-encoding: identity
  // connection: close
  // accept: */*
  // ----------------------------------------------------------------------------------------------------------------------- //

  // TODO (Colin): ultimately we want to download the `AuxParams` here and deserialize to setup
  // `PublicParams` alongside of calling `client_side_prover::supernova::get_circuit_shapes` for
  // this next step
  // ----------------------------------------------------------------------------------------------------------------------- //
  // - create program setup (creating new `PublicParams` each time, for the moment) -
  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      R1CSType::Raw(HTTP_NIVC_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_NIVC_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };

  // ----------------------------------------------------------------------------------------------------------------------- //

  // ----------------------------------------------------------------------------------------------------------------------- //
  // - construct private inputs and program layout for AES proof for request -
  debug!("Padding plaintext and ciphertext to nearest 16...");
  let mut nearest_16_padded_plaintext = request_plaintext.clone();
  let mut nearest_16_padded_ciphertext = request_ciphertext.clone();
  let remainder = request_plaintext.len() % 16;
  if remainder != 0 {
    let padding = 16 - remainder;
    nearest_16_padded_plaintext.resize(request_plaintext.len() + padding, 0);
    nearest_16_padded_ciphertext.resize(request_plaintext.len() + padding, 0);
  }
  trace!(
    "Padded plaintext: {:?}\nPadded ciphertext: {:?}",
    nearest_16_padded_plaintext,
    nearest_16_padded_ciphertext
  );

  let (rom_data, rom, fold_input) = proving.manifest.unwrap().rom_from_request(
    &key,
    &iv,
    &padded_aad,
    &nearest_16_padded_plaintext,
    &nearest_16_padded_plaintext,
  );
  // ----------------------------------------------------------------------------------------------------------------------- //

  debug!("Setting up `PublicParams`... (this may take a moment)");
  let public_params = program::setup(&setup_data);
  debug!("Created `PublicParams`!");

  Ok(
    ProgramData::<Online, NotExpanded> {
      public_params,
      setup_data,
      rom,
      rom_data,
      initial_nivc_input: vec![proofs::F::<G1>::from(0)],
      inputs: fold_input,
      witnesses: vec![vec![F::<G1>::from(0)]],
    }
    .into_expanded()?,
  )
}

/// we want to be able to specify somewhere in here what cipher suite to use. 
/// Perhapse the config object should have this information.
async fn proxy(
  config: config::Config,
  session_id: String,
) -> Result<(SignBody, WitnessData), ClientErrors> {
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
    tls_client_async2::bind_client(notary_tls_socket.compat(), client);

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

  let server_aes_iv =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_key").unwrap().clone();

  let witness = origo_conn.lock().unwrap().to_witness_data();
  let sb = SignBody {
    hs_server_aes_iv:  hex::encode(server_aes_iv.to_vec()),
    hs_server_aes_key: hex::encode(server_aes_key.to_vec()),
  };

  Ok((sb, witness))
}
