use std::{
  collections::HashMap,
  io::{BufReader, Cursor},
  path::PathBuf,
  sync::Arc,
};

use arecibo::{provider::Bn256EngineKZG, supernova::RecursiveSNARK};
use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use proofs::{
  circom::witness::load_witness_from_bin_reader, program, ProgramData, WitnessGeneratorType, F, G1,
};
use serde_json::json;
use tls_client2::{CipherSuite, Decrypter2, ProtocolVersion, origo::{OrigoConnection, WitnessData}};
use tls_core::msgs::{base::Payload, codec::Codec, enums::ContentType, message::OpaqueMessage};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use crate::{config, errors, origo::SignBody, Proof};

const AES_GCM_FOLD_R1CS: &str = "proofs/examples/circuit_data/aes-gcm-fold.r1cs";
const AES_GCM_FOLD_WASM: &str = "proofs/examples/circuit_data/aes-gcm-fold_js/aes-gcm-fold.wasm";

pub async fn proxy_and_sign(mut config: config::Config) -> Result<Proof, errors::ClientErrors> {
  let session_id = config.session_id();
  let (sb, witness) = proxy(config.clone(), session_id.clone()).await;

  let sign_data = crate::origo::sign(config.clone(), session_id.clone(), sb, &witness).await;
  let program_data = generate_program_data(&witness).await;

  let (params, proof) = program::run(&program_data);
  let (_pk, _vk, compressed_snark) = program::compress(&params, &proof);
  debug!("data={:?}", compressed_snark);

  Ok(crate::Proof::Origo(proof))
}

// TODO: Dedup origo_native and origo_wasm. The difference is the witness/r1cs preparation.
async fn generate_program_data(witness: &WitnessData) -> ProgramData {
  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: &[u8] = &witness.request.aes_key;
  let iv: &[u8] = &witness.request.aes_iv;

  let mut private_input = HashMap::new();

  let ct: &[u8] = witness.request.ciphertext.as_bytes();
  let sized_key: [u8; 16] = key[..16].try_into().unwrap();
  let sized_iv: [u8; 12] = iv[..12].try_into().unwrap();

  private_input.insert("key".to_string(), serde_json::to_value(&sized_key).unwrap());
  private_input.insert("iv".to_string(), serde_json::to_value(&sized_iv).unwrap());

  let dec = Decrypter2::new(sized_key, sized_iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = dec
    .decrypt_tls13_aes(
      &OpaqueMessage {
        typ:     ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(hex::decode(ct).unwrap()),
      },
      0,
    )
    .unwrap();
  let pt = plaintext.payload.0.to_vec();
  let aad = hex::decode(meta.additional_data.to_owned()).unwrap();
  let mut padded_aad = vec![0; 16 - aad.len()];
  padded_aad.extend(aad);

  // this somehow needs to be nested in this hashmap of values to be under another key called
  // "fold_input" private_input.insert("plainText".to_string(),
  // serde_json::to_value(&pt).unwrap()); private_input.insert("aad".to_string(),
  // serde_json::to_value(&aad).unwrap());

  // TODO: Is padding the approach we want or change to support variable length?
  let janky_padding = pt.len() % 16;
  let mut janky_plaintext_padding = vec![0; janky_padding];
  let rom_len = (pt.len() + janky_padding) / 16;
  janky_plaintext_padding.extend(pt);

  let private_input = json!({
    "private_input": {
      "key": sized_key,
      "iv": sized_iv,
      "fold_input": {
        "plainText": janky_plaintext_padding,
      },
      "aad": padded_aad,
    },
    "r1cs_paths": [AES_GCM_FOLD_R1CS],
    "witness_generator_types": [
      {
          "wasm": {
              "path": AES_GCM_FOLD_WASM,
              "wtns_path": "witness.wtns (unused)"
          }
      }
    ],
    "rom": vec![0; rom_len],
    "initial_public_input": vec![0; 48],
    "witnesses": vec![vec![F::<G1>::from(0)]],
  });

  serde_json::from_value(private_input).unwrap()
}

async fn proxy(config: config::Config, session_id: String) -> (SignBody, WitnessData) {
  let root_store = crate::tls::tls_client2_default_root_store();

  let client_config = tls_client2::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let origo_conn = Arc::new(std::sync::Mutex::new(OrigoConnection::new()));
  let client = tls_client2::ClientConnection::new(
    Arc::new(client_config),
    Box::new(tls_client2::RustCryptoBackend13::new(origo_conn.clone())),
    tls_client2::ServerName::try_from(config.target_host().as_str()).unwrap(),
  )
  .unwrap();

  let client_notary_config = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(crate::tls::rustls_default_root_store())
    .with_no_client_auth();

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
      .await
      .unwrap();

  let notary_tls_socket = notary_connector
    .connect(rustls::ServerName::try_from(config.notary_host.as_str()).unwrap(), notary_socket)
    .await
    .unwrap();

  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(notary_tls_socket).await.unwrap();
  let connection_task = tokio::spawn(connection.without_shutdown());

  // TODO build sanitized query
  let request: Request<Full<Bytes>> = hyper::Request::builder()
    .uri(format!(
      "https://{}:{}/v1/origo?session_id={}&target_host={}&target_port={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      session_id.clone(),
      config.target_host(),
      config.target_port(),
    ))
    .method("GET")
    .header("Host", config.notary_host.clone())
    .header("Connection", "Upgrade")
    .header("Upgrade", "TCP")
    .body(http_body_util::Full::default())
    .unwrap();

  let response = request_sender.send_request(request).await.unwrap();
  assert!(response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS);

  // Claim back the TLS socket after the HTTP to TCP upgrade is done
  let hyper::client::conn::http1::Parts { io: notary_tls_socket, .. } =
    connection_task.await.unwrap().unwrap();

  // TODO notary_tls_socket needs to implement futures::AsyncRead/Write, find a better wrapper here
  let notary_tls_socket = hyper_util::rt::TokioIo::new(notary_tls_socket);

  let (client_tls_conn, tls_fut) =
    tls_client_async2::bind_client(notary_tls_socket.compat(), client);

  // TODO: What do with tls_fut? what do with tls_receiver?
  let (tls_sender, _tls_receiver) = oneshot::channel();
  let handled_tls_fut = async {
    let result = tls_fut.await;
    // Triggered when the server shuts the connection.
    // debug!("tls_sender.send({:?})", result);
    let _ = tls_sender.send(result);
  };
  tokio::spawn(handled_tls_fut);

  let client_tls_conn = hyper_util::rt::TokioIo::new(client_tls_conn.compat());

  let (mut request_sender, connection) =
    hyper::client::conn::http1::handshake(client_tls_conn).await.unwrap();

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    // debug!("connection_sender.send({:?})", result);
    let _ = connection_sender.send(result);
  };
  tokio::spawn(handled_connection_fut);

  let response = request_sender.send_request(config.to_request()).await.unwrap();

  assert_eq!(response.status(), StatusCode::OK);

  let payload = response.into_body().collect().await.unwrap().to_bytes();
  debug!("Response: {:?}", payload);

  // Close the connection to the server
  // TODO this closes the TLS Connection, do we want to maybe close the TCP stream instead?
  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner().into_inner();
  client_socket.close().await.unwrap();

  let server_aes_iv =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_key").unwrap().clone();

  let witness = origo_conn.lock().unwrap().to_witness_data();
  let sb = SignBody {
    hs_server_aes_iv:  hex::encode(server_aes_iv.to_vec()),
    hs_server_aes_key: hex::encode(server_aes_key.to_vec()),
  };

  (sb, witness)
}
