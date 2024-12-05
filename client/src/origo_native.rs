use core::str;
use std::{collections::HashMap, io, ops::Deref, sync::Arc};

use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use jsonwebtoken::{
  decode, decode_header, encode,
  jwk::{AlgorithmParameters, JwkSet},
  Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tls_client2::{
  origo::{OrigoConnection, WitnessData},
  CipherSuite, Decrypter2, ProtocolVersion,
};
use tls_core::msgs::{base::Payload, codec::Codec, enums::ContentType, message::OpaqueMessage};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::{
  circuits::*, config, config::ProvingData, errors, errors::ClientErrors, origo::SignBody, Proof,
};

const JSON_MAX_ROM_LENGTH: usize = 35;

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
  // - get AES key, IV, request ciphertext, request plaintext, and AAD -
  debug!("key_as_string: {:?}, length: {}", witness.request.aes_key, witness.request.aes_key.len());
  debug!("iv_as_string: {:?}, length: {}", witness.request.aes_iv, witness.request.aes_iv.len());

  let key: [u8; 16] = witness.request.aes_key[..16].try_into()?;
  let iv: [u8; 12] = witness.request.aes_iv[..12].try_into()?;
  let ct: &[u8] = witness.request.ciphertext.as_bytes();

  let dec = Decrypter2::new(key, iv, CipherSuite::TLS13_AES_128_GCM_SHA256);
  let (plaintext, meta) = dec.decrypt_tls13_aes(
    &OpaqueMessage {
      typ:     ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_3,
      payload: Payload::new(hex::decode(ct)?),
    },
    0,
  )?;
  let pt = plaintext.payload.0.to_vec();
  let aad = hex::decode(meta.additional_data.to_owned())?;
  let mut padded_aad = vec![0; 16 - aad.len()];
  padded_aad.extend(aad);
  // ----------------------------------------------------------------------------------------------------------------------- //

  // TODO (Colin): ultimately we want to download the `AuxParams` here and deserialize to setup
  // `PublicParams` alongside of calling `client_side_prover::supernova::get_circuit_shapes` for
  // this next step
  // ----------------------------------------------------------------------------------------------------------------------- //
  // - create program setup (creating new `PublicParams` each time, for the moment) -
  let setup_data = SetupData {
    r1cs_types:              vec![
      R1CSType::Raw(AES_GCM_R1CS.to_vec()),
      R1CSType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_R1CS.to_vec()),
      R1CSType::Raw(HTTP_LOCK_HEADER_R1CS.to_vec()),
      R1CSType::Raw(HTTP_BODY_MASK_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_OBJECT_R1CS.to_vec()),
      R1CSType::Raw(JSON_MASK_ARRAY_INDEX_R1CS.to_vec()),
      R1CSType::Raw(EXTRACT_VALUE_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(AES_GCM_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_PARSE_AND_LOCK_START_LINE_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_LOCK_HEADER_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_BODY_MASK_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_OBJECT_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_MASK_ARRAY_INDEX_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(EXTRACT_VALUE_GRAPH.to_vec()),
    ],
    max_rom_length:          JSON_MAX_ROM_LENGTH,
  };

  // ----------------------------------------------------------------------------------------------------------------------- //

  // ----------------------------------------------------------------------------------------------------------------------- //
  // - construct private inputs and program layout for AES proof -
  let mut private_input = HashMap::new();
  private_input.insert("key".to_string(), serde_json::to_value(&key)?);
  private_input.insert("iv".to_string(), serde_json::to_value(&iv)?);

  // TODO: Is padding the approach we want or change to support variable length?
  let janky_padding = if pt.len() % 16 != 0 { 16 - pt.len() % 16 } else { 0 };
  let mut janky_plaintext_padding = vec![0; janky_padding];
  let rom_len = (pt.len() + janky_padding) / 16;
  janky_plaintext_padding.extend(pt);

  let (rom_data, rom) = proving.manifest.unwrap().rom_from_request(
    &key,
    &iv,
    &padded_aad,
    janky_plaintext_padding.len(),
  );
  let aes_instr = String::from("AES_GCM_1");

  // TODO (Sambhav): update fold input from manifest
  let inputs = HashMap::from([(aes_instr.clone(), FoldInput {
    value: HashMap::from([(
      String::from("plainText"),
      janky_plaintext_padding.iter().map(|val| json!(val)).collect::<Vec<Value>>(),
    )]),
  })]);

  let mut initial_input = vec![];
  initial_input.extend(janky_plaintext_padding.iter());
  initial_input.resize(TOTAL_BYTES_ACROSS_NIVC, 0);
  let final_input: Vec<u64> = initial_input.into_iter().map(u64::from).collect();
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
      initial_nivc_input: final_input.to_vec(),
      inputs,
      witnesses: vec![vec![F::<G1>::from(0)]],
    }
    .into_expanded()?,
  )
}

pub async fn proxy(
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
    .with_custom_certificate_verifier(SkipServerVerification::new()) // TODO
    // .with_root_certificates(crate::tls::rustls_default_root_store())
    .with_no_client_auth();

  let notary_connector =
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
      .await?;

  let notary_tls_socket = notary_connector
    .connect(rustls::ServerName::try_from(config.notary_host.as_str())?, notary_socket)
    .await?;

  let certs = notary_tls_socket.get_ref().1.peer_certificates().unwrap();
  let certs_fingerprint = stable_certs_fingerprint(&certs);
  dbg!(certs_fingerprint);

  let key_material = match export_key_material_middleware(
    &notary_tls_socket,
    32,
    b"EXPORTER-pluto-notary",
    Some(b"tee"),
  ) {
    Ok(key_material) => key_material,
    Err(err) => panic!("{:?}", err), // TODO panic here?!
  };

  dbg!(hex::encode(key_material.clone()));

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

  let response = request_sender.send_request(request).await.unwrap();

  // TODO: get the attestion token from response header (or body?)
  let tee_token = response.headers().get("x-pluto-notary-tee-token").unwrap().to_str().unwrap();
  dbg!(tee_token);

  #[derive(Debug, Serialize, Deserialize)]
  struct Claims {
    sub:       String,
    eat_nonce: String, // Actually, should be string array
  }

  let header = decode_header(tee_token).unwrap();
  let alg = header.alg;
  if alg != Algorithm::RS256 {
    panic!("unsupported JWT alg")
  }

  let mut validation = Validation::new(Algorithm::RS256);
  validation.validate_exp = true;

  // OIDC flow ...
  // https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
  // https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com
  let jwks_request = reqwest::get(
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
  )
  .await
  .unwrap();
  let jwks = jwks_request.bytes().await.unwrap();

  let jwks: JwkSet = serde_json::from_str(str::from_utf8(&jwks).unwrap()).unwrap();
  let header = decode_header(tee_token).unwrap();

  let Some(kid) = header.kid else {
    panic!("Token doesn't have a `kid` header field");
  };

  let Some(jwk) = jwks.find(&kid) else {
    panic!("No matching JWK found for the given kid");
  };

  let decoding_key = match &jwk.algorithm {
    AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap(),
    _ => unreachable!("algorithm should be a RSA in this example"),
  };

  let validation = {
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&["https://notary.pluto.xyz"]);
    validation.validate_exp = true;
    validation
  };

  let decoded_token = decode::<JwtPayload>(tee_token, &decoding_key, &validation).unwrap();
  dbg!(decoded_token.clone());

  assert_eq!(decoded_token.claims.eat_nonce, hex::encode(key_material.clone()));

  // PKI flow... (broken)
  // key:
  // https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
  // https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt
  // https://github.com/GoogleCloudPlatform/confidential-space/blob/main/codelabs/health_data_analysis_codelab/src/uwear/workload.go#L84
  //
  // let cert_request = reqwest::get(
  //   "https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt",
  // )
  // .await
  // .unwrap();
  // let cert = cert_request.bytes().await.unwrap();
  // let decoding_key = &DecodingKey::from_rsa_pem(&cert).unwrap();
  // let token_data = decode::<Claims>(tee_token, decoding_key, &validation).unwrap();
  // dbg!(token_data);

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
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_iv").unwrap().clone();
  let server_aes_key =
    origo_conn.lock().unwrap().secret_map.get("Handshake:server_aes_key").unwrap().clone();

  let witness = origo_conn.lock().unwrap().to_witness_data();
  let sb = SignBody {
    hs_server_aes_iv:  hex::encode(server_aes_iv.to_vec()),
    hs_server_aes_key: hex::encode(server_aes_key.to_vec()),
  };

  Ok((sb, witness))
}

fn export_key_material_middleware(
  tls_stream: &TlsStream<TcpStream>,
  length: usize,
  label: &[u8],
  context: Option<&[u8]>,
) -> Result<Vec<u8>, io::Error> {
  let rustls_conn = tls_stream.get_ref().1;

  if rustls_conn.is_handshaking() {
    return Err(io::Error::new(io::ErrorKind::Other, "TLS connection is still handshaking"));
  }

  let mut output = vec![0u8; length];
  rustls_conn.export_keying_material(&mut output, label, context).map_err(|err| {
    io::Error::new(io::ErrorKind::Other, format!("Failed to export keying material: {err}"))
  })?;

  Ok(output)
}

struct SkipServerVerification;

impl SkipServerVerification {
  fn new() -> std::sync::Arc<Self> { std::sync::Arc::new(Self) }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::Certificate,
    _intermediates: &[rustls::Certificate],
    _server_name: &rustls::ServerName,
    _scts: &mut dyn Iterator<Item = &[u8]>,
    _ocsp_response: &[u8],
    _now: std::time::SystemTime,
  ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
    Ok(rustls::client::ServerCertVerified::assertion())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtPayload {
  aud:                     String,
  exp:                     u64,
  iat:                     u64,
  iss:                     String,
  nbf:                     u64,
  sub:                     String,
  eat_nonce:               String,
  eat_profile:             String,
  secboot:                 bool,
  oemid:                   u32,
  hwmodel:                 String,
  swname:                  String,
  swversion:               Vec<String>,
  attester_tcb:            Vec<String>,
  dbgstat:                 String,
  submods:                 SubModules,
  google_service_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubModules {
  confidential_space: ConfidentialSpace,
  container:          Container,
  gce:                Gce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfidentialSpace {
  monitoring_enabled: MonitoringEnabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitoringEnabled {
  memory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Container {
  image_reference: String,
  image_digest:    String,
  restart_policy:  String,
  image_id:        String,
  env:             HashMap<String, String>,
  args:            Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gce {
  zone:           String,
  project_id:     String,
  project_number: String,
  instance_name:  String,
  instance_id:    String,
}

use sha2::{Digest, Sha256};

fn stable_certs_fingerprint(certs: &[rustls::Certificate]) -> String {
  let mut sorted_certs: Vec<&rustls::Certificate> = certs.iter().collect();
  sorted_certs.sort_by(|a, b| a.0.cmp(&b.0));

  let mut hasher = Sha256::new();
  for cert in sorted_certs {
    hasher.update(&cert.0);
  }

  hex::encode(hasher.finalize())
}
