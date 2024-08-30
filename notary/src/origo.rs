use std::{
  io::{Cursor, Read},
  sync::{Arc, Mutex},
  time::SystemTime,
};

use axum::{
  extract::{self, Query, State},
  response::Response,
  Json,
};
use base64::Engine;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use p256::ecdsa::{signature::SignerMut, Signature};
use serde::{Deserialize, Serialize};
use tls_client2::tls_core::msgs::{base::Payload, message::OpaqueMessage};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
  axum_websocket::WebSocket,
  tlsn::{NotaryServerError, ProtocolUpgrade},
  OrigoSession, SharedState,
};

#[derive(Deserialize)]
pub struct SignQuery {
  session_id: String,
}

#[derive(Serialize)]
pub struct SignReply {
  signature: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SignBody {
  server_aes_iv:  String,
  server_aes_key: String,
}

pub async fn sign(
  query: Query<SignQuery>,
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<SignBody>,
) -> Json<SignReply> {
  let session = state.origo_sessions.lock().unwrap().get(&query.session_id).unwrap().clone();

  // TODO transform session and sign it

  println!("\n\n{}\n\n", hex::encode(&session.request));
  extract_tls_handshake(&session.request, payload);

  let signature: Signature = state.notary_signing_key.clone().sign(&[1, 2, 3]); // TODO what do you want to sign?
  let signature_raw = hex::encode(signature.to_der().as_bytes());

  let response = SignReply { signature: signature_raw };

  Json(response)
}

use base64::prelude::BASE64_STANDARD;

fn extract_tls_handshake(bytes: &[u8], payload: SignBody) {
  dbg!(payload.server_aes_key.clone(), payload.server_aes_iv.clone());

  let server_aes_key = BASE64_STANDARD.decode(payload.server_aes_key).unwrap();
  let server_aes_iv = BASE64_STANDARD.decode(payload.server_aes_iv).unwrap();

  let mut cursor = Cursor::new(bytes);

  let mut seq = 0;
  let mut skip = 1;
  while cursor.position() < bytes.len() as u64 {
    match tls_parser::parse_tls_raw_record(&cursor.get_ref()[cursor.position() as usize..]) {
      Ok((_, record)) => {
        println!("{}", record.hdr.record_type);

        // let (r, x) = tls_parser::parse_tls_record_with_header(&cursor.get_ref()[cursor.position()
        // as usize..], &record.hdr).unwrap(); let header_len = r.len();

        // println!("Handshake:\n\n{}\n\n", hex::encode(record.data));

        if record.hdr.record_type == tls_parser::TlsRecordType::ApplicationData {
          //   // record.data
          if skip > 0 {
            skip = skip - 1;
            println!("skip");
            let record_length = 5 + record.hdr.len; // 5 is record header length
            cursor.set_position(cursor.position() + record_length as u64);
            continue;
          }
          println!("go for it");

          let d = tls_client2::Decrypter2::new(
            server_aes_key[..16].try_into().unwrap(),
            server_aes_iv[..12].try_into().unwrap(),
            tls_client2::CipherSuite::TLS13_AES_128_CCM_SHA256,
          );

          println!("Record data:\n{:?}\n", hex::encode(record.data.to_vec()));
          let msg = OpaqueMessage {
            typ:     tls_client2::tls_core::msgs::enums::ContentType::ApplicationData,
            version: tls_client2::ProtocolVersion::TLSv1_2,
            payload: Payload(record.data.to_vec()),
          };

          match d.decrypt_tls13_aes(&msg, seq) {
            Ok((plain_message, meta)) => {
              panic!("Plain Message: {:?}", plain_message);
            },
            Err(e) => {
              println!("not working: {:?}", e);
            },
          }

          //   // tls/tls-client/src/backend/standard13.rs make_nonce(iv: [u8; 12], seq: u64) ->
          // [u8;

          // seq += 1;
        }

        let record_length = 5 + record.hdr.len; // 5 is record header length
        cursor.set_position(cursor.position() + record_length as u64);
      },
      Err(e) => println!("{:?}", e),
    }
  }
}

//   /// Derive an encrypter from the given keys
//   pub fn get_encrypter(&self, keys: &TlsKeys) -> Encrypter {
//     Encrypter::new(
//         keys.client_key.buf[..16].try_into().unwrap(),
//         keys.client_iv.buf[..12].try_into().unwrap(),
//         self.cipher_suite.unwrap().suite(),
//     )
// }

// /// Derive an decrypter from the given keys
// pub fn get_decrypter(&self, keys: &TlsKeys) -> Decrypter {
//     Decrypter::new(
//         keys.server_key.buf[..16].try_into().unwrap(),
//         keys.server_iv.buf[..12].try_into().unwrap(),
//         self.cipher_suite.unwrap().suite(),
//     )
// }

#[derive(Deserialize)]
pub struct NotarizeQuery {
  session_id:  String,
  target_host: String,
  target_port: u16,
}

pub async fn proxy(
  protocol_upgrade: ProtocolUpgrade,
  query: Query<NotarizeQuery>,
  State(state): State<Arc<SharedState>>,
) -> Response {
  let session_id = query.session_id.clone();

  debug!("Starting notarize with ID: {}", session_id);

  match protocol_upgrade {
    ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| {
      websocket_notarize(
        socket,
        session_id,
        query.target_host.clone(),
        query.target_port.clone(),
        state,
      )
    }),
    ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| {
      tcp_notarize(stream, session_id, query.target_host.clone(), query.target_port.clone(), state)
    }),
  }
}

pub async fn websocket_notarize(
  socket: WebSocket,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to websocket connection");
  let stream = WsStream::new(socket.into_inner()).compat();
  match proxy_service(stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using websocket!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using websocket: {err}");
    },
  }
}

pub async fn tcp_notarize(
  stream: TokioIo<Upgraded>,
  session_id: String,
  target_host: String,
  target_port: u16,
  state: Arc<SharedState>,
) {
  debug!("Upgraded to tcp connection");
  match proxy_service(stream, &session_id, &target_host, target_port, state).await {
    Ok(_) => {
      info!(?session_id, "Successful notarization using tcp!");
    },
    Err(err) => {
      error!(?session_id, "Failed notarization using tcp: {err}");
    },
  }
}

pub async fn proxy_service<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
  mut socket: S,
  session_id: &str,
  target_host: &str,
  target_port: u16,
  state: Arc<SharedState>,
) -> Result<(), NotaryServerError> {
  debug!(?session_id, "Starting notarization...");

  info!("Connecting to target {}:{}", target_host, target_port);
  let mut tcp_stream = TcpStream::connect(format!("{}:{}", target_host, target_port))
    .await
    .expect("Failed to connect to TCP server");

  let (mut tcp_read, mut tcp_write) = tcp_stream.split();

  let (mut socket_read, mut socket_write) = tokio::io::split(socket);

  let mut request_buf = Arc::new(Mutex::new(vec![0u8; 0]));
  let mut response_buf = vec![0u8; 0];

  let client_to_server = async {
    // tokio::io::copy(&mut socket_read, &mut tcp_write).await.unwrap();

    let mut buf = [0; 4096];
    loop {
      debug!("read1");
      let n = socket_read.read(&mut buf).await.unwrap();
      if n == 0 {
        debug!("close client_to_server");
        break;
      }
      if n > 0 {
        let data = &buf[..n];
        debug!("write to server");
        tcp_write.write_all(data).await.unwrap();
        request_buf.lock().unwrap().extend(data);
      }
    }
  };

  let server_to_client = async {
    // tokio::io::copy(&mut tcp_read, &mut socket_write).await.unwrap();

    let mut buf = [0; 4096];
    loop {
      debug!("read2");
      let n = tcp_read.read(&mut buf).await.unwrap();
      if n == 0 {
        debug!("close server_to_client");
        break;
      }
      if n > 0 {
        let data = &buf[..n];
        debug!("write to client");
        socket_write.write_all(data).await.unwrap();
        request_buf.lock().unwrap().extend(data);
      }
    }
  };

  // client_to_server.await;
  // server_to_client.await;

  tokio::join!(client_to_server, server_to_client);

  state.origo_sessions.lock().unwrap().insert(session_id.to_string(), OrigoSession {
    request:   request_buf.lock().unwrap().to_vec(),
    response:  response_buf,
    timestamp: SystemTime::now(),
  });

  // let r = tls_parser::parse_tls_raw_record(&request_buf).unwrap();
  // dbg!(r.1.hdr.record_type);
  // dbg!(r);

  // send from socket to tcp_stream, then return from tcp_stream to socket

  //  TokioIo::new(socket)

  // TODO better error handling
  // tokio::io::copy_bidirectional(&mut socket, &mut tcp_stream).await.unwrap();

  // let (r, w) = tcp_stream.split();

  // tokio::io::copy(&mut socket, &mut tcp_stream).await.unwrap();
  // tokio::io::copy(&mut socket, &mut tcp_socketait.unwrtcp_stream

  Ok(())
}
