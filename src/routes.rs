use std::{collections::HashMap, convert::Infallible};

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
  body::{Bytes, Incoming},
  header::{
    HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION,
    UPGRADE,
  },
  upgrade::Upgraded,
  Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::{
  tungstenite::{handshake::derive_accept_key, protocol::Role},
  WebSocketStream,
};

pub async fn cors_preflight(
  _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
  // TODO
  Ok(
    Response::builder()
      .status(StatusCode::OK)
      .header("Access-Control-Allow-Origin", "*")
      .body(empty())
      .unwrap(),
  )
}

pub async fn not_found(
  _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
  Ok(Response::builder().status(StatusCode::NOT_FOUND).body(empty()).unwrap())
}

// GET /health
pub async fn health(
  _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
  Ok(Response::builder().status(StatusCode::OK).body(full(b"healthy\n".to_vec())).unwrap())
}

// GET /v1
pub async fn v1_websocket(
  mut req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
  // parse ?query params
  let query = if let Some(q) = req.uri().query() {
    q
  } else {
    return Ok(Response::builder().status(StatusCode::UNPROCESSABLE_ENTITY).body(empty()).unwrap());
  };

  let params =
    form_urlencoded::parse(query.as_bytes()).into_owned().collect::<HashMap<String, String>>();

  let target_host: String = if let Some(th) = params.get("target_host") {
    th.to_string()
  } else {
    return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
  };

  let target_port: u16 = if let Some(tp) = params.get("target_port") {
    match tp.parse() {
      Ok(tp) => tp,
      Err(_) => {
        return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
      },
    }
  } else {
    return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
  };

  let upgrade = HeaderValue::from_static("Upgrade");
  let websocket = HeaderValue::from_static("websocket");
  let websocket_version = HeaderValue::from(13);

  let headers = req.headers();

  // Check Connection == Upgrade header
  if let Some(connection) = headers.get(CONNECTION) {
    if connection != upgrade {
      return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
    }
  } else {
    return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
  }

  // Check Upgrade == Websocket header
  if let Some(upgrade) = headers.get(UPGRADE) {
    if upgrade != websocket {
      return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
    }
  } else {
    return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
  }

  // Check Websocket-Version == 13 header
  if let Some(version) = headers.get(SEC_WEBSOCKET_VERSION) {
    if version != websocket_version {
      return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
    }
  } else {
    return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(empty()).unwrap());
  }

  let key = headers.get(SEC_WEBSOCKET_KEY);
  let derived = key.map(|k| derive_accept_key(k.as_bytes()));

  tokio::task::spawn(async move {
    match hyper::upgrade::on(&mut req).await {
      Ok(upgraded) => {
        let upgraded = TokioIo::new(upgraded);
        v1_websocket_handler(
          target_host,
          target_port,
          // TODO configure WebsocketConfig
          WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await,
        )
        .await;
      },
      Err(e) => println!("websocket upgrade error: {}", e), // TODO handle this error better?
    }
  });

  Ok(
    Response::builder()
      .status(StatusCode::SWITCHING_PROTOCOLS)
      .header(CONNECTION, upgrade)
      .header(UPGRADE, websocket)
      .header(SEC_WEBSOCKET_ACCEPT, derived.unwrap())
      .body(empty())
      .unwrap(),
  )
}

async fn v1_websocket_handler(
  target_host: String,
  target_port: u16,
  in_socket: WebSocketStream<TokioIo<Upgraded>>,
) {
  // let mut stream = ws_stream_tungstenite::WsStream::new(ws_stream);

  use std::net::SocketAddr;

  use futures_util::{SinkExt, StreamExt};
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
  };
  use tokio_tungstenite::tungstenite::protocol::Message;

  let target_host = if target_host == "localhost" { "127.0.0.1" } else { &target_host };

  let target_url = format!("{}:{}", target_host, target_port);
  println!("target: {}", target_url);
  let target_addr: SocketAddr = target_url.parse().expect("Invalid address");
  let mut tcp_stream =
    TcpStream::connect(target_addr).await.expect("Failed to connect to TCP server");

  let mut tcp_buf = [0; 4096];

  let (mut ws_sink, mut ws_stream) = in_socket.split();
  loop {
    tokio::select! {
        Some(ws_msg) = ws_stream.next() => {
            let ws_msg = ws_msg.expect("failed to read ws");

            // TODO: dedup me
            if let Message::Binary(data) = ws_msg {
                println!("forward binary message: {:?}", data);
                tcp_stream.write_all(&data).await.expect("failed to write target server");
                let n = tcp_stream.read(&mut tcp_buf).await.expect("failed to read target server");
                println!("received response from server: bytes={:?}, message={:?}", n, tcp_buf[..n].to_vec());
                ws_sink.send(Message::Binary(tcp_buf[..n].to_vec())).await.expect("failed to forward to socket");
            } else if let Message::Text(data) = ws_msg {
                println!("forward text message: {:?}", data);
                tcp_stream.write_all(data.as_bytes()).await.expect("failed to write to server");
                let n = tcp_stream.read(&mut tcp_buf).await.expect("failed to read target server");
                let msg = String::from_utf8(tcp_buf[..n].to_vec()).expect("failed to parse str");
                ws_sink.send(Message::Text(msg)).await.expect("failed to forward to socket");
            } else if let Message::Close(_) = ws_msg {
                ws_sink.close().await.expect("failed to close socket");
                tcp_stream.shutdown().await.expect("failed to close tcp_stream");
            } else {
                println!("receiving data of unhandled format: {:?}", ws_msg);
            }
        },
        else => break,
    }
  }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> { Full::new(chunk.into()).boxed() }

fn empty() -> BoxBody<Bytes, Infallible> { Empty::<Bytes>::new().boxed() }
