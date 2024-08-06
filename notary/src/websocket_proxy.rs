use axum::{extract::Query, response::Response};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{debug, info};

use crate::axum_websocket::{WebSocket, WebSocketUpgrade};

#[derive(Deserialize)]
pub struct Target {
  target_host: String,
  target_port: u16,
}

pub async fn proxy(ws: WebSocketUpgrade, query: Query<Target>) -> Response {
  ws.on_upgrade(move |socket| async move {
    // TODO is await here correct?
    handle_connection(socket, &query.target_host, query.target_port).await;
  })
}

pub async fn handle_connection(socket: WebSocket, target_host: &str, target_port: u16) {
  info!("Connecting to target {}:{}", target_host, target_port);
  let mut tcp_stream = TcpStream::connect(format!("{}:{}", target_host, target_port))
    .await
    .expect("Failed to connect to TCP server");
  let (mut tcp_read, mut tcp_write) = tcp_stream.split();
  let (mut ws_sink, mut ws_stream) = socket.into_inner().split();

  let ws_to_tcp = async {
    while let Some(msg) = ws_stream.next().await {
      // TODO refactor below
      match msg {
        // Ok(Message::Text(text)) => {
        //   // Decode base64 encoded text
        //   //   let decoded = base64::decode(&text).expect("Failed to decode base64");
        //   //   tcp_stream.write_all(&decoded).await.expect("Failed to write to TCP stream");
        //   todo!("text message");
        // },
        Ok(Message::Binary(bin)) => {
          tcp_write.write_all(&bin).await.expect("Failed to write to TCP stream");
        },
        Ok(Message::Ping(_)) => {
          todo!("respond with pong?");
        },
        Ok(Message::Pong(_)) => {
          todo!("do we need to implement this?");
        },
        Ok(Message::Text(_)) => {
          panic!("we don't need this");
        },
        Ok(Message::Close(_)) => {
          break;
        },
        Ok(_) => (),
        Err(e) => {
          eprintln!("WebSocket error: {}", e);
          break;
        },
      };
    }
  };

  // TODO fix unwraps and expect's below

  let tcp_to_ws = async {
    let mut tcp_buf = [0; 4096];
    loop {
      let n = tcp_read.read(&mut tcp_buf).await.expect("Failed to read from TCP stream");

      // TODO n == 0 works but is not correct
      // If n is 0, then it can indicate one of two scenarios:
      // This reader has reached its "end of file" and will likely no longer be able to produce
      // bytes. Note that this does not mean that the reader will always no longer be able to
      // produce bytes. The buffer specified was 0 bytes in length.
      //
      // tcp_buf holds encrypted data, we can't introspect a HTTP request to check for ending
      // newlines for example.

      if n == 0 {
        ws_sink.close().await.unwrap(); // TODO fix unwrap
        break;
      }
      let data = &tcp_buf[..n];
      ws_sink.send(Message::Binary(data.to_vec())).await.expect("Failed to send WebSocket message");
    }
  };

  tokio::join!(ws_to_tcp, tcp_to_ws);
}
