use std::{
  io::{self, Read, Write},
  net::TcpStream,
  pin::Pin,
  sync::Arc,
};

use futures::{sink::SinkExt, stream::StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use ws_stream_wasm::WsStream;

pub fn foo(mut ws_stream: WsStream) -> WsStream {
  let config = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_custom_certificate_verifier(SkipServerVerification::new())
    .with_no_client_auth();

  let server_name = "localhost".try_into().unwrap();
  let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();

  let io = ws_stream.into_io().compat();
  let mut wrapped = IoStreamWrapper::new(io);
  let mut tls_stream = rustls::Stream::new(&mut conn, &mut wrapped);

  panic!("oh oh")
}

pub struct IoStreamWrapper<S> {
  inner: S,
}

impl<S> IoStreamWrapper<S> {
  pub fn new(inner: S) -> Self { IoStreamWrapper { inner } }
}

impl<S> Read for IoStreamWrapper<S>
where S: AsyncRead + Unpin
{
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    futures::executor::block_on(async {
      Pin::new(&mut self.inner).read(buf).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    })
  }
}

impl<S> Write for IoStreamWrapper<S>
where S: AsyncWrite + Unpin
{
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    futures::executor::block_on(async {
      Pin::new(&mut self.inner)
        .write(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    })
  }

  fn flush(&mut self) -> io::Result<()> {
    futures::executor::block_on(async {
      Pin::new(&mut self.inner).flush().await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    })
  }
}

pub struct SkipServerVerification;

impl SkipServerVerification {
  pub fn new() -> std::sync::Arc<Self> { std::sync::Arc::new(Self) }
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
    // TODO check server name
    Ok(rustls::client::ServerCertVerified::assertion())
  }
}
