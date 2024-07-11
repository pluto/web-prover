use std::{convert::Infallible, fs, io, sync::Arc};

use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Request, Response};
use hyper_util::{
  rt::{TokioExecutor, TokioIo},
  server::conn::auto::Builder,
};
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  let addr = "127.0.0.1:8080";

  let certs = load_certs("./tests/fixture/mock_server/server-cert.pem")?;
  let key = load_private_key("./tests/fixture/mock_server/server-key.pem")?;

  let listener = TcpListener::bind(addr).await?;

  let mut server_config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| error(e.to_string()))?;
  server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
  let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

  println!("Listening on https://{}", addr);

  loop {
    let (tcp_stream, _) = listener.accept().await?;

    let tls_acceptor = tls_acceptor.clone();

    tokio::task::spawn(async move {
      let tls_stream = match tls_acceptor.accept(tcp_stream).await {
        Ok(tls_stream) => tls_stream,
        Err(err) => {
          println!("failed to perform tls handshake: {err:#}");
          return;
        },
      };

      if let Err(err) = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls_stream), service_fn(response))
        .await
      {
        println!("failed to serve connection: {err:#}");
      }
    });
  }
}

async fn response(
  req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
  match req.uri().path() {
    "/health" => Ok(Response::default()),
    "/bin/1KB" => Ok(Response::new(Full::new(Bytes::from(vec![0; 1024])))),
    "/bin/2KB" => Ok(Response::new(Full::new(Bytes::from(vec![0; 2048])))),
    "/bin/4KB" => Ok(Response::new(Full::new(Bytes::from(vec![0; 4096])))),
    "/bin/8KB" => Ok(Response::new(Full::new(Bytes::from(vec![0; 8192])))),
    "/bin/10KB" => Ok(Response::new(Full::new(Bytes::from(vec![0; 10240])))),
    "/bin/20KB" => Ok(Response::new(Full::new(Bytes::from(vec![0; 20480])))),
    "/timeout" => {
      tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
      Ok(Response::new(Full::new(Bytes::from("Timeout response after 5 seconds"))))
    },
    _ => {
      let mut not_found = Response::new(Full::new(Bytes::from("Not Found")));
      *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
      Ok(not_found)
    },
  }
}

fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
  let certfile =
    fs::File::open(filename).map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
  let mut reader = io::BufReader::new(certfile);
  rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
  let keyfile =
    fs::File::open(filename).map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
  let mut reader = io::BufReader::new(keyfile);
  rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

fn error(err: String) -> io::Error { io::Error::new(io::ErrorKind::Other, err) }
