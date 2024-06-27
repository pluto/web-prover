use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::convert::Infallible;
use std::sync::Arc;
use std::{fs, io};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:8080";

    let certs = load_certs("fixture/mock_server/server-cert.pem")?;
    let key = load_private_key("fixture/mock_server/server-key.pem")?;

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
                }
            };

            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service_fn(hello))
                .await
            {
                println!("failed to serve connection: {err:#}");
            }
        });
    }
}

async fn hello(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    println!("Request: {:?}, Responding.", req.body());
    Ok(Response::new(Full::new(Bytes::from("Hello, World!\n"))))
}

fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
