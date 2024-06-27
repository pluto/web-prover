use std::{convert::Infallible, fs, io, sync::Arc};

use http_body_util::combinators::BoxBody;
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use notary::routes;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:8070"; // TODO make env var?
    let certs = load_certs("fixture/notary/server-cert.pem").unwrap();
    let key = load_private_key("fixture/notary/server-key.pem").unwrap();

    let listener = TcpListener::bind(addr).await.unwrap();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    println!("Listening on https://{}", addr);

    loop {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let tls_acceptor = tls_acceptor.clone();

        tokio::task::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    println!("failed to perform tls handshake: {err:#}");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = service_fn(handle_request);
            let conn = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades();
            if let Err(err) = conn.await {
                println!("failed to serve connection: {err:#}");
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // GET /health
        (&Method::OPTIONS, "/health") => routes::cors_preflight(req).await,
        (&Method::GET, "/health") => routes::health(req).await,

        // GET /v1 websocket handler
        (&Method::OPTIONS, "/v1") => routes::cors_preflight(req).await,
        (&Method::GET, "/v1") => routes::v1_websocket(req).await,

        // Not found
        _ => routes::not_found(req).await,
    }
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

// TODO: Start exploring inner memory ciphertext logging
