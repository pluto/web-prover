use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    body::{Bytes, Incoming},
    header::{
        HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION,
        UPGRADE,
    },
    service::service_fn,
    server::conn::http1,
    upgrade::Upgraded,
    {Method, Request, Response, StatusCode},
};
use hyper_util::rt::TokioIo;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    convert::Infallible,
    fs, io,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    tungstenite::{handshake::derive_accept_key, protocol::Role},
    WebSocketStream,
};

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:8070"; // TODO make env var?

    let certs = load_certs("./fixture/certs/server-cert.pem").unwrap();
    let key = load_private_key("./fixture/certs/server-key.pem").unwrap();

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
        (&Method::OPTIONS, "/health") => cors_preflight(req).await,
        (&Method::GET, "/health") => health(req).await,

        // GET /v1 websocket handler
        (&Method::OPTIONS, "/v1") => cors_preflight(req).await,
        (&Method::GET, "/v1") => v1_websocket(req).await,

        // Not found
        _ => not_found(req).await,
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

// TODO: find a better home for below logic. 
pub async fn cors_preflight(
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    // TODO
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .body(empty())
        .unwrap())
}

pub async fn not_found(
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty())
        .unwrap())
}

// GET /health
pub async fn health(
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(full(b"healthy\n".to_vec()))
        .unwrap())
}

// GET /v1
pub async fn v1_websocket(
    mut req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    // parse ?query params
    let query = if let Some(q) = req.uri().query() {
        q
    } else {
        return Ok(Response::builder()
            .status(StatusCode::UNPROCESSABLE_ENTITY)
            .body(empty())
            .unwrap());
    };

    let params = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();

    let target_host: String = if let Some(th) = params.get("target_host") {
        th.to_string()
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty())
            .unwrap());
    };

    let target_port: u16 = if let Some(tp) = params.get("target_port") {
        match tp.parse() {
            Ok(tp) => tp,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(empty())
                    .unwrap());
            }
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty())
            .unwrap());
    };

    let upgrade = HeaderValue::from_static("Upgrade");
    let websocket = HeaderValue::from_static("websocket");
    let websocket_version = HeaderValue::from(13);

    let headers = req.headers();

    // Check Connection == Upgrade header
    if let Some(connection) = headers.get(CONNECTION) {
        if connection != upgrade {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty())
                .unwrap());
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty())
            .unwrap());
    }

    // Check Upgrade == Websocket header
    if let Some(upgrade) = headers.get(UPGRADE) {
        if upgrade != websocket {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty())
                .unwrap());
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty())
            .unwrap());
    }

    // Check Websocket-Version == 13 header
    if let Some(version) = headers.get(SEC_WEBSOCKET_VERSION) {
        if version != websocket_version {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty())
                .unwrap());
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty())
            .unwrap());
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
            }
            Err(e) => println!("websocket upgrade error: {}", e), // TODO handle this error better?
        }
    });

    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, upgrade)
        .header(UPGRADE, websocket)
        .header(SEC_WEBSOCKET_ACCEPT, derived.unwrap())
        .body(empty())
        .unwrap())
}

async fn v1_websocket_handler(
    target_host: String,
    target_port: u16,
    in_socket: WebSocketStream<TokioIo<Upgraded>>,
) {
    // let mut stream = ws_stream_tungstenite::WsStream::new(ws_stream);
    
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Message;
    use tokio::net::TcpStream;
    use std::net::SocketAddr;
    use futures_util::{StreamExt, SinkExt};

    let target_host = if target_host == "localhost" {
        "127.0.0.1"
    } else {
        &target_host
    };
        
    let target_url = format!("{}:{}", target_host, target_port);
    println!("target: {}", target_url);
    let target_addr: SocketAddr = target_url.parse().expect("Invalid address");
    let mut tcp_stream = TcpStream::connect(target_addr).await.expect("Failed to connect to TCP server");

    let mut tcp_buf = [0; 4096];

    let (mut ws_sink, mut ws_stream) = in_socket.split();
    loop {
        tokio::select! {
            Some(ws_msg) = ws_stream.next() => {
                let ws_msg = ws_msg.expect("failed to read ws");

                use hex;

                // TODO: dedup me
                if let Message::Binary(data) = ws_msg {
                    println!("=== forward binary message === bytes={:?}, msg={:?}", data.len(), hex::encode(&data));
                    tcp_stream.write_all(&data).await.expect("failed to write target server");
                    let n = tcp_stream.read(&mut tcp_buf).await.expect("failed to read target server");
                    println!("=== received response from server === bytes={:?}, message={:?}", n, hex::encode(&tcp_buf[..n]));
                    
                    if n == 0 {
                        println!("=== CLOSING SOCKET === bytes={:?}, message={:?}, buf_len={:?}", n, hex::encode(&tcp_buf[..n]), tcp_buf.len());
                        ws_sink.close().await.expect("failed to close socket");
                    } else {
                        ws_sink.send(Message::Binary(tcp_buf[..n].to_vec())).await.expect("failed to forward to socket");
                    }
                } else if let Message::Text(data) = ws_msg {
                    println!("forward text message: {:?}", data);
                    tcp_stream.write_all(data.as_bytes()).await.expect("failed to write to server");
                    let n = tcp_stream.read(&mut tcp_buf).await.expect("failed to read target server");
                    let msg = String::from_utf8(tcp_buf[..n].to_vec()).expect("failed to parse str");
                    ws_sink.send(Message::Text(msg)).await.expect("failed to forward to socket");
                } else if let Message::Close(_) = ws_msg {
                    println!("=== Client sent close message === {:?}", ws_msg);
                    ws_sink.close().await.expect("failed to close socket");
                } else {
                    println!("receiving data of unhandled format: {:?}", ws_msg);
                }
            },
            else => break,
        }
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).boxed()
}

fn empty() -> BoxBody<Bytes, Infallible> {
    Empty::<Bytes>::new().boxed()
}