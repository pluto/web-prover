use std::panic;

use base64::prelude::*;
use client::Config;
use futures::{channel::oneshot, AsyncWriteExt};
use http_body_util::Full;
use hyper::{body::Bytes, Body, Request};
use serde::{Deserialize, Serialize};
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, info, trace};
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
  EnvFilter,
};
use tracing_web::{performance_layer, MakeWebConsoleWriter};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
pub use wasm_bindgen_rayon::init_thread_pool;
use ws_stream_wasm::WsMeta;

#[wasm_bindgen]
pub async fn prover(config: JsValue) -> Result<String, JsValue> {
  panic::set_hook(Box::new(console_error_panic_hook::hook));
  let config: Config = serde_wasm_bindgen::from_value(config).unwrap(); // TODO replace unwrap
  let proof = prover_inner(config)
    .await
    .map_err(|e| JsValue::from_str(&format!("Could not produce proof: {:?}", e)))?;
  serde_json::to_string_pretty(&proof)
    .map_err(|e| JsValue::from_str(&format!("Could not serialize proof: {:?}", e)))
}

#[wasm_bindgen]
pub fn setup_tracing(logging_filter: &str) {
  let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        // .with_thread_ids(true)
        // .with_thread_names(true)
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console
  let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

  let filter_layer = EnvFilter::builder().parse(logging_filter).unwrap_or_default();

  tracing_subscriber::registry().with(filter_layer).with(fmt_layer).with(perf_layer).init(); // Install these as subscribers to tracing events
  debug!("Logging set up")
}

pub async fn prover_inner(config: Config) -> Result<TlsProof, client::errors::ClientErrors> {
  let target_url = Url::parse(&config.target_url)?;

  let target_host = target_url.host_str().expect("Invalid `target_url` host!");
  assert!(target_url.scheme() == "https");

  let target_port = target_url.port_or_known_default().expect("Target has an unknown port!");

  let notary_wss_url = format!("wss://{}:{}/v1/tlsnotary", config.notary_host, config.notary_port);

  let (_, notary_ws_stream) = WsMeta::connect(notary_wss_url, None).await.unwrap();
  let notary_ws_stream_into = notary_ws_stream.into_io();

  let root_store = client::default_root_store(); // TODO lot of memory allocation happening here. maybe add this to shared state?

  let mut prover_config = ProverConfig::builder();
  let session_id = "c655ee6e-fad7-44c3-8884-5330287982a8"; // TODO random hardcoded UUID4. notary does not need it anymore.
  prover_config.id(session_id).server_dns(target_host).root_cert_store(root_store);
  prover_config.max_transcript_size(
    config.notarization_session_request.max_sent_data.unwrap()
      + config.notarization_session_request.max_recv_data.unwrap(),
  ); // TODO unwrap
  let prover_config = prover_config.build()?;

  let prover = Prover::new(prover_config).setup(notary_ws_stream_into).await.unwrap();

  let ws_query = url::form_urlencoded::Serializer::new(String::new())
    .extend_pairs([("target_host", target_host), ("target_port", &target_port.to_string())])
    .finish();

  let (_, client_ws_stream) =
    WsMeta::connect(format!("{}?{}", config.websocket_proxy_url, ws_query), None).await.unwrap();
  let client_ws_stream_into = client_ws_stream.into_io();

  let (mpc_tls_connection, prover_fut) = prover.connect(client_ws_stream_into).await.unwrap();

  let (prover_sender, prover_receiver) = oneshot::channel();
  let handled_prover_fut = async {
    let result = prover_fut.await;
    let _ = prover_sender.send(result);
  };
  spawn_local(handled_prover_fut);

  let (mut request_sender, connection) =
    hyper::client::conn::handshake(mpc_tls_connection.compat()).await.unwrap();

  let (connection_sender, connection_receiver) = oneshot::channel();
  let connection_fut = connection.without_shutdown();
  let handled_connection_fut = async {
    let result = connection_fut.await;
    let _ = connection_sender.send(result);
  };
  spawn_local(handled_connection_fut);

  let mut request = Request::builder().method(config.target_method.as_str()).uri(config.target_url);

  let headers = request.headers_mut().unwrap();

  for (key, value) in config.target_headers {
    headers.append(
      hyper::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
      value.parse().unwrap(),
    );
  }

  headers.insert("Host", target_host.parse().unwrap());
  headers.insert("Accept-Encoding", "identity".parse().unwrap());
  headers.insert("Connection", "close".parse().unwrap());

  if headers.get("Accept").is_none() {
    headers.insert("Accept", "*/*".parse().unwrap());
  }

  let body = if config.target_body.is_empty() {
    Body::empty()
  } else {
    Body::from(BASE64_STANDARD.decode(config.target_body).unwrap())
  };

  let request = request.body(body).unwrap();

  match request_sender.send_request(request).await {
    Ok(response) => {
      let is_success = response.status().is_success();
      let _payload = response.into_body();

      debug!("Response:\n{:?}", _payload);

      assert!(is_success); // status is 200-299

      debug!("Request OK");
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO */
    Err(e) => panic!("{:?}", e),
  };

  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner();
  client_socket.close().await.unwrap();

  let prover = prover_receiver.await.unwrap().unwrap();
  client::tlsnotary_notarize(prover).await
}
