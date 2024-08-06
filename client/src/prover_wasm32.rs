use std::{ops::Range, panic, time::Duration};

use elliptic_curve::pkcs8::DecodePublicKey;
use futures::{channel::oneshot, AsyncWriteExt};
use hyper::{body::to_bytes, Body, Request, StatusCode};
use js_sys::{Array, JSON};
use strum::EnumMessage;
use strum_macros;
use tlsn_core::proof::{SessionProof, TlsProof};
use tlsn_prover::tls::{
  state::{Closed, Notarize},
  Prover, ProverConfig,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing_subscriber::{
  fmt::{format::Pretty, time::UtcTime},
  prelude::*,
};
use tracing_web::{performance_layer, MakeConsoleWriter};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{spawn_local, JsFuture};
pub use wasm_bindgen_rayon::init_thread_pool;
use web_sys::{Headers, Request as WebsysRequest, RequestInit, RequestMode, Response};
use web_time::Instant;
use ws_stream_wasm::*;

use crate::{send_request, Config};

// uses websockets to connect to notary and websocket proxy
pub async fn setup_connection(config: &mut Config) -> Prover<Closed> {
  let session_id = config.session_id();

  let root_store = default_root_store();

  let prover_config = ProverConfig::builder()
    .id(session_id.clone())
    .server_dns(config.target_host())
    .root_cert_store(root_store)
    .max_transcript_size(
      config.notarization_session_request.max_sent_data.unwrap()
        + config.notarization_session_request.max_recv_data.unwrap(),
    )
    .build()
    .unwrap();

  let wss_url = format!(
    "wss://{}:{}/v1/tlsnotary?session_id={}",
    config.notary_host, config.notary_port, session_id.clone(),
  );

  let (_, notary_ws_stream) = WsMeta::connect(wss_url, None).await.unwrap();
  let notary_ws_stream_into = notary_ws_stream.into_io();

  let prover = Prover::new(prover_config).setup(notary_ws_stream_into).await.unwrap();

  let ws_query = url::form_urlencoded::Serializer::new(String::new())
    .extend_pairs([
      ("target_host", config.target_host()),
      ("target_port", config.target_port().to_string()),
    ])
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

  send_request(
    request_sender,
    config.target_method.clone(),
    config.target_url.clone(),
    config.target_headers.clone(),
    config.target_body.clone(),
  )
  .await;

  let mut client_socket = connection_receiver.await.unwrap().unwrap().io.into_inner();
  client_socket.close().await.unwrap();

  prover_receiver.await.unwrap().unwrap()
}

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

/// Default root store using mozilla certs.
fn default_root_store() -> tls_client::RootCertStore {
  let mut root_store = tls_client::RootCertStore::empty();
  root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
      ta.subject.as_ref(),
      ta.subject_public_key_info.as_ref(),
      ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
    )
  }));

  #[cfg(feature = "notary_ca_cert")]
  {
    debug!("notary_ca_cert feature enabled");
    let certificate = pki_types::CertificateDer::from(NOTARY_CA_CERT.to_vec());
    let (added, _) = root_store.add_parsable_certificates(&[certificate.to_vec()]); // TODO there is probably a nicer way
    assert_eq!(added, 1); // TODO there is probably a better way
  }

  root_store
}
