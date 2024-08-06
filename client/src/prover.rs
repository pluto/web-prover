use std::{
  backtrace::Backtrace,
  collections::HashMap,
  ffi::{CStr, CString},
  io::{BufReader, Cursor},
  os::raw::c_char,
  panic::{self, AssertUnwindSafe},
  sync::Arc,
};

use base64::prelude::*;
use futures::AsyncWriteExt;
use hyper::client::conn::Parts;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{
  state::{Closed, Notarize},
  Prover, ProverConfig,
};
use tokio::{net::TcpStream, runtime};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use url::Url;

use crate::{send_request, Config};

// uses websocket to connect to notary
// TODO decide if that means it's using the websocket proxy as well?
// #[cfg(feature = "websocket")]
// pub async fn setup_connection(_config: &mut Config) -> Prover<Closed> {
//   todo!("feature websocket enabled but not implemented for non-wasm target");
// }

// uses raw TCP socket to connect to notary
// #[cfg(not(feature = "websocket"))]
pub async fn setup_connection(config: &mut Config) -> Prover<Closed> {
  let root_store = default_root_store();

  let client_notary_config = ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  let prover_config = ProverConfig::builder()
    .id(config.session_id())
    .server_dns(config.target_host())
    .max_transcript_size(
      config.notarization_session_request.max_sent_data.unwrap()
        + config.notarization_session_request.max_recv_data.unwrap(),
    )
    .build()
    .unwrap();

  let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

  let notary_socket =
    tokio::net::TcpStream::connect((config.notary_host.clone(), config.notary_port.clone()))
      .await
      .unwrap();

  let notary_tls_socket = notary_connector
				// Require the domain name of notary server to be the same as that in the server cert
				.connect(
					rustls::ServerName::try_from(config.notary_host.as_str()).unwrap(),
					notary_socket,
				) // TODO make this a config
				.await
				.unwrap();

  // TODO remove this - it's not used?
  // Attach the hyper HTTP client to the notary TLS connection to send request to the /session
  // endpoint to configure notarization and obtain session id
  //   let (mut request_sender, connection) =
  // hyper::client::conn::handshake(notary_tls_socket).await.unwrap();
  // Spawn the HTTP task to be run concurrently
  //   let connection_task = tokio::spawn(connection.without_shutdown());
  // Claim back the TLS socket after HTTP exchange is done
  //   let Parts { io: notary_tls_socket, .. } = connection_task.await.unwrap().unwrap();

  let prover = Prover::new(prover_config).setup(notary_tls_socket.compat()).await.unwrap();

  let client_socket =
    tokio::net::TcpStream::connect((config.target_host(), config.target_port())).await.unwrap();

  let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

  let prover_task = tokio::spawn(prover_fut);

  let (request_sender, connection) =
    hyper::client::conn::handshake(mpc_tls_connection.compat()).await.unwrap();

  let connection_task = tokio::spawn(connection.without_shutdown());

  send_request(
    request_sender,
    config.target_method.clone(),
    config.target_url.clone(),
    config.target_headers.clone(),
    config.target_body.clone(),
  )
  .await;

  let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner(); // TODO: stalls here if Connection: close is removed
  client_socket.close().await.unwrap();

  prover_task.await.unwrap().unwrap()
}

#[cfg(feature = "notary_ca_cert")]
const NOTARY_CA_CERT: &[u8] = include_bytes!(env!("NOTARY_CA_CERT_PATH"));

/// Default root store using mozilla certs.
fn default_root_store() -> rustls::RootCertStore {
  let mut root_store = rustls::RootCertStore::empty();
  root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
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
