use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// TODO: Note, this is currently bringing in some of the `RequestOptions` and renames to simplify
// things if possible.
// * `notary_host` is now `notary_url`
// The `target_headers` was previously `HashMap<String, Vec<String>>`
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub notary_host:                  String,
  pub notary_port:                  u16,
  pub target_method:                String,
  pub target_url:                   String,
  pub target_headers:               HashMap<String, String>,
  pub target_body:                  String,
  #[cfg(feature = "websocket")]
  pub websocket_proxy_url:          String,
  pub notarization_session_request: NotarizationSessionRequest, // TODO rename to something better
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizationSessionRequest {
  pub client_type:   ClientType, // TODO depends on feature = websocket
  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
  /// Client that has access to the transport layer
  Tcp,
  /// Client that cannot directly access transport layer, e.g. browser extension
  Websocket,
}
