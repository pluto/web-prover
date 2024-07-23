use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use axum::{
  extract::{rejection::JsonRejection, FromRequestParts, Query, State},
  http::{header, request::Parts, StatusCode},
  response::{IntoResponse, Json, Response},
};
use axum_macros::debug_handler;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct SessionData {
  pub max_sent_data: Option<usize>,
  pub max_recv_data: Option<usize>,
  // pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct NotaryGlobals {
  // pub notary_signing_key: SigningKey,
  // pub notarization_config: NotarizationProperties,
  /// A temporary storage to store configuration data, mainly used for WebSocket client
  pub store: Arc<Mutex<HashMap<String, SessionData>>>,
  // Whitelist of API keys for authorization purpose
  // pub authorization_whitelist: Option<Arc<Mutex<HashMap<String,
  // AuthorizationWhitelistRecord>>>>,
}

impl NotaryGlobals {
  pub fn new(// notary_signing_key: SigningKey,
      // notarization_config: NotarizationProperties,
      // authorization_whitelist: Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>>,
  ) -> Self {
    Self {
      // notary_signing_key,
      // notarization_config,
      store: Default::default(),
      // authorization_whitelist,
    }
  }
}

/// Request query of the /notarize API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequestQuery {
  /// Session id that is returned from /session API
  pub session_id: String,
}

/// Request object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
  pub client_type:   ClientType,
  /// Maximum data that can be sent by the prover
  pub max_sent_data: Option<usize>,
  /// Maximum data that can be received by the prover
  pub max_recv_data: Option<usize>,
}

/// Response object of the /session API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
  /// Unique session id that is generated by notary and shared to prover
  pub session_id: String,
}

/// Types of client that the prover is using
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
  /// Client that has access to the transport layer
  Tcp,
  /// Client that cannot directly access transport layer, e.g. browser extension
  Websocket,
}

/// Handler to initialize and configure notarization for both TCP and WebSocket clients
#[debug_handler(state = NotaryGlobals)]
pub async fn initialize(
  State(notary_globals): State<NotaryGlobals>,
  payload: Result<Json<NotarizationSessionRequest>, JsonRejection>,
) -> impl IntoResponse {
  info!(?payload, "Received request for initializing a notarization session");

  // Parse the body payload
  let payload = match payload {
    Ok(payload) => payload,
    Err(err) => {
      error!("Malformed payload submitted for initializing notarization: {err}");
	  panic!("todo");
    //   return NotaryServerError::BadProverRequest(err.to_string()).into_response(); // TODO
    },
  };

  // TODO
  // Ensure that the max_transcript_size submitted is not larger than the global max limit
  // configured in notary server
  //   if payload.max_sent_data.is_some() || payload.max_recv_data.is_some() {
  //     let requested_transcript_size =
  //       payload.max_sent_data.unwrap_or_default() + payload.max_recv_data.unwrap_or_default();
  //     if requested_transcript_size > notary_globals.notarization_config.max_transcript_size {
  //       error!(
  //         "Max transcript size requested {:?} exceeds the maximum threshold {:?}",
  //         requested_transcript_size, notary_globals.notarization_config.max_transcript_size
  //       );
  //       return NotaryServerError::BadProverRequest(
  //         "Max transcript size requested exceeds the maximum threshold".to_string(),
  //       )
  //       .into_response();
  //     }
  //   }

  let prover_session_id = Uuid::new_v4().to_string();

  // Store the configuration data in a temporary store
  notary_globals.store.lock().unwrap().insert(prover_session_id.clone(), SessionData {
    max_sent_data: payload.max_sent_data,
    max_recv_data: payload.max_recv_data,
    // created_at:    Utc::now(),
  });

  trace!("Latest store state: {:?}", notary_globals.store);

  // Return the session id in the response to the client
  (StatusCode::OK, Json(NotarizationSessionResponse { session_id: prover_session_id }))
    .into_response()
}
