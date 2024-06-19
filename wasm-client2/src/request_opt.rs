use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Requestion Options of Fetch API
// https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    pub method: String, // *GET, POST, PUT, DELETE, etc.
    // pub mode: String, // no-cors, *cors, same-origin
    // pub cache: String, // *default, no-cache, reload, force-cache, only-if-cached
    // pub credentials: String, // include, *same-origin, omit
    pub headers: HashMap<String, String>,
    // pub redirect: String, // manual, *follow, error
    // pub referrer_policy: String, // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    pub body: String, // body data type must match "Content-Type" header
    pub max_sent_data: Option<usize>,
    pub max_recv_data: Option<usize>,
    pub notary_url: String,
    pub websocket_proxy_url: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub server_name: String,
    pub time: u64,
    pub sent: String,
    pub recv: String,
}
