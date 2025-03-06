// logic common to wasm32 and native

use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use serde::{Deserialize, Serialize};
use tracing::debug;
use web_prover_core::manifest::Manifest;

use crate::{errors, SignedVerificationReply};

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

pub async fn send_request(
  mut request_sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>,
  request: Request<http_body_util::Full<Bytes>>,
) {
  // TODO: Clean up this logging and error handling
  match request_sender.send_request(request).await {
    Ok(response) => {
      let status = response.status();
      let headers = response.headers().clone();
      debug!(
        "Response with status code {:?}:\nHeaders: {:?}\n\nBody:\n{}",
        status,
        headers,
        body_to_string(response).await
      );
      assert!(status.is_success()); // status is 200-299
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO is this safe to ignore */
    Err(e) => panic!("{:?}", e),
  };
}

async fn body_to_string(res: hyper::Response<hyper::body::Incoming>) -> String {
  let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
  String::from_utf8(body_bytes.to_vec()).unwrap()
}
