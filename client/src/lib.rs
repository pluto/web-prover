extern crate core;
pub mod config;
pub mod error;
use std::collections::HashMap;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message::Text};
use tracing::debug;
use web_prover_core::{
  frame::{
    Action, InitialInput, PromptResponse,
    View::{self, InitialView, PromptView},
  },
  manifest::Manifest,
  proof::{SignedVerificationReply, TeeProof},
};

use crate::error::WebProverClientError;

const EXAMPLE_DEVELOPER_SCRIPT: &str = r#"
await page.goto("https://pseudo-bank.pluto.dev");

const username = page.getByRole("textbox", { name: "Username" });
const password = page.getByRole("textbox", { name: "Password" });

let input = await prompt([
  { title: "Username", types: "text" },
  { title: "Password", types: "password" },
]);

await username.fill(input.inputs[0]);
await password.fill(input.inputs[1]);

const loginBtn = page.getByRole("button", { name: "Login" });
await loginBtn.click();

await page.waitForSelector("text=Your Accounts", { timeout: 5000 });

const balanceLocator = page.locator("\#balance-2");
await balanceLocator.waitFor({ state: "visible", timeout: 5000 });
const balanceText = (await balanceLocator.textContent()) || "";
const balance = parseFloat(balanceText.replace(/[$,]/g, ""));

await prove("bank_balance", balance);
"#;
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyConfig {
  pub target_method:  String,
  pub target_url:     String,
  pub target_headers: HashMap<String, String>,
  pub target_body:    String,
  pub manifest:       Manifest,
}

pub async fn proxy(config: config::Config) -> Result<TeeProof, WebProverClientError> {
  let session_id = config.session_id.clone();

  let url = format!(
    "https://{}:{}/v1/proxy?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let proxy_config = ProxyConfig {
    target_method:  config.manifest.request.method.clone(),
    target_url:     config.manifest.request.url.clone(),
    target_headers: config.manifest.request.headers.clone(),
    target_body:    config.target_body,
    manifest:       config.manifest,
  };

  let client = {
    let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Some(cert) = config.notary_ca_cert {
      client_builder =
        client_builder.add_root_certificate(reqwest::tls::Certificate::from_der(&cert)?);
    }
    client_builder.build()?
  };

  let response = client.post(url).json(&proxy_config).send().await?;
  assert_eq!(response.status(), hyper::StatusCode::OK);
  let tee_proof = response.json::<TeeProof>().await?;
  Ok(tee_proof)
}

pub async fn verify<T: Serialize>(
  config: crate::config::Config,
  verify_body: T,
) -> Result<SignedVerificationReply, error::WebProverClientError> {
  let url = format!(
    "https://{}:{}/v1/{}/verify",
    config.notary_host.clone(),
    config.notary_port.clone(),
    "tee",
  );

  let client = {
    let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Some(cert) = config.notary_ca_cert {
      client_builder =
        client_builder.add_root_certificate(reqwest::tls::Certificate::from_der(&cert)?);
    }
    client_builder.build()?
  };

  let response = client.post(url).json(&verify_body).send().await?;
  assert!(response.status() == hyper::StatusCode::OK, "response={:?}", response);
  let verify_response = response.json::<SignedVerificationReply>().await?;

  debug!("\n{:?}\n\n", verify_response.clone());

  Ok(verify_response)
}

pub async fn frame() {
  let config = std::fs::read("./fixture/client.proxy.json").unwrap();
  let mut config: config::Config = serde_json::from_slice(&config).unwrap();
  config.set_session_id();

  let url = format!(
    "wss://{}:{}/v1/frame?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    config.session_id
  );
  debug!("url={}", url);

  // Set up TLS connector that accepts your server certificate
  let mut connector_builder = native_tls::TlsConnector::builder();

  // For testing only: disable certificate verification
  // WARNING: Only use this for testing, never in production
  connector_builder.danger_accept_invalid_certs(true);

  let connector = connector_builder.build().unwrap();
  let connector = native_tls::TlsConnector::from(connector);

  // Connect with TLS
  let request = url.into_client_request().unwrap();
  let (mut ws_stream, response) = tokio_tungstenite::connect_async_tls_with_config(
    request,
    None,
    false,
    Some(tokio_tungstenite::Connector::NativeTls(connector)),
  )
  .await
  .unwrap();

  // assert!(response.status().is_success(), "WebSocket connection failed");
  debug!("response={:?}", response);

  let ws_spawn = tokio::spawn(async move {
    while let Some(message) = ws_stream.next().await {
      let message = message.unwrap();
      debug!("message={:?}", message);

      match message {
        Text(text) => {
          let view: View = serde_json::from_str(&text).unwrap();
          match view {
            InitialView => {
              debug!("Received InitialView");
              let action = Action {
                kind:    "initial_input".to_owned(),
                payload: serde_json::to_value(InitialInput {
                  script: EXAMPLE_DEVELOPER_SCRIPT.to_owned(),
                })
                .unwrap(),
              };
              ws_stream.send(Text(serde_json::to_string(&action).unwrap().into())).await.unwrap();
            },
            PromptView { prompts } => {
              debug!("Received PromptView with prompts: {:?}", prompts);
              let prompt_response = PromptResponse {
                inputs: prompts.iter().map(|prompt| prompt.title.clone()).collect(),
              };
              let action = Action {
                kind:    "prompt_response".to_owned(),
                payload: serde_json::to_value(prompt_response).unwrap(),
              };
              ws_stream.send(Text(serde_json::to_string(&action).unwrap().into())).await.unwrap();
            },
            View::ProveView { proof } => {
              debug!("Received ProveView with proof: {:?}", proof);

              ws_stream.close(None).await.unwrap();
            },
          }
        },
        _ => panic!("unexpected message"),
      };
    }
  });

  match ws_spawn.await {
    Ok(_) => debug!("WebSocket task completed"),
    Err(e) => debug!("WebSocket task failed: {:?}", e),
  }
}

#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message::Text};
  use web_prover_core::frame::{
    Action, InitialInput, PromptResponse,
    View::{self, InitialView, PromptView},
  };

  use super::*;

  #[tokio::test]
  #[tracing::instrument]
  async fn test_frame() {
    let config = std::fs::read("../fixture/client.proxy.json").unwrap();
    let mut config: config::Config = serde_json::from_slice(&config).unwrap();
    config.set_session_id();

    let url = format!(
      "wss://{}:{}/v1/frame?session_id={}",
      config.notary_host.clone(),
      config.notary_port.clone(),
      config.session_id
    );
    println!("url={}", url);

    // Set up TLS connector that accepts your server certificate
    let mut connector_builder = native_tls::TlsConnector::builder();

    // For testing only: disable certificate verification
    // WARNING: Only use this for testing, never in production
    connector_builder.danger_accept_invalid_certs(true);

    let connector = connector_builder.build().unwrap();
    let connector = native_tls::TlsConnector::from(connector);

    // Connect with TLS
    let request = url.into_client_request().unwrap();
    let (mut ws_stream, response) = tokio_tungstenite::connect_async_tls_with_config(
      request,
      None,
      false,
      Some(tokio_tungstenite::Connector::NativeTls(connector)),
    )
    .await
    .unwrap();

    // assert!(response.status().is_success(), "WebSocket connection failed");
    println!("response={:?}", response);

    let ws_spawn = tokio::spawn(async move {
      while let Some(message) = ws_stream.next().await {
        let message = message.unwrap();
        println!("message={:?}", message);

        match message {
          Text(text) => {
            let view: View = serde_json::from_str(&text).unwrap();
            match view {
              InitialView => {
                println!("InitialView");
                let action = Action {
                  kind:    "initial_input".to_owned(),
                  payload: serde_json::to_value(InitialInput {
                    script: EXAMPLE_DEVELOPER_SCRIPT.to_owned(),
                  })
                  .unwrap(),
                };
                ws_stream.send(Text(serde_json::to_string(&action).unwrap().into())).await.unwrap();
              },
              PromptView { prompts } => {
                println!("Received PromptView with prompts: {:?}", prompts);
                let prompt_response = PromptResponse {
                  inputs: prompts.iter().map(|prompt| prompt.title.clone()).collect(),
                };
                let action = Action {
                  kind:    "prompt_response".to_owned(),
                  payload: serde_json::to_value(prompt_response).unwrap(),
                };
                ws_stream.send(Text(serde_json::to_string(&action).unwrap().into())).await.unwrap();
                println!("Sent prompt response: {:?}", action);
              },
              View::ProveView { proof } => {
                println!("Received ProveView with proof: {:?}", proof);

                ws_stream.close(None).await.unwrap();
              },
            }
          },
          _ => panic!("unexpected message"),
        };
      }
    });

    match ws_spawn.await {
      Ok(_) => println!("WebSocket task completed"),
      Err(e) => println!("WebSocket task failed: {:?}", e),
    }
  }
}
