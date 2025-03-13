use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Action {
  pub kind:    String,
  pub payload: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum View {
  InitialView,
  PromptView { prompts: Vec<Prompt> },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitialInput {
  pub script: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Prompt {
  pub title: String,
  pub types: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PromptRequest {
  pub uuid:    String,
  pub prompts: Vec<Prompt>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PromptResponse {
  pub inputs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProveRequest {
  pub uuid:  String,
  pub key:   String,
  pub value: Value,
}
