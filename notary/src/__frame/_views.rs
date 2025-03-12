use super::_sessions::{Action, Writer};

pub trait View<W: Writer>: Send + Sync {
  fn handle(&mut self, action: &Action) -> impl Response;
  fn name(&self) -> String;
}

pub struct InitialView {
  foobar: String,
}

impl<W: Writer> View<W> for InitialView {
  fn handle(action: &Action) -> impl Response { Some(Box::new(ResultView {})) }

  fn name(&self) -> String { "initial".to_string() }

  fn serialize(&self) -> serde_json::Value {
    serde_json::json!({
      "foobar": self.foobar,
    })
  }
}

pub struct ResultView {}

impl<W: Writer> View<W> for ResultView {
  fn handle(&mut self, writer: &mut W, action: &Action) -> Option<Box<dyn View<W>>> { None }

  fn name(&self) -> String { "result".to_string() }

  fn serialize(&self) -> serde_json::Value { serde_json::json!({}) }
}
