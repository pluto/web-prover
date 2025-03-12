pub struct PromptView {
  state: State,
}

impl PromptView {
  pub fn new() -> Self { PromptView { state: State::Initial } }

  pub fn handle(self, action: Action) -> Action {
    match (self.state, action) {
      (State::Initial, Action::PromptsReply(prompts_request)) => todo!(),

      _ => todo!(), // TODO return error
    }
  }
}

pub enum State {
  Initial,
}

pub enum Action {
  PromptsRequest(actions::PromptsRequest),
  PromptsReply(actions::PromptsReply),
}

pub mod actions {
  pub struct PromptsRequest {}

  pub struct PromptsReply {}
}
