use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::states::State;

pub struct Session<W: Writer> {
  session_id: Uuid,
  writer:     Mutex<Option<W>>,
}

impl<W: Writer> Session<W> {
  pub fn new(session_id: Uuid) -> Self { Session { session_id, writer: Mutex::new(None) } }

  pub async fn set_writer(&mut self, writer: Option<W>) { *self.writer.lock().await = writer; }

  async fn write<T: Serialize + Send + Sync>(&mut self, data: &T) {
    // TODO return error if no writer is set
    if let Some(writer) = &mut *self.writer.lock().await {
      writer.write(data).await;
    }
  }

  pub async fn read(&mut self, state: State) {
    // TODO read incoming message from websocket, here it is already parsed into a struct
  }

  pub async fn close(&mut self) {
    // TODO: end or keep the session alive for another 10 mins?
    // in case clients wants to resume session
  }
}

pub trait Writer: Send {
  async fn write<T: Serialize + Send + Sync>(&mut self, data: &T) -> Result<(), String>;
}
