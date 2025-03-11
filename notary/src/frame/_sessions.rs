use std::collections::HashMap;

use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::_views::{InitialView, View};

pub struct Session<W: Writer> {
  session_id:   Uuid,
  writer:       Mutex<Option<W>>,
  current_view: View,
}

impl<W: Writer> Session<W> {
  pub fn new(session_id: Uuid) -> Self {
    Session { session_id, writer: Mutex::new(None), current_view: InitialView::new() }
  }

  pub async fn set_writer(&mut self, writer: Option<W>) { *self.writer.lock().await = writer; }

  async fn write<T: Serialize + Send + Sync>(&mut self, data: &T) {
    // TODO return error if no writer is set
    if let Some(writer) = &mut *self.writer.lock().await {
      writer.write(data).await;
    }
  }

  pub async fn read(&mut self, action: Action) {
    // TODO dispatch to current view
  }

  pub async fn close(&mut self) {
    // TODO: end or keep the session alive for another 10 mins?
    // in case clients wants to resume session
  }
}

pub trait Writer: Send {
  async fn write<T: Serialize + Send + Sync>(&mut self, data: &T) -> Result<(), String>;
}

pub struct Action {
  kind: String,
  data: HashMap<String, String>,
}
