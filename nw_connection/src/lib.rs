use std::{
  borrow::BorrowMut,
  ffi::{c_char, CStr, CString},
  future::{Future, Ready},
  io::Read,
  net::SocketAddr,
  ptr,
  sync::{Arc, Mutex},
  task::{Poll, Waker},
};

use bytes::buf;
use cidre::{
  arc::Retained,
  dispatch::{self, Data, Queue},
  nw::{self, Connection, ContentCtx, Endpoint, Error, Params},
};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  net::ToSocketAddrs,
  sync::oneshot,
};
struct CustomError(String); // TODO can we use cidre::Error instead?

struct ReadResult {
  data:  Vec<u8>,
  error: Option<CustomError>,
}

struct WriteResult {
  error: Option<CustomError>,
}

pub struct NWConnection {
  queue:            Retained<Queue>,
  connection:       Retained<Connection>,
  write_waker:      Arc<Mutex<Option<Waker>>>,
  read_waker:       Arc<Mutex<Option<Waker>>>,
  sending_finished: Arc<Mutex<Option<WriteResult>>>,
  reading_finished: Arc<Mutex<Option<ReadResult>>>,
}

impl NWConnection {
  pub fn connect(host: &str, port: u16) -> Self {
    let hostname = CString::new(host).unwrap();
    let port = CString::new(port.to_string()).unwrap();
    let endpoint = Endpoint::with_host(hostname.as_c_str(), port.as_c_str()).unwrap();
    let params =
      Params::create_secure_tcp(Params::disable_protocol(), Params::default_cfg()).unwrap();
    let mut connection = Connection::with_endpoint(&endpoint, &params).unwrap();
    let queue = Queue::new();
    connection.start(&queue);
    NWConnection {
      queue,
      connection,
      read_waker: Arc::new(Mutex::new(None)),
      write_waker: Arc::new(Mutex::new(None)),
      sending_finished: Arc::new(Mutex::new(None)),
      reading_finished: Arc::new(Mutex::new(None)),
    }
  }
}

impl AsyncRead for NWConnection {
  fn poll_read(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    println!("poll_read:1");
    if self.read_waker.lock().unwrap().is_some() {
      println!("poll_read:2");
      return Poll::Pending;
    }

    println!("poll_read:3");
    if let Some(result) = self.reading_finished.lock().unwrap().take() {
      if let Some(error) = result.error {
        println!("poll_read:4");
        return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, error.0)));
      }
      println!("poll_read:5");
      if result.data.len() > 0 {
        buf.put_slice(result.data.as_slice());
      }
      return Poll::Ready(Ok(()));
    }

    println!("poll_read:6");
    let waker = self.read_waker.clone();
    println!("poll_read:7");
    let reading_finished = self.reading_finished.clone();

    println!("poll_read:8");
    let completion_callback = move |content: Option<&dispatch::Data>,
                                    context: Option<&nw::ContentCtx>,
                                    _is_complete: bool,
                                    error: Option<&Error>| {
      // is_complete is always false?

      println!("poll_read:9");
      let data: &[u8] = content.as_ref().map_or(&[], |c| c.as_ns().as_slice());
      let error = error.map(|e| CustomError(format!("{:?}", e)));

      println!("poll_read:10");
      *reading_finished.lock().unwrap() = Some(ReadResult { data: data.into(), error });

      println!("poll_read:11");
      if let Some(waker) = waker.lock().unwrap().take() {
        println!("poll_read:12");
        waker.wake();
      }
    };

    println!("poll_read:13");
    let mut_self = self.get_mut();
    *mut_self.read_waker.lock().unwrap() = Some(cx.waker().clone());
    println!("poll_read:14");
    *mut_self.reading_finished.lock().unwrap() = None;
    println!("poll_read:15");

    mut_self.connection.recv(1, 8192, completion_callback);

    println!("poll_read:16");
    Poll::Pending
  }
}

impl AsyncWrite for NWConnection {
  fn poll_write(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> std::task::Poll<Result<usize, std::io::Error>> {
    println!("poll_write:1");
    if self.write_waker.lock().unwrap().is_some() {
      println!("poll_write:2");
      return Poll::Pending;
    }

    println!("poll_write:3");
    if let Some(result) = self.sending_finished.lock().unwrap().take() {
      println!("poll_write:4");
      if let Some(error) = result.error {
        println!("poll_write:5");
        return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, error.0)));
      }
      println!("poll_write:6");
      return Poll::Ready(Ok(buf.len()));
    }

    println!("poll_write:7");
    if buf.len() == 0 {
      println!("poll_write:8");
      return Poll::Ready(Ok(0));
    }

    println!("poll_write:9");
    let waker = self.write_waker.clone();
    println!("poll_write:10");
    let sending_finished = self.sending_finished.clone();

    println!("poll_write:11");
    let completion_callback = move |error: Option<&Error>| {
      let error = error.map(|e| CustomError(format!("{:?}", e)));
      println!("poll_write:12");
      *sending_finished.lock().unwrap() = Some(WriteResult { error });
      println!("poll_write:13");
      if let Some(waker) = waker.lock().unwrap().take() {
        println!("poll_write:14");
        waker.wake();
      }
    };

    println!("poll_write:15");
    let mut_self = self.get_mut();
    println!("poll_write:16");
    *mut_self.write_waker.lock().unwrap() = Some(cx.waker().clone());
    println!("poll_write:17");
    *mut_self.sending_finished.lock().unwrap() = None;

    println!("poll_write:18");
    let content = Data::copy_from_slice(buf);
    let context = ContentCtx::default_msg();
    let is_complete = true; // TODO true or false?!
    mut_self.connection.send(Some(&content), context, is_complete, completion_callback);

    println!("poll_write:19");
    return Poll::Pending;
  }

  fn poll_flush(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), std::io::Error>> {
    println!("poll_flush");
    std::task::Poll::Ready(Ok(()))
  }

  fn poll_shutdown(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), std::io::Error>> {
    // TODO cancel connection?
    println!("poll_shutdown");
    std::task::Poll::Ready(Ok(()))
  }
}
