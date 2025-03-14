use std::{
  io::{BufRead, BufReader},
  path::PathBuf,
  process::{Child, Command, Stdio},
  sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
  },
  thread,
  time::Duration,
};

use tokio::time::{sleep, timeout};

// File paths
const NOTARY_CONFIG_PATH: &str = "fixture/notary-config.toml";
const CLIENT_CONFIG_PATH: &str = "fixture/client.json.proxy.json";
const RELEASE_DIR: &str = "target/release";

// Binary names
const NOTARY_BIN: &str = "web-prover-notary";
const CLIENT_BIN: &str = "web-prover-client";

// Timeouts and delays
const NOTARY_READY_TIMEOUT: Duration = Duration::from_secs(60);
const PROVING_TIMEOUT: Duration = Duration::from_secs(60);
const NOTARY_STARTUP_DELAY: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

// Log messages
const NOTARY_READY_MSG: &str = "Listening on https://0.0.0.0:7443";
const PROVING_SUCCESS_MSG: &str = "Proving Successful";

struct TestSetup {
  notary: Child,
  client: Child,
}

impl TestSetup {
  async fn new() -> Self {
    // Find the workspace root directory
    let workspace_root = {
      let output =
        Command::new("cargo").args(["metadata", "--format-version", "1"]).output().unwrap();

      if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("cargo metadata failed: {}", stderr);
      }

      let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

      PathBuf::from(metadata["workspace_root"].as_str().unwrap())
    };

    println!("Workspace root: {:?}", workspace_root);

    // Check for pre-built binaries in target/release
    let notary_bin = workspace_root.join(RELEASE_DIR).join(NOTARY_BIN);
    let client_bin = workspace_root.join(RELEASE_DIR).join(CLIENT_BIN);

    let use_prebuilt = notary_bin.exists() && client_bin.exists();
    println!("Using pre-built binaries: {}", use_prebuilt);

    // Print the config file content for debugging
    let notary_config_path = workspace_root.join(NOTARY_CONFIG_PATH);
    if notary_config_path.exists() {
      match std::fs::read_to_string(&notary_config_path) {
        Ok(content) => println!("Notary config content:\n{}", content),
        Err(e) => println!("Error reading notary config: {}", e),
      }
    } else {
      println!("Notary config file not found at {:?}", notary_config_path);
    }

    // Start notary
    let mut notary = if use_prebuilt {
      std::env::set_current_dir(&workspace_root).unwrap();
      println!("Current directory: {:?}", std::env::current_dir().unwrap());

      let cmd = Command::new(format!("./{}/{}", RELEASE_DIR, NOTARY_BIN))
        .arg("--config")
        .arg(format!("./{}", NOTARY_CONFIG_PATH))
        .env("RUST_LOG", "DEBUG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

      println!("Started notary with PID: {}", cmd.id());
      cmd
    } else {
      Command::new("cargo")
        .args(["run", "-p", NOTARY_BIN, "--release", "--"])
        .arg("--config")
        .arg(notary_config_path)
        .env("RUST_LOG", "DEBUG")
        .current_dir(&workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
    };

    // Create a flag to indicate when the notary is ready
    let ready_flag = Arc::new(AtomicBool::new(false));
    let ready_flag_clone = ready_flag.clone();

    let notary_stdout = notary.stdout.take().unwrap();
    let notary_stderr = notary.stderr.take().unwrap();

    // Spawn a thread to monitor notary output
    thread::spawn(move || {
      let stdout_reader = BufReader::new(notary_stdout);
      let stderr_reader = BufReader::new(notary_stderr);

      // Check both stdout and stderr for the ready message
      for line in stdout_reader.lines().chain(stderr_reader.lines()) {
        if let Ok(line) = line {
          println!("Notary: {}", line);
          if line.contains(NOTARY_READY_MSG) {
            ready_flag_clone.store(true, Ordering::SeqCst);
            break;
          }
        }
      }
    });

    // Wait for notary to be ready with a timeout, or sleep 10 seconds like the original workflow
    match timeout(NOTARY_READY_TIMEOUT, async {
      while !ready_flag.load(Ordering::SeqCst) {
        sleep(POLL_INTERVAL).await;
      }
      sleep(NOTARY_STARTUP_DELAY).await;
    })
    .await
    {
      Ok(_) => println!("Notary is ready!"),
      Err(_) => {
        println!("Timeout waiting for notary ready message - sleeping 10 seconds anyway");
        sleep(Duration::from_secs(10)).await;
      },
    }

    // Start client
    let client = if use_prebuilt {
      println!("Current directory before client: {:?}", std::env::current_dir().unwrap());

      let cmd = Command::new(format!("./{}/{}", RELEASE_DIR, CLIENT_BIN))
        .arg("--config")
        .arg(format!("./{}", CLIENT_CONFIG_PATH))
        .env("RUST_LOG", "DEBUG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

      println!("Started client with PID: {}", cmd.id());
      cmd
    } else {
      Command::new("cargo")
        .args(["run", "-p", CLIENT_BIN, "--"])
        .arg("--config")
        .arg(workspace_root.join(CLIENT_CONFIG_PATH))
        .env("RUST_LOG", "DEBUG")
        .current_dir(&workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
    };

    Self { notary, client }
  }
}

impl Drop for TestSetup {
  fn drop(&mut self) {
    let _ = self.notary.kill();
    let _ = self.client.kill();
  }
}

#[tokio::test]
async fn test_proving_successful() {
  let mut setup = TestSetup::new().await;

  let stdout = BufReader::new(setup.client.stdout.take().unwrap());
  let stderr = BufReader::new(setup.client.stderr.take().unwrap());

  let result = timeout(PROVING_TIMEOUT, async {
    let mut stdout_lines = stdout.lines();
    let mut stderr_lines = stderr.lines();
    loop {
      if let Some(Ok(line)) = stdout_lines.next() {
        println!("Client stdout: {}", line);
        if line.contains(PROVING_SUCCESS_MSG) {
          return true;
        }
      }

      if let Some(Ok(line)) = stderr_lines.next() {
        println!("Client stderr: {}", line);
        if line.contains(PROVING_SUCCESS_MSG) {
          return true;
        }
      }

      sleep(POLL_INTERVAL).await;
    }
  })
  .await;

  match result {
    Ok(found) => assert!(found, "Did not find '{}' in output", PROVING_SUCCESS_MSG),
    Err(_) => panic!(
      "Timed out waiting for '{}' after {} seconds",
      PROVING_SUCCESS_MSG,
      PROVING_TIMEOUT.as_secs()
    ),
  }
}
