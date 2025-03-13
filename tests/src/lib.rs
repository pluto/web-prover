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
    let notary_bin = workspace_root.join("target/release/notary");
    let client_bin = workspace_root.join("target/release/client");

    let use_prebuilt = notary_bin.exists() && client_bin.exists();
    println!("Using pre-built binaries: {}", use_prebuilt);

    // Print the config file content for debugging
    let notary_config_path = workspace_root.join("fixture/notary-config.toml");
    if notary_config_path.exists() {
      match std::fs::read_to_string(&notary_config_path) {
        Ok(content) => println!("Notary config content:\n{}", content),
        Err(e) => println!("Error reading notary config: {}", e),
      }
    } else {
      println!("Notary config file not found at {:?}", notary_config_path);
    }

    // This matches exactly what worked in your shell script
    let mut notary = if use_prebuilt {
      // Change directory to workspace root first
      std::env::set_current_dir(&workspace_root).unwrap();
      println!("Current directory: {:?}", std::env::current_dir().unwrap());

      let cmd = Command::new("./target/release/notary")
        .arg("--config")
        .arg("./fixture/notary-config.toml")
        .env("RUST_LOG", "DEBUG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

      println!("Started notary with PID: {}", cmd.id());
      cmd
    } else {
      Command::new("cargo")
        .args(["run", "-p", "notary", "--release", "--"])
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
          if line.contains("Listening on https://0.0.0.0:7443") {
            ready_flag_clone.store(true, Ordering::SeqCst);
            break;
          }
        }
      }
    });

    // Wait for notary to be ready with a timeout, or sleep 10 seconds like the original workflow
    match timeout(Duration::from_secs(60), async {
      while !ready_flag.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(100)).await;
      }

      // Add extra delay to match original workflow
      sleep(Duration::from_secs(5)).await;
    })
    .await
    {
      Ok(_) => println!("Notary is ready!"),
      Err(_) => {
        println!("Timeout waiting for notary ready message - sleeping 10 seconds anyway");
        sleep(Duration::from_secs(10)).await;
      },
    }

    // Start client with exact same pattern as the working workflow
    let client = if use_prebuilt {
      // We're already in workspace_root directory
      println!("Current directory before client: {:?}", std::env::current_dir().unwrap());

      let cmd = Command::new("./target/release/client")
        .arg("--config")
        .arg("./fixture/client.proxy.json")
        .env("RUST_LOG", "DEBUG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

      println!("Started client with PID: {}", cmd.id());
      cmd
    } else {
      Command::new("cargo")
        .args(["run", "-p", "client", "--"])
        .arg("--config")
        .arg(workspace_root.join("../../fixture/client.json.proxy.json"))
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

  // Wait for proving successful with timeout
  let result = timeout(Duration::from_secs(60), async {
    let mut stdout_lines = stdout.lines();
    let mut stderr_lines = stderr.lines();
    loop {
      // Check stdout
      if let Some(Ok(line)) = stdout_lines.next() {
        println!("Client stdout: {}", line);
        if line.contains("Proving Successful") {
          return true;
        }
      }

      // Check stderr
      if let Some(Ok(line)) = stderr_lines.next() {
        println!("Client stderr: {}", line);
        if line.contains("Proving Successful") {
          return true;
        }
      }

      // Small sleep to avoid busy waiting
      sleep(Duration::from_millis(10)).await;
    }
  })
  .await;

  match result {
    Ok(found) => assert!(found, "Did not find 'Proving Successful' in output"),
    Err(_) => panic!("Timed out waiting for 'Proving Successful' after 60 seconds"),
  }
}
