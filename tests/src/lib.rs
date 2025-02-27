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

    // Use relative paths that match the original workflow
    let notary_config = "./fixture/notary-config.toml";
    let client_config = "./fixture/client.tee_tcp_local.json";

    println!("Checking if config files exist:");
    println!("Notary config (workspace): {}", workspace_root.join(notary_config).exists());
    println!("Client config (workspace): {}", workspace_root.join(client_config).exists());
    println!("Notary config (relative): {}", PathBuf::from(notary_config).exists());
    println!("Client config (relative): {}", PathBuf::from(client_config).exists());

    // Check for pre-built binaries in target/release
    let notary_bin = workspace_root.join("target/release/notary");
    let client_bin = workspace_root.join("target/release/client");

    let use_prebuilt = notary_bin.exists() && client_bin.exists();
    println!("Using pre-built binaries: {}", use_prebuilt);

    // Start notary with captured output
    let mut notary = if use_prebuilt {
      println!("Running notary from: {:?}", &notary_bin);
      // Match the original workflow exactly - use relative paths
      let mut cmd = Command::new(&notary_bin);
      cmd.arg("--config").arg(notary_config);
      cmd.env("RUST_LOG", "DEBUG").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    } else {
      let mut cmd = Command::new("cargo");
      cmd
        .args(["run", "-p", "notary", "--release", "--"])
        .arg("--config")
        .arg(workspace_root.join(notary_config))
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

    // Wait for notary to be ready with a timeout
    match timeout(Duration::from_secs(60), async {
      while !ready_flag.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(100)).await;
      }

      // Add extra delay to ensure the notary is fully ready
      // This matches the 10 second sleep in the original workflow
      sleep(Duration::from_secs(2)).await;
    })
    .await
    {
      Ok(_) => println!("Notary is ready!"),
      Err(_) => panic!("Timed out waiting for notary to be ready after 60 seconds"),
    }

    // Start client and capture its output
    let client = if use_prebuilt {
      println!("Running client from: {:?}", &client_bin);
      // Match the original workflow exactly - use relative paths
      let mut cmd = Command::new(&client_bin);
      cmd.arg("--config").arg(client_config);
      cmd.env("RUST_LOG", "DEBUG").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    } else {
      let mut cmd = Command::new("cargo");
      cmd
        .args(["run", "-p", "client", "--"])
        .arg("--config")
        .arg(workspace_root.join(client_config))
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
        // If we see a file not found error, print more detailed info
        if line.contains("NotFound") {
          println!(
            "File not found error detected. Current directory: {:?}",
            std::env::current_dir().unwrap()
          );
          println!("Directory contents:");
          for entry in std::fs::read_dir(".").unwrap() {
            println!("  {:?}", entry.unwrap().path());
          }
          if let Ok(entries) = std::fs::read_dir("./fixture") {
            println!("Fixture directory contents:");
            for entry in entries {
              println!("  {:?}", entry.unwrap().path());
            }
          }
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
