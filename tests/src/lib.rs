use std::{
  io::{BufRead, BufReader},
  path::PathBuf,
  process::{Child, Command, Stdio},
  time::Duration,
};

use tokio::time::sleep;

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

    let notary_config = workspace_root.join("fixture/notary-config.toml");
    let client_config = workspace_root.join("fixture/client.tee_tcp_local.json");

    println!("Checking if config files exist:");
    println!("Notary config exists: {}", notary_config.exists());
    println!("Client config exists: {}", client_config.exists());

    // Start notary
    let notary = Command::new("cargo")
      .args(["run", "-p", "notary", "--release", "--"])
      .arg("--config")
      .arg(&notary_config)
      .env("RUST_LOG", "DEBUG")
      .current_dir(&workspace_root)
      .stdout(Stdio::inherit())
      .stderr(Stdio::inherit())
      .spawn()
      .unwrap();

    sleep(Duration::from_secs(2)).await;

    // Start client and capture its output
    let client = Command::new("cargo")
      .args(["run", "-p", "client", "--"])
      .arg("--config")
      .arg(&client_config)
      .env("RUST_LOG", "DEBUG")
      .current_dir(&workspace_root)
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .unwrap();

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

  // Check both stdout and stderr for our message
  let found =
    stdout.lines().chain(stderr.lines()).any(|line| line.unwrap().contains("Proving Successful"));

  assert!(found, "Did not find 'Proving Successful' in output");
}
