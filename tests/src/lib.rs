use std::{
  io::{BufRead, BufReader},
  path::PathBuf,
  process::{Child, Command, Stdio},
  time::Duration,
};

use anyhow::{Context, Result};
use tokio::time::sleep;

struct TestSetup {
  notary: Child,
  client: Child,
}

impl TestSetup {
  async fn new() -> Result<Self> {
    // Find the workspace root directory
    let workspace_root = {
      let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .output()
        .context("Failed to run cargo metadata")?;

      if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("cargo metadata failed: {}", stderr);
      }

      let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse cargo metadata")?;

      PathBuf::from(
        metadata["workspace_root"].as_str().context("workspace_root not found in metadata")?,
      )
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
      .with_context(|| format!("Failed to spawn notary with config {:?}", notary_config))?;

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
      .with_context(|| format!("Failed to spawn client with config {:?}", client_config))?;

    Ok(Self { notary, client })
  }
}

impl Drop for TestSetup {
  fn drop(&mut self) {
    let _ = self.notary.kill();
    let _ = self.client.kill();
  }
}

#[tokio::test]
async fn test_proving_successful() -> Result<()> {
  let mut setup = TestSetup::new().await?;

  let stdout = BufReader::new(setup.client.stdout.take().unwrap());
  let stderr = BufReader::new(setup.client.stderr.take().unwrap());

  // Check both stdout and stderr for our message
  let found =
    stdout.lines().chain(stderr.lines()).any(|line| line.unwrap().contains("Proving Successful"));

  assert!(found, "Did not find 'Proving Successful' in output");
  Ok(())
}
