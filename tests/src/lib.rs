use std::{
  path::PathBuf,
  process::{Child, Command},
  time::Duration,
};

use anyhow::{Context, Result};
use tokio::time::sleep;
use tracing_test::traced_test;

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

    // Start notary first
    let notary = Command::new("cargo")
      .args(["run", "-p", "notary", "--release", "--"])
      .arg("--config")
      .arg(&notary_config)
      .env("RUST_LOG", "DEBUG")
      .current_dir(&workspace_root)
      .spawn()
      .with_context(|| format!("Failed to spawn notary with config {:?}", notary_config))?;

    // Give notary time to start up
    sleep(Duration::from_secs(2)).await;

    // Start client
    let client = Command::new("cargo")
      .args(["run", "-p", "client", "--"])
      .arg("--config")
      .arg(&client_config)
      .env("RUST_LOG", "DEBUG")
      .current_dir(&workspace_root)
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
#[traced_test]
async fn test_proving_successful() -> Result<()> {
  let _setup = TestSetup::new().await?;

  // Wait for and verify the proof message appears
  for _ in 0..60 {
    // Wait up to 30 seconds
    if logs_contain("Proving Successful") {
      return Ok(());
    }
    sleep(Duration::from_secs(1)).await;
  }

  anyhow::bail!("Did not find 'Proving Successful' message in logs after 30 seconds");
}
