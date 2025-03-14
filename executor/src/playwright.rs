use std::{
  io::{Read, Write},
  path::PathBuf,
  process::Stdio,
  time::Duration,
};

use tempfile::NamedTempFile;
use tokio::process::Command;
use tracing::{debug, error};
use uuid::Uuid;
use wait_timeout::ChildExt;

/// The Playwright template with a placeholder for the script
pub const PLAYWRIGHT_TEMPLATE: &str = r#"
const { chromium } = require('playwright-core');
const { prompt, prove, setSessionUUID } = require("@plutoxyz/playwright-utils");

(async () => {
  const sessionUUID = process.argv[2];
  setSessionUUID(sessionUUID);
  console.log("Starting Playwright session with UUID:", sessionUUID);

  const browser = await chromium.launch({
    headless: true,
    executablePath: '/Users/darkrai/Library/Caches/ms-playwright/chromium_headless_shell-1155/chrome-mac/headless_shell'
  });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Developer provided script:
  {{.Script}}

  await browser.close();
})();
"#;

/// Configuration for the Playwright runner
pub struct PlaywrightRunnerConfig {
  /// Developer script to run in the Playwright template
  pub script:          String,
  /// Timeout for script execution in seconds
  pub timeout_seconds: u64,
}

pub struct PlaywrightRunner {
  /// scipt template with placeholder for the developer script
  template:  String,
  /// Playwright runner configuration
  config:    PlaywrightRunnerConfig,
  /// Path to the Node.js executable
  node_path: PathBuf,
  /// environment variables
  env:       Vec<(String, String)>,
}

#[derive(Debug)]
pub struct PlaywrightOutput {
  pub stdout: String,
  pub stderr: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PlaywrightError {
  #[error(transparent)]
  IoError(#[from] std::io::Error),

  #[error("Playwright execution failed: {0}")]
  ExecutionError(String),
}

// TODO: add a PlaywrightError type

impl PlaywrightRunner {
  pub fn new(
    config: PlaywrightRunnerConfig,
    template: String,
    node_path: PathBuf,
    env_vars: Vec<(String, String)>,
  ) -> Self {
    Self { config, template, node_path, env: env_vars }
  }

  pub async fn run_script(&self, session_id: &Uuid) -> Result<PlaywrightOutput, PlaywrightError> {
    // fill the template with the developer script
    let template = self.template.replace("{{.Script}}", &self.config.script);

    // create a temporary file to store the template
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(template.as_bytes())?;
    let temp_path = temp_file.path().to_owned();
    let temp_dir = temp_path.parent().unwrap();

    // close the file to flush the buffer
    let _temp_file = temp_file.into_temp_path();

    // Execute the command with timeout
    debug!("Starting Playwright session id: {}", session_id);
    let mut command = Command::new(&self.node_path);
    let command = command
      .arg(&temp_path)
      .arg(session_id.to_string())
      .current_dir(temp_dir)
      .stdout(Stdio::piped())
      .stderr(Stdio::piped());

    // Add environment variables
    for (key, value) in &self.env {
      command.env(key, value);
    }

    let child = command.spawn()?;

    let status = child.wait_with_output().await?;
    if !status.status.success() {
      error!("Playwright execution failed: {:?}", status);
      return Err(PlaywrightError::ExecutionError("Playwright execution failed".into()));
    }

    let stdout = String::from_utf8_lossy(&status.stdout).to_string();
    let stderr = String::from_utf8_lossy(&status.stderr).to_string();

    // Set a timeout
    // let timeout = Duration::from_secs(self.config.timeout_seconds);
    // let _ = match child.wait_timeout(timeout)? {
    //   Some(status) =>
    //     if let Some(code) = status.code() {
    //       code
    //     } else {
    //       error!("Process terminated by signal: {:?}", status);
    //       return Err(PlaywrightError::ExecutionError("Process terminated by signal".into()));
    //     },
    //   None => {
    //     child.kill()?;
    //     error!("Process timed out after {:?}", timeout);
    //     return Err(PlaywrightError::ExecutionError("Process timed out".into()));
    //   },
    // };

    // Convert output to string
    // let stdout = match child.stdout.take() {
    //   Some(mut stdout_stream) => {
    //     let mut stdout = String::new();
    //     stdout_stream.read_to_string(&mut stdout)?;
    //     stdout
    //   },
    //   None => String::new(),
    // };

    // let stderr = match child.stderr.take() {
    //   Some(mut stderr_stream) => {
    //     let mut stderr = String::new();
    //     stderr_stream.read_to_string(&mut stderr)?;
    //     stderr
    //   },
    //   None => String::new(),
    // };

    let output = PlaywrightOutput { stdout, stderr };

    Ok(output)
  }
}

mod tests {
  use super::*;

  const EXAMPLE_DEVELOPER_SCRIPT: &str = r#"
await page.goto("https://pseudo-bank.pluto.dev");

const username = page.getByRole("textbox", { name: "Username" });
const password = page.getByRole("textbox", { name: "Password" });

let input = await prompt([
  { title: "Username", types: "text" },
  { title: "Password", types: "password" },
]);

await username.fill(input.inputs[0]);
await password.fill(input.inputs[1]);

const loginBtn = page.getByRole("button", { name: "Login" });
await loginBtn.click();

await page.waitForSelector("text=Your Accounts", { timeout: 5000 });

const balanceLocator = page.locator("\#balance-2");
await balanceLocator.waitFor({ state: "visible", timeout: 5000 });
const balanceText = (await balanceLocator.textContent()) || "";
const balance = parseFloat(balanceText.replace(/[$,]/g, ""));

await prove("bank_balance", balance);
"#;

  #[tokio::test]
  async fn test_playwright_script() {
    // Example developer script to inject into the Playwright template
    let session_id = Uuid::new_v4();
    // output of `which node`
    let node_path =
      Command::new("which").arg("node").output().expect("Failed to run `which node`").stdout;
    let node_path = String::from_utf8_lossy(&node_path).trim().to_string();

    let config = PlaywrightRunnerConfig {
      script:          EXAMPLE_DEVELOPER_SCRIPT.to_string(),
      timeout_seconds: 30,
    };
    let runner = PlaywrightRunner::new(
      config,
      PLAYWRIGHT_TEMPLATE.to_string(),
      PathBuf::from(node_path),
      vec![(String::from("DEBUG"), String::from("pw:api"))],
    );

    let result = runner.run_script(&session_id).await;

    if let Err(e) = result {
      eprintln!("Failed to run Playwright script: {:?}", e);
    } else {
      println!("output: {:?}", result.unwrap());
    }
  }
}
