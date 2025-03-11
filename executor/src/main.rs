use std::{io::Write, process::Stdio};

use tempfile::NamedTempFile;
use uuid::Uuid;

/// The Playwright template with a placeholder for the script
const PLAYWRIGHT_TEMPLATE: &str = r#"
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

fn run_playwright_script(script: &str) -> Result<(), Box<dyn std::error::Error>> {
  let filled_template = PLAYWRIGHT_TEMPLATE.replace("{{.Script}}", script);

  // Generate a session UUID
  let session_uuid = Uuid::new_v4().to_string();

  let mut temp_file = NamedTempFile::new()?;
  let temp_path = temp_file.path().to_owned();

  temp_file.write_all(filled_template.as_bytes())?;

  // close the file to flush the buffer
  let _temp_file = temp_file.into_temp_path();

  // Execute the command with timeout
  println!("Starting Playwright session with UUID: {}", session_uuid);
  let mut command = std::process::Command::new("node");
  let mut child = command
    .arg(temp_path)
    .arg(session_uuid.clone())
    .env("DEBUG", "pw:api")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;

  // Set a timeout of 20 seconds (matching the Go version)
  // let timeout = Duration::from_secs(20);
  // // kill process after timeout
  // let _ = std::thread::spawn(move || {
  //   std::thread::sleep(timeout);
  //   let _ = child.kill();
  // });

  let output = child.wait_with_output()?;
  println!("Output: {:?}", output);

  // Convert output to string
  let stdout = String::from_utf8_lossy(&output.stdout).to_string();
  let stderr = String::from_utf8_lossy(&output.stderr).to_string();

  println!("Stdout: {}", stdout);
  println!("Stderr: {}", stderr);

  Ok(())
}

const DEVELOPER_SCRIPT: &str = r#"
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

fn main() {
  // Example developer script to inject
  let developer_script = r#"
  await page.goto('https://example.com');
  console.log('Page title:', await page.title());

  // Take a screenshot
  await page.screenshot({ path: 'example.png' });
  console.log('Screenshot taken');
  "#;
  let developer_script = DEVELOPER_SCRIPT;

  let _ = run_playwright_script(developer_script);
}
