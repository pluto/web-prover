use std::process::Command;

fn main() {
  if !cfg!(target_arch = "wasm32") {
    let output =
      Command::new("git").args(["rev-parse", "HEAD"]).output().expect("Failed to execute git");

    let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();

    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/main");
  } else {
    // Set the PATH environment variable for wasm32 target
    let output = Command::new("wasm-pack")
      .args(["build", "--target", "web", "."])
      .output()
      .expect("Wasm-pack failed to build");

    if !output.status.success() {
      eprintln!("Wasm-pack build failed with status: {}", output.status);
      if let Some(code) = output.status.code() {
        std::process::exit(code);
      } else {
        std::process::exit(1);
      }
    }
  }
}
