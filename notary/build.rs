use std::process::Command;

fn main() {
  let output =
    Command::new("git").args(["rev-parse", "HEAD"]).output().expect("Failed to execute git");
  let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
  println!("cargo:rustc-env=GIT_HASH={}", git_hash);
  println!("cargo:rerun-if-changed=../.git/HEAD");
  println!("cargo:rerun-if-changed=../.git/refs/heads/main");

  // make workspace's Cargo.toml's web_prover_circuits_version available
  let metadata = cargo_metadata::MetadataCommand::new()
    .manifest_path("../Cargo.toml")
    .exec()
    .expect("Failed to read cargo metadata");
  if let Some(version) = metadata.workspace_metadata.get("web_prover_circuits_version") {
    println!("cargo:rustc-env=WEB_PROVER_CIRCUITS_VERSION={}", version.as_str().unwrap());
  }
  println!("cargo:rerun-if-changed=../Cargo.toml");
}
