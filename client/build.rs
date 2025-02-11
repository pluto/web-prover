use std::{env, process::Command};

fn main() {
  let output =
    Command::new("git").args(["rev-parse", "HEAD"]).output().expect("Failed to execute git");
  let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
  println!("cargo:rustc-env=GIT_HASH={}", git_hash);
  println!("cargo:rerun-if-changed=../.git/HEAD");
  println!("cargo:rerun-if-changed=../.git/refs/heads/main");

  // add custom trusted CA (useful for local debugging)
  if let Ok(notary_ca_cert_path) = env::var("NOTARY_CA_CERT_PATH") {
    println!("Using NOTARY_CA_CERT_PATH={}", notary_ca_cert_path);
    println!("cargo:rustc-cfg=feature=\"notary_ca_cert\"");
    println!("cargo:rustc-env=NOTARY_CA_CERT_PATH={}", notary_ca_cert_path);
  }
  // TODO rerun does not trigger if env variable changes
  // https://github.com/rust-lang/cargo/issues/10358
  // workaround? run `cargo clean`
  // println!("cargo:rerun-if-env-changed=NOTARY_CA_CERT_PATH");

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
