use std::{env, process::Command};

use rust_witness::transpile::transpile_wasm;

fn main() {
  let output =
    Command::new("git").args(["rev-parse", "HEAD"]).output().expect("Failed to execute git");
  let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
  println!("cargo:rustc-env=GIT_HASH={}", git_hash);
  println!("cargo:rerun-if-changed=examples");

  let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
  let out_dir = env::var("OUT_DIR").unwrap();
  println!("target_arch={}, out_dir={}", target_arch, out_dir.clone());

  // NOTE: w2c2 cannot build the necessary C objects for witness generation for wasm
  // due to a dependency on the stdlib (guessing). Skip for wasm.
  if target_arch != "wasm32" {
    // This function will recursively search the target directory
    // for any files with the `wasm` extension and compile
    // them to C and link them
    transpile_wasm("examples/circuit_data/".to_string()); // This will walk into all `*_js` dirs
  }
}
