use rust_witness::transpile::transpile_wasm;

fn main() {
  // This function will recursively search the target directory
  // for any files with the `wasm` extension and compile
  // them to C and link them
  transpile_wasm("examples/circuit_data/".to_string()); // This will walk into all `*_js` dirs
}
