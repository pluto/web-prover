use rust_witness::transpile::transpile_wasm;

fn main() {
  // This function will recursively search the target directory
  // for any files with the `wasm` extension and compile
  // them to C and link them
  transpile_wasm("examples/circuit_data/parse_fold_batch_js/".to_string());
}
