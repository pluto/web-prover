# web prover

```
make client_wasm

cargo build -p origo --release


cargo run -p origo --release
cargo run -p mock-server --release

```

TODOs:
  * .github/workflows/client_wasm.yaml doesn't pick up cache
  * tests/fixture needs cleanup
  * client_wasm/README.md needs update