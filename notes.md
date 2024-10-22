To get iOS to work:

1. `cd proofs && make circuits && cd ..`
2. `make ios-sim`
2. `make wasm && make wasm-demo` (Maybe needed for now?)
3. `RUST_LOG=debug cargo run --release -p notary -- --config ./fixture/notary-config.toml`