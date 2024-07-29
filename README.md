# Web Prover

TODO: Web Prover high level explainer  
TODO: Explain project layout  

## Usage

```
make wasm
make ios
cargo run --release -p notary -- --config ./fixture/notary-config.toml
cargo run --release --bin mock_server
```

## WASM Demo

```
cargo run --release -p notary -- --config ./fixture/notary-config.toml
cargo run --release --bin mock_server
make wasm
make wasm-demo
open https://localhost:8090
```

## Feature flags

TODO: target_arch explainer (for wasm)  
TODO: target_os explainer (for ios)  
TODO: explain all feature flags  


## Development

### Configuring rust-analyzer for wasm32

```
# .vscode/settings.json
{
  "rust-analyzer.cargo.target": "wasm32-unknown-unknown",
  "rust-analyzer.cargo.features": ["websocket"]
}

# Cargo.toml
# set members to:
members =["client", "client_wasm"]
```

### Configuring rust-analyzer for ios

Note that this only works on Mac. The iOS target cannot be built on Linux.

```
# .vscode/settings.json
{
  "rust-analyzer.cargo.target": "aarch64-apple-ios",
  "rust-analyzer.cargo.features": []
}

# Cargo.toml
# set members to:
members =["client", "client_ios"]
```

## Known Issues

#### `error: failed to run custom build command for ring v0.17.8`

You'll have to install LLVM, ie. `brew install llvm`, and then update your
`export PATH="$(brew --prefix)/opt/llvm/bin:$PATH"`.

rust-analyzer might not pick up on the llvm path, you can manually let it know via:

```
# .vscode/settings.json
{
  "rust-analyzer.cargo.extraEnv": {
    "PATH": "<paste your $PATH here>" // note, $PATH env substitutions don't work
  }
}
```
