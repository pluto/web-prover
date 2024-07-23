# Web Prover

TODO: Web Prover high level explainer  
TODO: Explain project layout  

## Usage

```
make wasm
make ios # TODO
cargo run --release --bin tlsnotary
cargo run --release --bin origo
cargo run --release --bin mock_server
```

## WASM Demo

```
cargo run --release --bin tlsnotary
cargo run --release --bin mock_server
cargo run --release --bin proxy
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

The [client](./client/) crate utilizes `#[cfg(target_arch = "wasm32")]` flags. To ensure that rust-analyzer highlights active code paths that depend on these feature flags, you can configure it in Visual Studio Code. Here’s how:

```
# .vscode/settings.json
{
  "rust-analyzer.cargo.target": "wasm32-unknown-unknown"
}
```

## Known Reproducible Failures

- `error: failed to run custom build command for ring v0.17.8`. If you run into this error you machine is not using the right llvm path and you should prefix this command with `PATH="/opt/homebrew/opt/llvm/bin:$PATH"`. If this still doesn't work install with `brew install llvm`
