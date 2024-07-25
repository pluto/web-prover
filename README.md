# Web Prover

TODO: Web Prover high level explainer  
TODO: Explain project layout  

## Usage

```
make wasm
make ios # TODO
cargo run --release -p notary
cargo run --release --bin mock_server
```

## WASM Demo

```
cargo run --release -p notary
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

### Mac 

```
brew instal llvm openssl@v3 cbindgen
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
```

### Linux

```
apt install llvm libssl-dev cbindgen
```

### Configuring rust-analyzer

The [client](./client/) crate utilizes `#[cfg(target_arch = "wasm32")]` flags. To ensure that rust-analyzer highlights active code paths that depend on these feature flags, you can configure it in Visual Studio Code. Here’s how:

```
# .vscode/settings.json
{
  "rust-analyzer.cargo.target": "wasm32-unknown-unknown",
  "rust-analyzer.cargo.features: [""], // List of features to activate
  "rust-analyzer.cargo.extraEnv": {
    "PATH": "<paste your $PATH here>", // does not support $PATH variable substitutions
    "OPENSSL_DIR": "/opt/homebrew/opt/openssl@3" // depends on your system
  }
}
```

## Known Issues

- `error: failed to run custom build command for ring v0.17.8`. Install LLVM deps, see above.
