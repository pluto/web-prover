# Web Prover

The web-prover repository contains build pipelines for two types of Web Proofs: [TLSNotary proofs](https://tlsnotary.org/) and [Origo proofs](https://eprint.iacr.org/2024/447.pdf). Most of this work centers around the Origo proofs as we built it from the ground up, while the TLSNotary team has done most of the lifting for their work.

The Origo pipeline of the web-prover repository is to test and build a collection of circom generated artificts used for Web Proofs and compile them to two primary targets with a Nova folding backend to be used in a developer SDK. The two compilation targets we compile to are iOS mobile and Web Assembly and are referenced as the client.

The repository is laid out as follows:

- `bin/`: a mock server for testing.
- `client/`: contains components for the client that are shared across both WASM and iOS targets.
- `client_ios/`: contains client components specific to the iOS target.
- `client_wasm/`: contains client components specific to the WASM target.
- `fixture`: contains transport layer artifacts for testing such as TLS certificates and configuration files for both Origo and TLSNotary.
- `notary`: contains binaries for our notary server which can notarize with both the TLSNotary and the Origo flow.
- `proofs`: contains all of our circom artifacts for the Origo proofs as well as a set of extractor proofs for selective disclosure over response data.
- `tls`: contains a fork of rustls with a custom cryptography backend.

Documentation is evolving throughout the repository as the pipeline becomes more stable.

## Usage

```
make wasm
make ios
cargo run --release -p notary -- --config ./fixture/notary-config.toml
cargo run --release -p client -- --config ./fixture/client.tlsn_tcp_local.json
cargo run --release --bin mock_server
```

## WASM Demo

```
cargo run --release -p notary -- --config ./fixture/notary-config.toml
make wasm
make wasm-demo
open https://localhost:8090
```

## Native Client Demo

```
cargo run --release -p notary -- --config ./fixture/notary-config.toml

# TLSNotary flow (requires --release flag or it will be slow, try release mode for notary as well)
cargo run --release -p client -- --config ./fixture/client.tlsn_tcp_local.json

# Origo flow
cargo run --release -p client -- --config ./fixture/client.origo_tcp_local.json

# TEE flow (uses DummyToken so it can run outside of TEE)
cargo run --release -p client -- --config ./fixture/client.tee_tcp_local.json
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

#### `Error: LLVM version must be 18 or higher. Found xxxxxx.`

- Follow instruction at https://apt.llvm.org/

#### `[wasm-validator error in function xxxx] unexpected false: all used features should be allowed, on yyyy`

- Your existing `wasm-opt` installation may conflict with the one in `wasm-pack`. Check for local installation: `$ which wasm-opt && wasm-opt --version`
- Consider updating `wasm-pack`:  `$ cargo install --force wasm-pack`

## Release

1. Update the `version` field in the appropriate `Cargo.toml` file.
2. Create a pull request with the version update.
3. Merge the pull request.

Once merged, the package will be automatically released. **Note:** Releases are immutable.

The following crates are checked for version changes:

- `notary/Cargo.toml`
- `client_wasm/Cargo.toml`
- `client_ios/Cargo.toml`
