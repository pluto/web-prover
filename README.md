# Web Prover

[![web-prover workflow](https://github.com/pluto/web-prover/actions/workflows/web-prover.yaml/badge.svg)](https://github.com/pluto/web-prover/actions/workflows/web-prover.yaml)
[![codecov](https://codecov.io/gh/pluto/web-prover/branch/main/graph/badge.svg)](https://codecov.io/gh/pluto/web-prover)
[![docs](https://img.shields.io/badge/docs-e28f00)](https://docs.pluto.xyz)

The Web Prover is infrastructure for generating Web Proofs. There are 3 components of the Web Prover — (1) the Client Crates, which run inside of the app or browser; (2) Notary Crate, which is a hosted service; and (3) the Proofs Crate, which handles running the circuits through the `client-side-prover`.

The default option for generating Web Proofs is to use the Pluto-hosted service. We recommend using the Javascript SDK, which uses a Pluto-hosted notary. Learn more [here](https://docs.pluto.xyz/guides/using-the-javascript-sdk). Developers do not need to set up the prover or host it themselves, unless they explicitly want to self-host this infrastructure or build custom infrastructure.

Pluto's Web Prover repo contains the source code for the three types of Web Proofs:
- [Origo proofs](https://pluto.xyz/blog/web-proof-techniques-origo-mode),
- [Trusted Execution Environment (TEE) proofs](https://pluto.xyz/blog/web-proof-techniques-tee-mode) and
- [MPC proofs](https://pluto.xyz/blog/web-proof-techniques-mpc-mode) via TLSNotary


## How to get started

Visit the [Pluto documentation](https://docs.pluto.xyz) for integration guides, conceptual overviews, and reference materials.

If you have any questions, please reach out to any of Pluto's [team members](https://pluto.xyz/team) or join our [Telegram](https://t.me/pluto_xyz) to ask questions. We'd love to hear from you!

## Development

### Repo layout

- `bin`: a mock server for testing.
- `client`: contains components for the client that are shared across both WASM and iOS targets.
- `client_ios`: contains client components specific to the iOS target.
- `client_wasm`: contains client components specific to the WASM target.
- `fixture`: contains testing artifacts such as TLS certificates and configuration files.
- `notary`: notary server which can notarize MPC/ Origo/ TEE proofs.
- `proofs`: contains all of our circom artifacts for the Origo proofs as well as a set of extractor proofs for selective disclosure over response data.

### Setup
- Install rust nightly: `rustup install toolchain nightly`
- Run `make artifacts` to download circuit artifacts required for Web Prover proxy mode
- Compilation errors? Have a look at [KNOWN_ISSUES.md](KNOWN_ISSUES.md)

### Native Client Development

```
cargo run -p notary -- --config ./fixture/notary-config.toml

# TLSNotary flow (requires --release flag or it will be slow, try release mode for notary as well)
cargo run --release -p client -- --config ./fixture/client.tlsn_tcp_local.json

# Origo flow
cargo run -p client -- --config ./fixture/client.origo_tcp_local.json

# TEE flow (uses DummyToken so it can run outside of TEE)
cargo run -p client -- --config ./fixture/client.tee_tcp_local.json
```

### WASM Development in Browser

```
cargo run -p notary -- --config ./fixture/notary-config.toml
make wasm
make wasm-demo
open https://localhost:8090
```

## Security Status

As of February 2025, the code in this repository is operational on Ethereum testnets, and we have begun the security auditing process.

While we are actively developing towards a production release in Q2 2025, the system is not yet recommended for production use.

Following completion of audits, we plan to launch with protective guardrails in place, which will be gradually adjusted and removed as the system demonstrates stability in real-world conditions.

## Release

1. Update the `version` field in the appropriate `Cargo.toml` file.
2. Create a pull request with the version update.
3. Merge the pull request.

Once merged, the package will be automatically released.
**Note:** Releases are immutable.

The following crates are checked for version changes:

- `notary/Cargo.toml`
- `client_wasm/Cargo.toml`
- `client_ios/Cargo.toml`

## rust-analyzer configuration

### wasm32 target

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

### ios target

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
