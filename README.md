<p align="center">
  <img src="https://raw.githubusercontent.com/pluto/.github/main/profile/assets/assets_ios_Pluto-1024%401x.png" alt="Pluto Logo" width="50" height="50">
  <br>
  <b style="font-size: 24px;">Pluto</b>
</p>
<p align="center">
  <a href="https://t.me/pluto_xyz/1"><img src="https://img.shields.io/badge/Telegram-Group-8B5CF6?style=flat-square&logo=telegram&logoColor=white&labelColor=24292e&scale=1.5" alt="Telegram"></a>
  <a href="https://docs.pluto.xyz/"><img src="https://img.shields.io/badge/Docs-Pluto-8B5CF6?style=flat-square&logo=readme&logoColor=white&labelColor=24292e&scale=1.5" alt="Docs"></a>
  <img src="https://img.shields.io/badge/License-Apache%202.0-8B5CF6.svg?label=license&labelColor=2a2f35" alt="License">
</p>

---

# Web Prover

[![web-prover workflow](https://github.com/pluto/web-prover/actions/workflows/web-prover.yaml/badge.svg)](https://github.com/pluto/web-prover/actions/workflows/web-prover.yaml)
[![docs](https://img.shields.io/badge/docs-e28f00)](https://docs.pluto.xyz)

The Web Prover is infrastructure for generating Web Proofs with [Trusted Execution Environments (TEEs)](https://pluto.xyz/blog/web-proof-techniques-tee-mode).

The default option for generating Web Proofs is to use the Pluto-hosted service. We recommend using the Javascript SDK, which uses a Pluto-hosted notary. Learn more [here](https://docs.pluto.xyz/guides/using-the-javascript-sdk). Developers do not need to set up the prover or host it themselves, unless they explicitly want to self-host this infrastructure or build custom infrastructure.

## How to get started

Visit the [Pluto documentation](https://docs.pluto.xyz) for integration guides, conceptual overviews, and reference materials.

If you have any questions, please reach out to any of Pluto's [team members](https://pluto.xyz/team) or join our [Telegram](https://t.me/pluto_xyz) to ask questions. We'd love to hear from you!

## Development

### Repo layout

- `client`: contains components for the client that are shared across both WASM and iOS targets.
- `fixture`: contains testing artifacts such as TLS certificates and configuration files.
- `notary`: notary server which can notarize TEE proofs.
- `core`: core features of web proofs, i.e. manifest validation, parser, extraction.

### Usage

```
cargo run -p web-prover-notary -- --config ./fixture/notary-config.toml
cargo run -p web-prover-client -- --config ./fixture/client.proxy.json
```

## Security Status

As of February 2025, the code in this repository is operational on Ethereum testnets, and we have begun the security auditing process.

Following completion of audits, we plan to launch with protective guardrails in place, which will be gradually adjusted and removed as the system demonstrates stability in real-world conditions.

## Release

1. Update the `version` field in the appropriate `Cargo.toml` file.
2. Create a pull request with the version update.
3. Merge the pull request.

Once merged, the package will be automatically released.
**Note:** Releases are immutable.

The following crates are checked for version changes:

- `notary/Cargo.toml`
- `client/Cargo.toml`