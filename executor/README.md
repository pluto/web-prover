# Web Prover Executor

## Set up playground

```
npx playwright install
npm install -g playwright-core

git clone git@github.com:pluto/playwright-playground.git
cd playwright-playground
npm install -g ./playwright-utils

export NODE_PATH=$(npm root -g)
```

## Run example

Run notary in a separate terminal:
```
RUST_LOG=debug cargo run -p web-prover-notary -- --config ./fixture/notary-config.toml
```

Run example executor:
```
cargo run -p web-prover-executor
```