Before running the client and notary, make sure to run the following commands:
```
npm i -g playwright-core
export NODE_PATH=$(npm root -g)
```

Also, need to have the `playwright-playground` installed globally:
```
npm i -g ./playwright-utils
```
from the `playwright-playground` repo.

```
RUST_LOG=debug cargo run -p web-prover-notary -- --config ./fixture/notary-config.toml
cargo run -p web-prover-client -- --config ./fixture/client.proxy.json
```
- currently stuck at notary sent prompt request to client -> client responded -> notary received response -> notary sends back to playwright