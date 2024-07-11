# Web Prover

## Build

```shell
make client_wasm

cargo build -p tlsnotary --release

# TODO: build origo, client_ios
```

## Test TLS Notary via WASM end to end

```shell
cargo run -p mock_server --release

cargo run -p tlsnotary  --release

cd websocket_proxy
go run main.go

cd client_wasm
npm install
npm run start
open https://localhost:8090 # then watch console
```

## TODOS

* .github/workflows/client_wasm.yaml doesn't pick up cache
* tests/fixture needs cleanup
* client_wasm/README.md needs update
* port websocket_proxy to rust and include it in tlsnotary binary. then remove websocket_proxy dir.
* websocket_proxy should not rely on ?target but listen for TLS ClientHello message and use SNI name as target
* add client_ios implementation
* add origo proxy implemenation
* adapt all clients to work with origo proxy
* abstract common code from client_wasm and client_ios into client
