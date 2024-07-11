# web prover

```
make client_wasm

cargo build -p origo --release


cargo run -p origo --release
cargo run -p tlsnotary  --release

cargo run -p mock-server --release
```

## test client wasm end to end

```
cd websocket_proxy
go run main.go

cargo run -p mock_server --release
cargo run -p tlsnotary  --release

cd client_wasm
npm install
npm run start
open https://localhost:8090 # then watch console
```

TODOs:
  * .github/workflows/client_wasm.yaml doesn't pick up cache
  * tests/fixture needs cleanup
  * client_wasm/README.md needs update