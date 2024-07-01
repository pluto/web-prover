# Web Prover
This repository is used to do end-to-end testing on the TLSN protocol.
There are two end to end flows we test here. 
- a rust binary that represents the mobile SDK target
- a web assembly client (`wasm-client`) 

## Client Abstraction

The client is designed to be egnostic both over build targets, the underlying networking protocol, and the underlying notarization scheme. 

## End to End testing for Mobile Target

1) Start the notary. From the root directory run:
```sh
cargo run -p webprover --bin tlsn --release
```
2) Run the mock target.
```sh
cargo run -p webprover --bin mock_target
```
3) Run the mock client
```sh
cargo run -p webprover --bin mock_client
```


<!-- You can test the binary mobile target with a simple TUI.
```
cargo run -p tester
```
This will test and end to end web proof against a mock go server with the with the default `health` endpoint on the go server which just returns a status OK.
To run with other endpoints you can pass the `--endpoint` flag followed by the endpoint parameters for example: `cargo run -p notary-tester -- --endpoint bin/10KB`.  -->

## End to End testing WASM target
TODO

Run wasm with 
```sh
wasm-pack build --target web wasm-proxy-client     
``` 


## Known Reproducible Failures

- `error: failed to run custom build command for ring v0.17.8`. If you run into this error you machine is not using the right llvm path and you should prefix this command with `PATH="/opt/homebrew/opt/llvm/bin:$PATH"`. If this still doesn't 

There have a been a number of reproducible failures we have discovered.

1. [Exceed Transcript Size](https://github.com/pluto/tlsn-monorepo/issues/15)
2. [Transfer-Encoding](https://github.com/pluto/tlsn-monorepo/issues/14)
