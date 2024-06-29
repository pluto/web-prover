# Web Prover
This repository is used to do end-to-end testing on the TLSN protocol.
There are two end to end flows we test here. 
- a rust binary that represents the mobile SDK target
- a web assembly client (`wasm-client`) 

In `web-prover` you can think of there being three distinct asynchronus processes for every notarization:
- The `notary/` directory which has our different notaries. For example there is the `tlsn` who performs garbled-circuit 2-party computation with the client to compute TLS session ciphertext and authentication messages
- The `client/`, i.e. a user wanting to make a web proof of some their TLS session with some server
- a mock server, `mock_target`, that responds to client request with a dummy response.

## End to End testing for Mobile Target
The specific binaries for this test are:
- `notary/src/bin/tlsn` : Representing the notary server
- `mock_target` : Representing a mock server (mocking venmo)
- `clien/src/bin/mock_client`: representing a user

1) Start the notary. From the root directory run:
```sh
cargo run --release -p notary --bin tlsn
```
2) Run the mock target.
```sh
cargo run -p mock_target
```
3) Run the mock client
```sh
cargo run --release --bin mock_client
```


<!-- You can test the binary mobile target with a simple TUI.
```
cargo run -p tester
```
This will test and end to end web proof against a mock go server with the with the default `health` endpoint on the go server which just returns a status OK.
To run with other endpoints you can pass the `--endpoint` flag followed by the endpoint parameters for example: `cargo run -p notary-tester -- --endpoint bin/10KB`.  -->

## End to End testing WASM target
TODO

## Known Reproducible Failures
There have a been a number of reproducible failures we have discovered.

1. [Exceed Transcript Size](https://github.com/pluto/tlsn-monorepo/issues/15)
2. [Transfer-Encoding](https://github.com/pluto/tlsn-monorepo/issues/14)