# Web Prover
This repository is used to do end-to-end testing on the TLSN protocol.
There are two end to end flows we test here. 
- a rust binary that represents the mobile SDK target
- a web assembly client (`wasm-client`) 

In `tlsn-monorepo` you can think of there being three distinct asynchronus processes:
- The `tlsn/notary-server` notary server who performs garbled-circuit 2-party computation with the client to compute TLS session ciphertext and authentication messages
- The `client`, i.e. a user wanting to make a web proof of some their TLS session with some server
- a mock server, `mock_target`, that responds to client request with a dummy response.

When testing this flow there are a number of endpoints we have set up on the mock go server that are documented [here](/vanilla-go-app/README.md). Our goal is 

## End to End testing for Mobile Target
The specific binaries for this test are:
- `notary-server` : Representing the notary
- `mock_target` : Representing a mock server
- `client`: representing a user

You can test the binary mobile target with a simple TUI.
```
cargo run -p tester
```
This will test and end to end web proof against a mock go server with the with the default `health` endpoint on the go server which just returns a status OK.
To run with other endpoints you can pass the `--endpoint` flag followed by the endpoint parameters for example: `cargo run -p notary-tester -- --endpoint bin/10KB`. 

## Running Processes Manually
You also have the option to run these processes manaully if you like.

To run the notary server:
```sh
cargo run --release -p notary-server
```

Then you can run the mock go server with
```sh
cargo run --release -p mock_target
```

and the client with:

```sh
cargo run --release -p client 
```

## End to End testing WASM target
TODO

## Known Reproducible Failures
There have a been a number of reproducible failures we have discovered.

1. [Exceed Transcript Size](https://github.com/pluto/tlsn-monorepo/issues/15)
2. [Transfer-Encoding](https://github.com/pluto/tlsn-monorepo/issues/14)