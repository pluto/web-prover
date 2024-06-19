# tlsn-monorepo
This repository is used to do end-to-end testing on the TLSN protocol.
There are two end to end flows we test here. 
- a rust binary that represents the mobile SDK target
- a web assembly client (`wasm-client`) 

In `tlsn-monorepo` you can think of there being three distinct asynchronus processes:
- The `tlsn/notary-server` notary server who performs garbled-circuit 2-party computation with the client to compute TLS session ciphertext and authentication messages
- The `client`, i.e. a user wanting to make a web proof of some their TLS session with some server
- a mock server, `vanilla-go-app`, that responds to client request with a dummy response.

When testing this flow there are a number of endpoints we have set up on the mock go server that are documented [here](/vanilla-go-app/README.md). Our goal is 

## End to End testing for Mobile Target
The specific binaries for this test are:
- `notary-server` : Representing the notary
- `vanilla-go-app` : Representing a mock server
- `client`: representing a user

You can test the binary mobile target with a simple tui.
```
cargo run -p tester
```
This will test and end to end web proof against a mock go server with the with the default `health` endpoint on the go server which just returns a status OK.
To 
run with other endpoints you can pass the `--endpoint` flag  followed by the endpoint partameters for example: `cargo run -p notary-tester -- --endpoint bin/10KB`. 

## Running Processes Manually
You also have the option to run these processes manaully if you like.

To run the notary server:
```sh
cargo run --release -p notary-server
```

Then you can run the mock go server with
```sh
cd vanilla-go-app
go run main.go -listen 0.0.0.0:8065 \
  -tls-cert-path certs/server-cert.pem \
  -tls-key-path certs/server-key.pem \
  -http-read-timeout 5m -http-write-timeout 5m
```

and the client with :

```sh
cargo run --release -p client 
```

## End to End testing wasm target
TODO