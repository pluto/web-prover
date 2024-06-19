# tlsn-monorepo

To run the notary server:

```sh
cargo run -p notary-server
```

To run the go server:

```sh
cd vanilla-go-app
go run main.go -listen 0.0.0.0:8065 \
  -tls-cert-path certs/server-cert.pem \
  -tls-key-path certs/server-key.pem \
  -http-read-timeout 5m -http-write-timeout 5m
```

To run the client:

```sh
cargo run -p client 
```

## Tester
Alternatively, to run the tester you can just do:
```sh
cargo run -p tester
```
in the root directory of the project.
This will run all of the processes in the correct order so that the web prover can be tested.

We currently have one adjustment we can make which changes the timeout for TCP on the Go server. 
Adjust it like so:
```sh
cargo run -p tester -- --tcp-idle-timeout 1m5s
```
and to see the help menu,
```sh
cargo run -p tester -- --help
```