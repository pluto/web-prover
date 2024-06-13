# tlsn-monorepo

to run the notary server:

```sh
cargo run -p notary-server
```

to run the go server:

```sh
go run -mod=mod vanilla-go-app/main.go
```

to run the client:

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