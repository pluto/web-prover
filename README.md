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