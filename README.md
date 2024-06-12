# tlsn-monorepo

to run the notary server:

```
cargo run -p notary-server
```

to run the go server:

```
cd vanilla-go-app/
go run main.go -listen :8065 \
  -tls-cert-path ./certs/server-cert.pem \
  -tls-key-path ./certs/server-key.pem
```

to run the client:

```
cargo run -p client 
```