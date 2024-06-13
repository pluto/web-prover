# Websocket Proxy

```
wasm-client -> Websocket proxy -> target (ie vanilla-go-app)
```

## Usage

```
go run main.go -listen :8050 \
  -tls-cert-path ../vanilla-go-app/certs/server-cert.pem \
  -tls-key-path ../vanilla-go-app/certs/server-key.pem
```
