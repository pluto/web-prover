# TLSN WASM Demo

```shell
cd websocket-proxy
go run main.go -listen 0.0.0.0:8050 \
  -tls-cert-path ../vanilla-go-app/certs/server-cert.pem \
  -tls-key-path ../vanilla-go-app/certs/server-key.pem

cd vanilla-go-app
go run main.go -listen 0.0.0.0:8065 \
  -tls-cert-path ./certs/server-cert.pem \
  -tls-key-path ./certs/server-key.pem \
  -http-read-timeout 5m -http-write-timeout 5m

cargo run -p notary-server -- --config-file ./notary-config.yaml
```

```
npm install
npm run start
open https://localhost:8090
```

TODO: It's possible to run headless tests, which could be interesting for some unit tests.
