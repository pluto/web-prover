build:
	wasm-pack build --release --target web .

serve:
	miniserve -i 0.0.0.0 -p 8090 \
	  --tls-cert ../vanilla-go-app/certs/server-cert.pem \
	  --tls-key ../vanilla-go-app/certs/server-key.pem \
	  --index index.html ./demo

.PHONY: build serve
