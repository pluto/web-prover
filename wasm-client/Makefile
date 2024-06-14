build:
	wasm-pack build --release --target web .

serve:
	miniserve -i 0.0.0.0 -p 8090 \
	  --tls-cert ../vanilla-go-app/certs/server-cert.pem \
	  --tls-key ../vanilla-go-app/certs/server-key.pem \
	  --header "Content-Security-Policy:default-src 'self' 'unsafe-eval' 'unsafe-inline' https://localhost:* wss://localhost:*; script-src 'self' 'unsafe-eval' 'unsafe-inline'" \
	  --index index.html ./demo


.PHONY: build serve
