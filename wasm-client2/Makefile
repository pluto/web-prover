build:
	wasm-pack build --release --target web .

serve:
	miniserve -i 0.0.0.0 -p 8091 \
	  --tls-cert ../vanilla-go-app/certs/server-cert.pem \
	  --tls-key ../vanilla-go-app/certs/server-key.pem \
	  --header "Cross-Origin-Embedder-Policy:require-corp" \
	  --header "Cross-Origin-Opener-Policy:same-origin" \
	  --index index.html ./demo

.PHONY: build serve
