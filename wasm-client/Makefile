build:
	wasm-pack build --release --target web .

serve:
	miniserve -i 0.0.0.0 -p 8090 \
	  --tls-cert ../vanilla-go-app/certs/server-cert.pem \
	  --tls-key ../vanilla-go-app/certs/server-key.pem \
	  --header "Cross-Origin-Embedder-Policy:require-corp" \
	  --header "Cross-Origin-Opener-Policy:same-origin" \
	  --header "Cross-Origin-Resource-Policy:cross-origin" \
	  --index index.html ./demo

	  # --header "Content-Security-Policy:script-src 'self' 'unsafe-eval' 'unsafe-inline' 'wasm-unsafe-eval'" \
	  # --header "Content-Security-Policy:default-src 'self' 'unsafe-eval' 'unsafe-inline' https://localhost:* wss://localhost:*; script-src 'self' 'unsafe-eval' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'" \

.PHONY: build serve
