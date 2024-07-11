check:
	cargo check
	cd client_wasm && cargo check

client_wasm:
	cargo install wasm-pack
	cd client_wasm && ~/.cargo/bin/wasm-pack build --target web --release --out-dir ./target/wasm32-pkg

client_wasm_test:
	# TODO
	# cargo install wasm-pack
	# cd client_wasm && ~/.cargo/bin/wasm-pack test --firefox

.PHONY: \
  check \
  client_wasm client_wasm_test \
  origo \
  web
