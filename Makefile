check:
	cargo check
	(cd client_wasm && cargo check)

client_wasm:
	cargo install wasm-pack
	~/.cargo/bin/wasm-pack build --target web --release --out-dir ./target/wasm32-pkg ./client_wasm


.PHONY: check client_wasm