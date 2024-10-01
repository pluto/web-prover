wasm:
	@# TODO: -C lto fails with `lto can only be run for executables, cdylibs and static library outputs`
	-cargo install wasm-pack
	-ln -s ./proofs/examples/circuit_data/ ./client_wasm/demo/static/build
	cd client_wasm && \
	  PATH="/opt/homebrew/opt/llvm/bin:$$PATH" RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals -C opt-level=z -C link-arg=--max-memory=3221225472" \
	  rustup run nightly ~/.cargo/bin/wasm-pack build --release --target web ./ -- \
	    -Z build-std=panic_abort,std

wasm-debug:
	@# TODO: -C lto fails with `lto can only be run for executables, cdylibs and static library outputs`
	-cargo install wasm-pack
	-ln -s ./proofs/examples/circuit_data/ ./client_wasm/demo/static/build
	cd client_wasm && \
	  PATH="/opt/homebrew/opt/llvm/bin:$$PATH" RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals -C opt-level=z -C link-arg=--max-memory=3221225472" \
	  rustup run nightly ~/.cargo/bin/wasm-pack build --debug --target web ./ -- \
	    -Z build-std=panic_abort,std

ios:
	-cargo install cbindgen
	rustup target add aarch64-apple-ios
	rustup target add aarch64-apple-ios-sim
	RUSTFLAGS="-C panic=unwind" cargo build -p client_ios --release --target aarch64-apple-ios # builds target/aarch64-apple-ios/release/libclient_ios.a
	RUSTFLAGS="-C panic=unwind" cargo build -p client_ios --release --target aarch64-apple-ios-sim # builds target/aarch64-apple-ios-sim/release/libclient_ios.a
	~/.cargo/bin/cbindgen --lang c --crate client_ios --output target/aarch64-apple-ios/release/libclient_ios.h
	-rm -r target/aarch64-apple-ios/release/libclient_ios.xcframework
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libclient_ios.a \
		-headers target/aarch64-apple-ios/release/libclient_ios.h \
		-output target/aarch64-apple-ios/release/libclient_ios.xcframework

wasm-demo/node_modules:
	cd client_wasm/demo && npm install

wasm-demo: wasm-demo/node_modules
	cd client_wasm/demo && npm run start

.PHONY: wasm wasm-debug wasm-demo ios
