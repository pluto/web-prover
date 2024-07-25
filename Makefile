wasm:
	@# TODO: -C lto fails with `lto can only be run for executables, cdylibs and static library outputs`
	-cargo install wasm-pack
	cd client_wasm && \
	  PATH="/opt/homebrew/opt/llvm/bin:$$PATH" RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals -C opt-level=z" \
	  ~/.cargo/bin/wasm-pack build --release --target web ./ -- \
	    -Z build-std=panic_abort,std

ios:
	rustup target add aarch64-apple-ios
	rustup target add aarch64-apple-ios-sim
	cargo build -p client_ios --release --target aarch64-apple-ios # builds target/aarch64-apple-ios/release/libclient_ios.a
	cargo build -p client_ios --release --target aarch64-apple-ios-sim # builds target/aarch64-apple-ios-sim/release/libclient_ios.a
	cbindgen --lang c --crate client_ios --output target/aarch64-apple-ios/release/libclient_ios.h # brew install cbindgen
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libclient_ios.a \
		-headers target/aarch64-apple-ios/release/libclient_ios.h \
		-library target/aarch64-apple-ios-sim/release/libclient_ios.a \
		-headers target/aarch64-apple-ios/release/libclient_ios.h \
		-output target/aarch64-apple-ios/release/libclient_ios.xcframework

wasm-demo/node_modules:
	cd client_wasm/demo && npm install

wasm-demo: wasm-demo/node_modules
	cd client_wasm/demo && npm run start

.PHONY: wasm wasm-demo ios
