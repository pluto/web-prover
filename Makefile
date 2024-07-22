wasm:
	cargo install wasm-pack
	cd client_wasm && \
	  RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals" \
	  ~/.cargo/bin/wasm-pack build --release --target web ./ -- \
	    -Z build-std=panic_abort,std

ios:
	# TODO

wasm-demo/node_modules:
	cd wasm-demo && npm install

wasm-demo: wasm-demo/node_modules
	cd wasm-demo && npm run start

libs:
	# TODO ios target
	-mkdir build
	cargo build --release --target aarch64-apple-ios
	cargo build --release --target aarch64-apple-ios-sim
	cp target/aarch64-apple-ios/release/libtlsnotary.a build/tlsnotary-ios-device.a
	cp target/aarch64-apple-ios-sim/release/libtlsnotary.a build/tlsnotary-ios-simulator.a

cbindgen:
	# TODO ios target
	cbindgen --lang c --crate tlsnotary --output build/tlsnotary.h

xcframework:
	# TODO ios target
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libtlsnotary.a \
		-headers ./build/tlsnotary.h \
		-library target/aarch64-apple-ios-sim/release/libtlsnotary.a \
		-headers ./build/tlsnotary.h \
		-output build/tlsnotary.xcframework

.PHONY: wasm wasm-demo ios libs xcframework cbindgen
