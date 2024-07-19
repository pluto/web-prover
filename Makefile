wasm:
	@# TODO use `-- --crate-type=cdylib --crate-type=rlib` in wasm-pack command below
	@# once https://github.com/rustwasm/wasm-pack/pull/1329 has been merged.
	@# Docs: https://doc.rust-lang.org/reference/linkage.html
	@# For now, manually add [lib] section to Cargo.toml for WASM compilation.
	cargo install wasm-pack
	cp Cargo.toml Cargo.toml.backup
	echo '\n\n[lib]\ncrate-type = ["cdylib", "rlib"]' >> Cargo.toml
	~/.cargo/bin/wasm-pack build --release --target web ./ -- \
	  -Z build-std=panic_abort,std \
	  --features=websocket,tracing
	mv Cargo.toml.backup Cargo.toml

ios:
	# TODO

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

.PHONY: wasm ios libs xcframework cbindgen
