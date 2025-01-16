artifacts:
	cd proofs && make web-prover-circuits

wasm: artifacts
	@# NOTE: This build depends on RUSTFLAGS in the client_wasm/.cargo/config.toml
	-cargo install wasm-pack
	-cd client_wasm/demo/static && rm -f build && ln -s ../../../proofs/web_proof_circuits build && cd ../../..
	cd client_wasm && \
	  PATH="/opt/homebrew/opt/llvm@18/bin:/opt/homebrew/opt/llvm/bin:$$PATH" \
	  rustup run ~/.cargo/bin/wasm-pack build --release --target web ./ -- \
	    -Z build-std=panic_abort,std

wasm-debug: artifacts
	-cargo install wasm-pack
	-cd client_wasm/demo/static && rm -f build && ln -s ../../../proofs/web_proof_circuits build && cd ../../..
	cd client_wasm && \
	  PATH="/opt/homebrew/opt/llvm@18/bin:opt/homebrew/opt/llvm/bin:$$PATH" \
	  rustup run ~/.cargo/bin/wasm-pack build --debug --target web ./ -- \
	    -Z build-std=panic_abort,std

ios-sim: artifacts
	-cargo install cbindgen
	rustup target add aarch64-apple-ios-sim --toolchain nightly-2024-10-28
	NOTARY_CA_CERT_PATH="../../fixture/certs/ca-cert.cer" RUSTFLAGS="-C panic=unwind" cargo build -p client_ios --release --target aarch64-apple-ios-sim # builds target/aarch64-apple-ios-sim/release/libclient_ios.a
	~/.cargo/bin/cbindgen --lang c --crate client_ios --output target/aarch64-apple-ios-sim/release/libclient_ios.h
	-rm -r target/aarch64-apple-ios-sim/release/libclient_ios.xcframework
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios-sim/release/libclient_ios.a \
		-headers client_ios/headers/ \
		-output target/aarch64-apple-ios-sim/release/libclient_ios.xcframework

ios: artifacts
	-cargo install cbindgen
	rustup target add aarch64-apple-ios-sim --toolchain nightly-2024-10-28
	# rustup target add aarch64-apple-ios-sim
	NOTARY_CA_CERT_PATH="../../fixture/certs/ca-cert.cer" RUSTFLAGS="-C panic=unwind" cargo  build -p client_ios --release --target aarch64-apple-ios # builds target/aarch64-apple-ios/release/libclient_ios.a
	~/.cargo/bin/cbindgen --lang c --crate client_ios --output client_ios/headers/libclient_ios.h
	-rm -r target/aarch64-apple-ios/release/libclient_ios.xcframework
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libclient_ios.a \
		-headers client_ios/headers \
		-output target/aarch64-apple-ios/release/libclient_ios.xcframework

wasm-demo/node_modules:
	cd client_wasm/demo && npm install

wasm-demo: wasm-demo/node_modules
	cd client_wasm/demo && npm run start

.PHONY: wasm wasm-debug wasm-demo ios ios-sim