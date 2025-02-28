artifacts:
	cd proofs && make web-prover-circuits

check-llvm:
	@PATH="/opt/homebrew/opt/llvm@18/bin:/opt/homebrew/opt/llvm/bin:$$PATH"; \
	if ! command -v llvm-config > /dev/null 2>&1; then \
		echo "Error: LLVM is not installed or not in PATH."; \
		exit 1; \
	fi; \
	LLVM_VERSION=$$(llvm-config --version); \
	if [ "$${LLVM_VERSION%%.*}" -lt 18 ]; then \
		echo "Error: LLVM version must be 18 or higher. Found $$LLVM_VERSION."; \
		exit 1; \
	fi

wasm: artifacts
	@# NOTE: This build depends on RUSTFLAGS in the client_wasm/.cargo/config.toml
	-cargo install wasm-pack
	-cd client_wasm/demo/static && rm -f build && ln -s ../../../proofs/web_proof_circuits build && cd ../../..
	PATH="/opt/homebrew/opt/llvm@18/bin:/opt/homebrew/opt/llvm/bin:$$PATH"; \
	LLVM_PATH=$$(dirname $$(command -v llvm-config)); \
	PATH="$$LLVM_PATH:$$PATH"; \
	cd client_wasm && \
	  rustup run nightly ~/.cargo/bin/wasm-pack build --release --target web ./ -- \
	    -Z build-std=panic_abort,std

wasm-debug: check-llvm artifacts
	-cargo install wasm-pack
	-cd client_wasm/demo/static && rm -f build && ln -s ../../../proofs/web_proof_circuits build && cd ../../..
	PATH="/opt/homebrew/opt/llvm@18/bin:/opt/homebrew/opt/llvm/bin:$$PATH"; \
	LLVM_PATH=$$(dirname $$(command -v llvm-config)); \
	PATH="$$LLVM_PATH:$$PATH"; \
	cd client_wasm && \
	  rustup run nightly ~/.cargo/bin/wasm-pack build --debug --target web ./ -- \
	    -Z build-std=panic_abort,std

ios: artifacts
	-cargo install cbindgen
	# Build simulator
	rustup target add aarch64-apple-ios-sim --toolchain nightly
	RUSTFLAGS="-C panic=unwind" cargo  build -p client_ios --release --target aarch64-apple-ios-sim # builds target/aarch64-apple-ios-sim/release/libclient_ios.a
	mkdir -p target/sim/headers
	~/.cargo/bin/cbindgen --lang c --crate client_ios --output target/sim/headers/Prover.h
	mv target/aarch64-apple-ios-sim/release/libclient_ios.a target/sim/libProver.a
	# Build device
	rustup target add aarch64-apple-ios --toolchain nightly
	RUSTFLAGS="-C panic=unwind" cargo   build -p client_ios --release --target aarch64-apple-ios # builds target/aarch64-apple-ios/release/libclient_ios.a
	mkdir -p target/device/headers
	~/.cargo/bin/cbindgen --lang c --crate client_ios --output target/device/headers/Prover.h
	mv target/aarch64-apple-ios/release/libclient_ios.a target/device/libProver.a
	# Create combined xcframework
	xcodebuild -create-xcframework \
		-library "target/sim/libProver.a" \
		-headers target/sim/headers \
		-library "target/device/libProver.a" \
		-headers target/device/headers \
		-output target/PlutoProver.xcframework
	# Cleanup
	rm -rf target/device target/sim

wasm-demo/node_modules:
	cd client_wasm/demo && npm install

wasm-demo: wasm-demo/node_modules
	cd client_wasm/demo && npm run start

coverage: artifacts
	-cargo install cargo-tarpaulin
	cargo tarpaulin --workspace --exclude client_wasm --timeout 360 --out Xml --out Html --output-dir coverage
	@echo "Coverage report generated in coverage/tarpaulin-report.html"

.PHONY: wasm wasm-debug wasm-demo ios coverage
