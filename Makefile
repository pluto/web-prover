UNAME := $(shell uname -s)

ifeq ($(UNAME),Linux)
    SED_CMD = sed -i
endif
ifeq ($(UNAME),Darwin)
    SED_CMD = sed -i ''
endif

libs:
	-mkdir build
	cargo build --release --target aarch64-apple-ios
	cargo build --release --target aarch64-apple-ios-sim
	cp target/aarch64-apple-ios/release/libtlsnotary.a build/tlsnotary-ios-device.a
	cp target/aarch64-apple-ios-sim/release/libtlsnotary.a build/tlsnotary-ios-simulator.a

cbindgen:
	cbindgen --lang c --crate tlsnotary --output build/tlsnotary.h

xcframework:
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libtlsnotary.a \
		-headers ./build/tlsnotary.h \
		-library target/aarch64-apple-ios-sim/release/libtlsnotary.a \
		-headers ./build/tlsnotary.h \
		-output build/tlsnotary.xcframework

.PHONY: libs xcframework cbindgen


CARGO_CONFIG := .cargo/config.toml

switch-to-wasm:
	$(SED_CMD) 's/^target="aarch64-apple-ios"/# target="aarch64-apple-ios"/' $(CARGO_CONFIG)
	$(SED_CMD) 's/^# target="wasm32-unknown-unknown"/target="wasm32-unknown-unknown"/' $(CARGO_CONFIG)
	@echo "Switched to WASM target"
	@$(MAKE) restart-rust-analyzer

switch-to-ios:
	$(SED_CMD) 's/^target="wasm32-unknown-unknown"/# target="wasm32-unknown-unknown"/' $(CARGO_CONFIG)
	$(SED_CMD) 's/^# target="aarch64-apple-ios"/target="aarch64-apple-ios"/' $(CARGO_CONFIG)
	@echo "Switched to iOS target"
	@$(MAKE) restart-rust-analyzer

restart-rust-analyzer:
	@echo "Restarting Rust Analyzer..."
	@if pgrep -f "rust-analyzer" > /dev/null; then \
		pkill -f "rust-analyzer"; \
	fi
	@echo "Rust Analyzer has been restarted. You may need to reopen your editor."