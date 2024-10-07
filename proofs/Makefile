ios:
	-rm -rf target
	-rm -rf Rust.xcframework 
	-cargo install cbindgen
	rustup target add aarch64-apple-ios
	# rustup target add aarch64-apple-ios-sim
	cargo build --release --target aarch64-apple-ios # builds target/aarch64-apple-ios/release/libproofs.a
	# RUSTFLAGS="-C panic=unwind" cargo build --release --target aarch64-apple-ios-sim # builds target/aarch64-apple-ios-sim/release/libproofs.a
	~/.cargo/bin/cbindgen --lang c --output headers/libproofs.h
	# -rm -r target/aarch64-apple-ios/release/libproofs_ios.xcframework
	xcodebuild -create-xcframework \
		-library ../target/aarch64-apple-ios/release/libproofs.a \
		-headers ./headers/ \
		-output Rust.xcframework