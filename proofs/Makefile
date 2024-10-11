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

# First generate the R1CS files using Circom
# Second generate the graph bin files using circom-witnesscalc
# Finally run test using these files
proof:
	circom web_proof_circuits/aes_gcm_chunk.circom --r1cs --wasm -o web_proof_circuits/ -l node_modules

	circom web_proof_circuits/http_get_response.circom --r1cs --wasm -o web_proof_circuits/ -l node_modules # NEEDS FIXED

	# - These work ------------------------------------------------------------------------------------------------------ #
	circom web_proof_circuits/json_parse.circom --r1cs -o web_proof_circuits/ -l node_modules
	build-circuit web_proof_circuits/json_parse.circom web_proof_circuits/json_parse.bin -l node_modules 
	# ------------------------------------------------------------------------------------------------------------------- #

	circom web_proof_circuits/json_object_extract.circom -l node_modules --r1cs -o web_proof_circuits







	circom web_proof_circuits/json_array.circom -l node_modules --r1cs --wasm -o web_proof_circuits
	cargo test --release -- tests::test_end_to_end_proofs --exact --ignored
