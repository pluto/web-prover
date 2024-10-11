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

	# HTTP parse and lock start line
	circom web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.circom \
		--r1cs -o web_proof_circuits/http_parse_and_lock_start_line -l node_modules
	build-circuit web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.circom \
		web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.bin -l node_modules

	# - These work ----------------------------------------------------------------------------------------------------------- #
	

	# JSON parse
	circom web_proof_circuits/json_parse/json_parse.circom --r1cs -o web_proof_circuits/json_parse -l node_modules
	build-circuit web_proof_circuits/json_parse/json_parse.circom web_proof_circuits/json_parse/json_parse.bin -l node_modules

	# JSON mask object 
	circom web_proof_circuits/json_mask_object/json_mask_object.circom --r1cs -o web_proof_circuits/json_mask_object -l node_modules
	build-circuit web_proof_circuits/json_mask_object/json_mask_object.circom web_proof_circuits/json_mask_object/json_mask_object.bin -l node_modules

	# JSON mask array index
	circom web_proof_circuits/json_mask_array_index/json_mask_array_index.circom --r1cs -o web_proof_circuits/json_mask_array_index -l node_modules
	build-circuit web_proof_circuits/json_mask_array_index/json_mask_array_index.circom web_proof_circuits/json_mask_array_index/json_mask_array_index.bin -l node_modules
	# ------------------------------------------------------------------------------------------------------------------------ #

	circom web_proof_circuits/json_object_extract.circom -l node_modules --r1cs -o web_proof_circuits







	circom web_proof_circuits/json_array.circom -l node_modules --r1cs --wasm -o web_proof_circuits
	cargo test --release -- tests::test_end_to_end_proofs --exact --ignored
