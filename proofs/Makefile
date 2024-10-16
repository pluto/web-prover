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
	# AES-GCM, ~500K constraints
	circom web_proof_circuits/aes_gcm/aes_gcm.circom --r1cs -o web_proof_circuits/aes_gcm -l node_modules
	build-circuit web_proof_circuits/aes_gcm/aes_gcm.circom web_proof_circuits/aes_gcm/aes_gcm.bin -l node_modules

	# HTTP parse and lock start line, ~18.6K constraints
	circom web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.circom \
		--r1cs -o web_proof_circuits/http_parse_and_lock_start_line -l node_modules
	build-circuit web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.circom \
		web_proof_circuits/http_parse_and_lock_start_line/http_parse_and_lock_start_line.bin -l node_modules

	# HTTP lock header, ~19.5K constraints
	circom web_proof_circuits/http_lock_header/http_lock_header.circom \
		--r1cs -o web_proof_circuits/http_lock_header -l node_modules
	build-circuit web_proof_circuits/http_lock_header/http_lock_header.circom \
		web_proof_circuits/http_lock_header/http_lock_header.bin -l node_modules

	# HTTP body mask, 320 constraints (lol)
	circom web_proof_circuits/http_body_mask/http_body_mask.circom \
		--r1cs -o web_proof_circuits/http_body_mask -l node_modules
	build-circuit web_proof_circuits/http_body_mask/http_body_mask.circom \
		web_proof_circuits/http_body_mask/http_body_mask.bin -l node_modules

	# JSON parse, ~39K constraints
	circom web_proof_circuits/json_parse/json_parse.circom --r1cs -o web_proof_circuits/json_parse -l node_modules
	build-circuit web_proof_circuits/json_parse/json_parse.circom web_proof_circuits/json_parse/json_parse.bin -l node_modules

	# JSON mask object, ~48.6K constraints
	circom web_proof_circuits/json_mask_object/json_mask_object.circom --r1cs -o web_proof_circuits/json_mask_object -l node_modules
	build-circuit web_proof_circuits/json_mask_object/json_mask_object.circom web_proof_circuits/json_mask_object/json_mask_object.bin -l node_modules

	# JSON mask array index, 3749 constraints
	circom web_proof_circuits/json_mask_array_index/json_mask_array_index.circom --r1cs -o web_proof_circuits/json_mask_array_index -l node_modules
	build-circuit web_proof_circuits/json_mask_array_index/json_mask_array_index.circom web_proof_circuits/json_mask_array_index/json_mask_array_index.bin -l node_modules

	# Extract final, ~80K constraints
	circom web_proof_circuits/extract_value/extract_value.circom --r1cs -o web_proof_circuits/extract_value/ -l node_modules
	build-circuit web_proof_circuits/extract_value/extract_value.circom web_proof_circuits/extract_value/extract_value.bin -l node_modules
	# ------------------------------------------------------------------------------------------------------------------------ #

	cargo test --release -- tests::test_end_to_end_proofs --exact --show-output
