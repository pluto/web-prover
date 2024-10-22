# First generate the R1CS files using Circom
# Second generate the graph bin files using circom-witnesscalc
# Finally run test using these files
aes:
	# AES-GCM, ~500K constraints (for now we need wasm witgen)
	circom web_proof_circuits/aes_gcm/aes_gcm.circom --r1cs --wasm -o web_proof_circuits/aes_gcm -l node_modules
	build-circuit web_proof_circuits/aes_gcm/aes_gcm.circom web_proof_circuits/aes_gcm/aes_gcm.bin -l node_modules

circuits: aes
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

	# Test circuits
	circom examples/circuit_data/add_external.circom --r1cs -o examples/circuit_data -l node_modules
	circom examples/circuit_data/square_zeroth.circom --r1cs -o examples/circuit_data -l node_modules
	circom examples/circuit_data/swap_memory.circom --r1cs -o examples/circuit_data -l node_modules

	build-circuit examples/circuit_data/add_external.circom examples/circuit_data/add_external.bin -l node_modules
	build-circuit examples/circuit_data/square_zeroth.circom examples/circuit_data/square_zeroth.bin -l node_modules
	build-circuit examples/circuit_data/swap_memory.circom examples/circuit_data/swap_memory.bin -l node_modules

proof: circuit
	cargo test --release -- tests::test_end_to_end_proofs --exact --show-output

params:
	cargo test --release -- tests::test_offline_proofs --exact --show-output