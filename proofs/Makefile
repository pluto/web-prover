# First generate the R1CS files using Circom
# Second generate the graph bin files using circom-witnesscalc
# Finally run test using these files

web-prover-circuits:
	curl -L -o circuits.zip https://github.com/pluto/web-prover-circuits/releases/latest/download/circom-artifacts-target_512b-v0.3.0.zip
	mkdir -p web_proof_circuits/target_512b/
	unzip -o circuits.zip -d web_proof_circuits/target_512b/
	rm circuits.zip

aes:
	# AES-GCM, ~500K constraints (for now we need wasm witgen)
	circom web_proof_circuits/aes_gcm/aes_gcm.circom --r1cs --wasm -o web_proof_circuits/aes_gcm -l node_modules
	build-circuit web_proof_circuits/aes_gcm/aes_gcm.circom web_proof_circuits/aes_gcm/aes_gcm.bin -l node_modules

test-circuits:
	# Test circuits
	circom examples/circuit_data/add_external.circom --r1cs -o examples/circuit_data -l node_modules
	circom examples/circuit_data/square_zeroth.circom --r1cs -o examples/circuit_data -l node_modules
	circom examples/circuit_data/swap_memory.circom --r1cs -o examples/circuit_data -l node_modules

	build-circuit examples/circuit_data/add_external.circom examples/circuit_data/add_external.bin -l node_modules
	build-circuit examples/circuit_data/square_zeroth.circom examples/circuit_data/square_zeroth.bin -l node_modules
	build-circuit examples/circuit_data/swap_memory.circom examples/circuit_data/swap_memory.bin -l node_modules

proof: web-prover-circuits
	cargo test --release -- tests::test_end_to_end_proofs --exact --show-output

params:
	cargo test --release -- tests::test_offline_proofs --exact --show-output --ignored
