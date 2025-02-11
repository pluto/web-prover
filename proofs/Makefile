# First generate the R1CS files using Circom
# Second generate the graph bin files using circom-witnesscalc
# Finally run test using these files

VERSION = $(shell sed -n 's/^web_prover_circuits_version *= *"\(.*\)"/\1/p' ../Cargo.toml)
CIRCUIT_VERSIONS = circom-artifacts-256b-v$(VERSION) circom-artifacts-512b-v$(VERSION)

web-prover-circuits:
	for version in $(CIRCUIT_VERSIONS); do \
		if [ ! -d "web_proof_circuits/$$version" ] || [ -z "$$(ls -A web_proof_circuits/$$version)" ]; then \
			curl -L -o circuits.zip https://github.com/pluto/web-prover-circuits/releases/download/v$(VERSION)/$$version.zip; \
			mkdir -p web_proof_circuits/$$version/; \
			unzip -o circuits.zip -d web_proof_circuits/$$version/; \
			rm circuits.zip; \
		else \
			echo "Directory web_proof_circuits/$$version already exists and is not empty. Skipping download."; \
		fi \
	done

test-circuits:
	# Test circuits
	circom examples/circuit_data/add_external.circom --r1cs -o examples/circuit_data -l node_modules
	circom examples/circuit_data/square_zeroth.circom --r1cs -o examples/circuit_data -l node_modules
	circom examples/circuit_data/swap_memory.circom --r1cs -o examples/circuit_data -l node_modules

	build-circuit examples/circuit_data/add_external.circom examples/circuit_data/add_external.bin -l node_modules
	build-circuit examples/circuit_data/square_zeroth.circom examples/circuit_data/square_zeroth.bin -l node_modules
	build-circuit examples/circuit_data/swap_memory.circom examples/circuit_data/swap_memory.bin -l node_modules

proof: web-prover-circuits
	cargo test --release --features timing -- tests::test_end_to_end_proofs --exact --show-output
