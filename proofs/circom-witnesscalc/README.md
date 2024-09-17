# circom-witnesscalc

## Description

This crate provides a fast witness generator for Circom circuits, serving as a drop-in replacement for Circom's witness generator.
It was created in response to the slow performance of Circom's WASM generator for larger circuits, which also necessitates a WASM runtime, often a cumbersome requirement.
Although the native C++ generator is faster, it requires embedding itself into a compiled binary, which is not always desirable.
The idea is to have a universal library that can calculate the witness for any Circom circuit without the need for a WASM runtime or embedding a C++ binary.

`circom-witnesscalc` comes with two executables:

1. `build-circuit` command to build a Circom circuit. As a result, you will get a binary file of graph operations to calculate the witness for a circuit.
2. `calc-witness` command uses the generated binary file and circuit inputs to generate a witness. This functionality is also availabe as a Rust or C library API.

The project originally inspired by [circom-witness-rs](https://github.com/philsippl/circom-witness-rs).

## Unimplemented features

There are some Circom features that are not yet implemented. If you need these features,
please open an issue with the Circom circuit that doesn't work.
In the near future, we plan to add support for using input signals in the loop condition to accommodate circuits that uses the `long_div` function from the [zk-email](https://github.com/zkemail/zk-email-verify/blob/8685d35f9137ea566e0a07f6609fde0123d15f51/packages/circuits/lib/bigint-func.circom#L169) project.

## Compile a circuit and build the witness graph

To create a circuit graph file from a Circom 2 program, run the following command:

```shell
# Using compiled binary
./build-circuit <path_to_circuit.circom> <path_to_circuit_graph.bin> [-l <path_to_circom_libs/>]* [-i <inputs_file.json>] [-print-unoptimized]
# Or using `cargo` from the root of the repository
cargo run --package circom_witnesscalc --bin build-circuit <path_to_circuit.circom> <path_to_circuit_graph.bin> [-l <path_to_circom_libs/>]* [-i <inputs_file.json>] [-print-unoptimized]
```

Optional flags:

* `-l <path_to_circom_libs/>` - Path to the circomlib directory. This flag can be used multiple times.
* `-i <inputs_file.json>` - Path to the inputs file. If provided, the inputs will be used to generate the witness. Otherwise, inputs will be set to 0.
* `-print-unoptimized` - Evaluate the graph with provided or default inputs and print it to stdout (useful for debugging).

## Calculate witness from circuit graph created on previous step

To generate a witness file from a circuit graph and inputs, run the following command.

```shell
# Using compiled binary
./calc-witness <path_to_circuit_graph.bin> <path_to_inputs.json> <path_to_output_witness.wtns>
# Or using `cargo` from the root of the repository
cargo run --package circom_witnesscalc --bin calc-witness <path_to_circuit_graph.bin> <path_to_inputs.json> <path_to_output_witness.wtns>
```

## Run circuits tests

To run circuits tests, we need to make some manual setup

```shell
# Update the git submodules to checkout all required dependencies
git submodule update --init --recursive
# Install dependencies for iden3 authV2 circuits
pushd test_deps/iden3-circuits-authV2
npm install
popd
# Install dependencies for master branch of iden3 circuits
pushd test_deps/iden3-circuits-master
npm install
popd
```

Also, you need to have the following commands installed: `circom`, `snarkjs`,
`curl`, `cargo`, `node` and `cmp`.

Now run the `test_circuits.sh` script.

```shell
./test_circuits.sh
```
