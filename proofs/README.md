# Instructions


## Dependencies
Do the following from whatever location you want:
```
git clone https://github.com/pluto/circom-witnesscalc.git
cd circom-witnesscalc
cargo install --path .
```
this will give you the `build-circuit` and `calc-witness` binaries.
We just need `build-circuit` for preprocessing the correct graph for using the `circom-witnesscalc` lib.
If necessary, use commit `ec597bb` as this definitely works.

**YOU NEED GIT SSH KEY** to work with `circom-witnesscalc` in Rust.
Not sure why, but this will fail to get that dependency without it.

## Run example
To run an example, make sure you have installed the above and either have it in your path, or know the bin location.
The `proofs` bin currently requires nightly (though this can be easily removed, it is only for some logging capture).
For an example, take a look at `proofs/setup/fold_batch.json` which will be used if you execute from the `proofs/` dir:
```sh
cargo +nightly run --release -- -i setup/fold_batch.json -vvvv
```
which will show logs to the trace level.

## Wasm witnessgen
<!-- TODO (autoparllel): What the fuck was this about -->
To generate witness using wasm binary, just modify these keys in setup configs.

```
"wgen_type": "node",
"wgen": "build/parse_fold/parse_fold_js/parse_fold.wasm",
```

> [!NOTE] `witness_calculator.js` is assumed to be in the same directory as wasm bin.


## WASM note

- run notary:
```
RUST_LOG=debug cargo run --release -p notary -- --config ./fixture/notary-config.toml
```

- run `make wasm` or `make wasm-debug` (for better stacktraces in wasm (really necessary to debug))
- run `make wasm-demo`
- open `localhost:8090` and check console