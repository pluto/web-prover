# Instructions


## Dependencies
Do the following from whatever location you want:
```
git clone https://github.com/iden3/circom-witnesscalc.git
cd circom-witnesscalc
cargo install --path .
```
this will give you the `build-circuit` and `calc-witness` binaries. 
We just need `build-circuit` for preprocessing the correct graph for using the `circom-witnesscalc` lib.
If necessary, use commit `ec597bb` as this definitely works.

## Run example
To run an example, make sure you have installed the above and either have it in your path, or know the bin location. 
The `proofs` bin currently requires nightly (though this can be easily removed, it is only for some logging capture).
For an example, take a look at `proofs/setup/fold_batch.json` which will be used if you execute from the `proofs/` dir:
```sh
cargo +nightly run --release -- -i setup/fold_batch.json -vvvv
```
which will show logs to the trace level. 