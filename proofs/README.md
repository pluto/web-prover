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